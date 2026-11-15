// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package client

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5/internal/proto"
)

const (
	// mobilityRtxCount is the total number of mobility Refresh transmissions
	// (Rc), matching the STUN retransmission recommendation of RFC 5389.
	mobilityRtxCount = 7

	defaultMobilityRTO = 200 * time.Millisecond
	mobilityBufferSize = 1600
)

// Migrate performs the client side of an RFC 8016 mobility event: it sends an
// authenticated Refresh request carrying the current mobility ticket over
// newConn (the client's new 5-tuple) and, on success, adopts the new mobility
// ticket returned by the server. The allocation's permissions and channel
// bindings are preserved by the server across the migration.
//
// Migrate only performs the mobility transaction; switching the client's
// read/write path to newConn is the caller's responsibility (see
// turn.Client.MigrateAllocation).
func (c *UDPConn) Migrate(newConn net.PacketConn, rto time.Duration) error {
	if c.isClosed() {
		return errClosed
	}

	return c.migrate(newConn, rto)
}

// MobilityTicket returns a copy of the current RFC 8016 mobility ticket, or
// nil if mobility was not negotiated with the server.
func (c *UDPConn) MobilityTicket() []byte {
	ticket := c.mobilityTicket()
	if ticket == nil {
		return nil
	}

	return append([]byte(nil), ticket...)
}

func (c *UDPConn) migrate(newConn net.PacketConn, rto time.Duration) error {
	if newConn == nil {
		return errNilPacketConn
	}
	if len(c.mobilityTicket()) == 0 {
		return errMobilityNotNegotiated
	}
	if rto <= 0 {
		rto = defaultMobilityRTO
	}

	var err error
	for range maxRetryAttempts {
		var msg *stun.Message
		msg, err = stun.Build(
			stun.TransactionID,
			stun.NewType(stun.MethodRefresh, stun.ClassRequest),
			proto.Lifetime{Duration: c.lifetime()},
			c.username,
			c.realm,
			c.nonce(),
			proto.MobilityTicket(c.mobilityTicket()),
			c.integrity,
			stun.Fingerprint,
		)
		if err != nil {
			return fmt.Errorf("%w: %s", errFailedToBuildRefreshRequest, err.Error())
		}

		var res *stun.Message
		res, err = c.doMobilityTransaction(newConn, msg, rto)
		if err != nil {
			return err
		}

		if res.Type.Class == stun.ClassErrorResponse {
			var code stun.ErrorCodeAttribute
			if codeErr := code.GetFrom(res); codeErr == nil {
				if code.Code == stun.CodeStaleNonce {
					c.setNonceFromMsg(res)

					continue
				}

				return &stun.TurnError{
					StunMessageType: res.Type,
					ErrorCodeAttr:   code,
				}
			}

			return fmt.Errorf("%s", res.Type) //nolint:err113
		}

		// RFC 8016 Section 4.2: the success response carries a new ticket
		// that supersedes the presented one.
		var newTicket proto.MobilityTicket
		if ticketErr := newTicket.GetFrom(res); ticketErr != nil || len(newTicket) == 0 {
			return errMobilityTicketMissing
		}
		c.setMobilityTicket(newTicket)

		var lifetime proto.Lifetime
		if lifetimeErr := lifetime.GetFrom(res); lifetimeErr == nil {
			c.setLifetime(lifetime.Duration)
		}

		c.log.Debugf("Mobility refresh successful, allocation migrated to %s", newConn.LocalAddr())

		return nil
	}

	return err
}

// doMobilityTransaction sends the mobility Refresh over conn and waits for
// the matching response, retransmitting with exponential backoff. Packets
// that are not the transaction response (e.g. media already arriving on the
// new path) are discarded.
func (c *UDPConn) doMobilityTransaction(
	conn net.PacketConn,
	msg *stun.Message,
	rto time.Duration,
) (*stun.Message, error) {
	buf := make([]byte, mobilityBufferSize)

	// Restore any read deadline we set so the caller's conn is left untouched.
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	interval := rto
	for range mobilityRtxCount {
		if _, err := conn.WriteTo(msg.Raw, c.serverAddr); err != nil {
			return nil, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(interval)); err != nil {
			return nil, err
		}

		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					break // retransmit
				}

				return nil, err
			}
			if from == nil || from.String() != c.serverAddr.String() || !stun.IsMessage(buf[:n]) {
				continue
			}

			res := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if err := res.Decode(); err != nil {
				continue
			}
			if res.TransactionID != msg.TransactionID {
				continue
			}
			if err := c.integrity.Check(res); err != nil {
				continue
			}

			return res, nil
		}

		interval *= 2
	}

	return nil, errMobilityRefreshTimeout
}
