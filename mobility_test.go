// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package turn

import (
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/test"
	"github.com/pion/turn/v5/internal/allocation"
	"github.com/pion/turn/v5/internal/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mobilityUserA = "mobilityUserA"
	mobilityUserB = "mobilityUserB"
	mobilityRealm = "pion.ly"
)

func mobilityAuthHandler(ra *RequestAttributes) (userID string, key []byte, ok bool) {
	switch ra.Username {
	case mobilityUserA:
		return ra.Username, GenerateAuthKey(mobilityUserA, mobilityRealm, "passA"), true
	case mobilityUserB:
		return ra.Username, GenerateAuthKey(mobilityUserB, mobilityRealm, "passB"), true
	default:
		return "", nil, false
	}
}

// newMobilityTestServer starts a TURN server on a random local port with the
// given mobility ticket lifetime (0 disables mobility).
func newMobilityTestServer(t *testing.T, ticketLifetime time.Duration) (*Server, net.Addr) {
	t.Helper()

	udpListener, err := net.ListenPacket("udp4", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)

	server, err := NewServer(ServerConfig{
		AuthHandler:            mobilityAuthHandler,
		MobilityTicketLifetime: ticketLifetime,
		PacketConnConfigs: []PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "127.0.0.1",
				},
			},
		},
		Realm:         mobilityRealm,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)

	return server, udpListener.LocalAddr()
}

func newMobilityTestClient(
	t *testing.T,
	serverAddr net.Addr,
	conn net.PacketConn,
	username, password string,
	mobility bool,
) *Client {
	t.Helper()

	client, err := NewClient(&ClientConfig{
		TURNServerAddr: serverAddr.String(),
		Conn:           conn,
		Username:       username,
		Password:       password,
		Realm:          mobilityRealm,
		Mobility:       mobility,
		RTO:            50 * time.Millisecond,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)
	require.NoError(t, client.Listen())

	return client
}

func listenUDP(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)

	return conn
}

func readPacketString(t *testing.T, conn net.PacketConn) string {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 1600)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)

	return string(buf[:n])
}

// mobilityTicketOf extracts the current mobility ticket from a relayed conn.
func mobilityTicketOf(conn net.PacketConn) []byte {
	holder, ok := conn.(interface{ MobilityTicket() []byte })
	if !ok {
		return nil
	}

	return holder.MobilityTicket()
}

// rawMobilityRefresh performs a long-term-credential Refresh transaction
// carrying the given mobility ticket directly over conn, and returns the
// server's response. It is used to drive the server with hand-crafted
// (expired, replayed, cross-user or tampered) tickets.
func rawMobilityRefresh(
	t *testing.T,
	conn net.PacketConn,
	serverAddr net.Addr,
	username, password string,
	ticket []byte,
) *stun.Message {
	t.Helper()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	defer func() {
		require.NoError(t, conn.SetReadDeadline(time.Time{}))
	}()

	exchange := func(msg *stun.Message) *stun.Message {
		_, err := conn.WriteTo(msg.Raw, serverAddr)
		require.NoError(t, err)

		buf := make([]byte, 1600)
		for {
			n, _, err := conn.ReadFrom(buf)
			require.NoError(t, err)
			res := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if err := res.Decode(); err != nil || res.TransactionID != msg.TransactionID {
				continue
			}

			return res
		}
	}

	// Unauthenticated request to learn the nonce and realm.
	msg, err := stun.Build(
		stun.TransactionID,
		stun.NewType(stun.MethodRefresh, stun.ClassRequest),
		proto.Lifetime{Duration: time.Minute},
	)
	require.NoError(t, err)
	res := exchange(msg)
	require.Equal(t, stun.ClassErrorResponse, res.Type.Class)

	var nonce stun.Nonce
	require.NoError(t, nonce.GetFrom(res))
	var realm stun.Realm
	require.NoError(t, realm.GetFrom(res))

	integrity := stun.NewLongTermIntegrity(username, realm.String(), password)
	msg, err = stun.Build(
		stun.TransactionID,
		stun.NewType(stun.MethodRefresh, stun.ClassRequest),
		proto.Lifetime{Duration: time.Minute},
		stun.NewUsername(username),
		realm,
		nonce,
		proto.MobilityTicket(ticket),
		integrity,
		stun.Fingerprint,
	)
	require.NoError(t, err)

	return exchange(msg)
}

func requireErrorCode(t *testing.T, res *stun.Message, code stun.ErrorCode) {
	t.Helper()
	require.Equal(t, stun.ClassErrorResponse, res.Type.Class)
	var errCode stun.ErrorCodeAttribute
	require.NoError(t, errCode.GetFrom(res))
	assert.Equal(t, code, errCode.Code)
}

// TestMobilityMigration covers the happy path of RFC 8016: a client whose
// 5-tuple changes migrates its allocation with an authenticated Refresh
// carrying the mobility ticket, permissions and channel bindings survive,
// media keeps flowing in both directions over the new path, and no new
// allocation is created.
func TestMobilityMigration(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	server, serverAddr := newMobilityTestServer(t, time.Minute)
	defer func() {
		assert.NoError(t, server.Close())
	}()

	peer := listenUDP(t)
	defer func() {
		assert.NoError(t, peer.Close())
	}()

	conn1 := listenUDP(t)
	client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
	defer client.Close()

	relayConn, err := client.Allocate()
	require.NoError(t, err)
	relayedAddr := relayConn.LocalAddr()

	ticket := mobilityTicketOf(relayConn)
	require.NotEmpty(t, ticket, "server should have issued a mobility ticket")

	// client -> peer and peer -> client over the original path.
	_, err = relayConn.WriteTo([]byte("ping"), peer.LocalAddr())
	require.NoError(t, err)
	assert.Equal(t, "ping", readPacketString(t, peer))

	_, err = peer.WriteTo([]byte("pong"), relayedAddr)
	require.NoError(t, err)
	require.NoError(t, relayConn.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, err := relayConn.ReadFrom(make([]byte, 1600))
	require.NoError(t, err)
	_ = n

	oldFiveTuple := &allocation.FiveTuple{
		Protocol: allocation.UDP,
		SrcAddr:  conn1.LocalAddr(),
		DstAddr:  serverAddr,
	}
	allocBefore := server.allocationManagers[0].GetAllocation(oldFiveTuple)
	require.NotNil(t, allocBefore)
	require.Equal(t, 1, server.AllocationCount())

	// Migrate to a new 5-tuple (e.g. Wi-Fi -> cellular).
	conn2 := listenUDP(t)
	defer func() {
		assert.NoError(t, conn2.Close())
	}()
	require.NoError(t, client.MigrateAllocation(conn2))

	// The same allocation object must be re-keyed, not recreated.
	newFiveTuple := &allocation.FiveTuple{
		Protocol: allocation.UDP,
		SrcAddr:  conn2.LocalAddr(),
		DstAddr:  serverAddr,
	}
	allocAfter := server.allocationManagers[0].GetAllocation(newFiveTuple)
	require.NotNil(t, allocAfter)
	assert.True(t, allocBefore == allocAfter, "migration must not create a new allocation")
	assert.Equal(t, 1, server.AllocationCount())
	assert.Nil(t, server.allocationManagers[0].GetAllocation(oldFiveTuple),
		"old 5-tuple must no longer map to the allocation")

	// The ticket must have rotated.
	newTicket := mobilityTicketOf(relayConn)
	require.NotEmpty(t, newTicket)
	assert.NotEqual(t, ticket, newTicket)

	// The old path is gone (e.g. Wi-Fi interface down); the listen loop
	// must keep working on the new connection.
	assert.NoError(t, conn1.Close())

	// peer -> client still arrives, now on the new path.
	_, err = peer.WriteTo([]byte("after-migration"), relayedAddr)
	require.NoError(t, err)
	require.NoError(t, relayConn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 1600)
	n, _, err = relayConn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "after-migration", string(buf[:n]))

	// client -> peer still works over the migrated 5-tuple.
	_, err = relayConn.WriteTo([]byte("back"), peer.LocalAddr())
	require.NoError(t, err)
	assert.Equal(t, "back", readPacketString(t, peer))

	// Closing the allocation works over the new path.
	require.NoError(t, relayConn.Close())
	require.Eventually(t, func() bool {
		return server.AllocationCount() == 0
	}, 2*time.Second, 10*time.Millisecond)
}

// dropFirstResponseConn swallows the first packet received, simulating the
// loss of the first mobility Refresh success response.
type dropFirstResponseConn struct {
	net.PacketConn
	dropped atomic.Bool
}

func (c *dropFirstResponseConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if c.dropped.CompareAndSwap(false, true) {
			continue
		}

		return n, addr, nil
	}
}

// TestMobilityRetransmission verifies that a retransmitted mobility Refresh
// (same ticket, same new 5-tuple) is answered idempotently with the same new
// ticket, so a lost success response does not break the migration.
func TestMobilityRetransmission(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	server, serverAddr := newMobilityTestServer(t, time.Minute)
	defer func() {
		assert.NoError(t, server.Close())
	}()

	conn1 := listenUDP(t)
	defer func() {
		assert.NoError(t, conn1.Close())
	}()
	client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
	defer client.Close()

	relayConn, err := client.Allocate()
	require.NoError(t, err)
	ticket := mobilityTicketOf(relayConn)
	require.NotEmpty(t, ticket)

	conn2 := &dropFirstResponseConn{PacketConn: listenUDP(t)}
	defer func() {
		assert.NoError(t, conn2.Close())
	}()

	require.NoError(t, client.MigrateAllocation(conn2))
	assert.True(t, conn2.dropped.Load(), "the first response should have been dropped")

	// The client retransmitted the original ticket and still received the
	// rotated ticket from the idempotent server replay.
	newTicket := mobilityTicketOf(relayConn)
	require.NotEmpty(t, newTicket)
	assert.NotEqual(t, ticket, newTicket)
	assert.Equal(t, 1, server.AllocationCount())

	require.NoError(t, relayConn.Close())
}

// TestMobilityRefreshTimeout verifies that a migration attempt fails cleanly
// (without disturbing the existing allocation) when the server never answers
// the mobility Refresh.
func TestMobilityRefreshTimeout(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	server, serverAddr := newMobilityTestServer(t, time.Minute)

	conn1 := listenUDP(t)
	defer func() {
		assert.NoError(t, conn1.Close())
	}()
	client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
	defer client.Close()

	relayConn, err := client.Allocate()
	require.NoError(t, err)
	require.NotEmpty(t, mobilityTicketOf(relayConn))

	// Make the server unreachable.
	require.NoError(t, server.Close())

	conn2 := listenUDP(t)
	defer func() {
		assert.NoError(t, conn2.Close())
	}()

	err = client.MigrateAllocation(conn2)
	require.Error(t, err, "migration must fail when the server does not respond")

	// The client must not have switched connections.
	require.NoError(t, relayConn.Close())
}

// TestMobilityTicketRejected verifies that expired, replayed, cross-user and
// tampered tickets are all rejected with a generic 400 and do not disturb
// the ticket owner's allocation.
func TestMobilityTicketRejected(t *testing.T) {
	lim := test.TimeOut(time.Second * 60)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	t.Run("expired", func(t *testing.T) {
		server, serverAddr := newMobilityTestServer(t, 300*time.Millisecond)
		defer func() {
			assert.NoError(t, server.Close())
		}()

		peer := listenUDP(t)
		defer func() {
			assert.NoError(t, peer.Close())
		}()

		conn1 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn1.Close())
		}()
		client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
		defer client.Close()

		relayConn, err := client.Allocate()
		require.NoError(t, err)
		relayedAddr := relayConn.LocalAddr()
		require.NotEmpty(t, mobilityTicketOf(relayConn))

		_, err = relayConn.WriteTo([]byte("ping"), peer.LocalAddr())
		require.NoError(t, err)
		assert.Equal(t, "ping", readPacketString(t, peer))

		// Let the ticket expire.
		time.Sleep(500 * time.Millisecond)

		conn2 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn2.Close())
		}()

		err = client.MigrateAllocation(conn2)
		require.Error(t, err)
		var turnErr *stun.TurnError
		require.True(t, errors.As(err, &turnErr), "expected a TURN error, got %v", err)
		assert.Equal(t, stun.CodeBadRequest, turnErr.ErrorCodeAttr.Code)

		// The allocation must be untouched: media still flows on the old path.
		_, err = peer.WriteTo([]byte("still-here"), relayedAddr)
		require.NoError(t, err)
		require.NoError(t, relayConn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1600)
		n, _, err := relayConn.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, "still-here", string(buf[:n]))
		assert.Equal(t, 1, server.AllocationCount())

		require.NoError(t, relayConn.Close())
	})

	t.Run("tampered", func(t *testing.T) {
		server, serverAddr := newMobilityTestServer(t, time.Minute)
		defer func() {
			assert.NoError(t, server.Close())
		}()

		conn1 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn1.Close())
		}()
		client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
		defer client.Close()

		relayConn, err := client.Allocate()
		require.NoError(t, err)
		require.NotEmpty(t, mobilityTicketOf(relayConn))

		// A random (tampered) ticket must be rejected with 400.
		attacker := listenUDP(t)
		defer func() {
			assert.NoError(t, attacker.Close())
		}()
		fakeTicket := make([]byte, 32)
		_, err = rand.Read(fakeTicket)
		require.NoError(t, err)

		res := rawMobilityRefresh(t, attacker, serverAddr, mobilityUserA, "passA", fakeTicket)
		requireErrorCode(t, res, stun.CodeBadRequest)
		assert.Equal(t, 1, server.AllocationCount())

		require.NoError(t, relayConn.Close())
	})

	t.Run("cross-user", func(t *testing.T) {
		server, serverAddr := newMobilityTestServer(t, time.Minute)
		defer func() {
			assert.NoError(t, server.Close())
		}()

		conn1 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn1.Close())
		}()
		client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
		defer client.Close()

		relayConn, err := client.Allocate()
		require.NoError(t, err)
		ticket := mobilityTicketOf(relayConn)
		require.NotEmpty(t, ticket)

		// Another authenticated user presenting user A's ticket must be
		// rejected and must not learn or take over A's allocation.
		connB := listenUDP(t)
		defer func() {
			assert.NoError(t, connB.Close())
		}()
		res := rawMobilityRefresh(t, connB, serverAddr, mobilityUserB, "passB", ticket)
		requireErrorCode(t, res, stun.CodeBadRequest)
		assert.Equal(t, 1, server.AllocationCount())

		// The legitimate owner can still migrate with the same ticket.
		conn2 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn2.Close())
		}()
		require.NoError(t, client.MigrateAllocation(conn2))
		assert.Equal(t, 1, server.AllocationCount())

		require.NoError(t, relayConn.Close())
	})

	t.Run("replayed", func(t *testing.T) {
		server, serverAddr := newMobilityTestServer(t, time.Minute)
		defer func() {
			assert.NoError(t, server.Close())
		}()

		conn1 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn1.Close())
		}()
		client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
		defer client.Close()

		relayConn, err := client.Allocate()
		require.NoError(t, err)
		oldTicket := mobilityTicketOf(relayConn)
		require.NotEmpty(t, oldTicket)

		conn2 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn2.Close())
		}()
		require.NoError(t, client.MigrateAllocation(conn2))
		newTicket := mobilityTicketOf(relayConn)
		require.NotEmpty(t, newTicket)

		// Replaying the consumed ticket from a *different* 5-tuple must be
		// rejected, even with the owner's credentials.
		conn3 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn3.Close())
		}()
		res := rawMobilityRefresh(t, conn3, serverAddr, mobilityUserA, "passA", oldTicket)
		requireErrorCode(t, res, stun.CodeBadRequest)
		assert.Equal(t, 1, server.AllocationCount())

		// The current ticket must still be valid afterwards.
		assert.Equal(t, newTicket, mobilityTicketOf(relayConn))

		require.NoError(t, relayConn.Close())
	})
}

// TestMobilityDisabled verifies that clients and servers that do not
// negotiate mobility behave exactly as before.
func TestMobilityDisabled(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	t.Run("server without mobility", func(t *testing.T) {
		server, serverAddr := newMobilityTestServer(t, 0)
		defer func() {
			assert.NoError(t, server.Close())
		}()

		peer := listenUDP(t)
		defer func() {
			assert.NoError(t, peer.Close())
		}()

		conn1 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn1.Close())
		}()
		// Client requests mobility, but the server does not support it.
		client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", true)
		defer client.Close()

		relayConn, err := client.Allocate()
		require.NoError(t, err)
		assert.Empty(t, mobilityTicketOf(relayConn), "server without mobility must not issue a ticket")

		// Migration is not possible, plain relaying is unaffected.
		conn2 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn2.Close())
		}()
		assert.Error(t, client.MigrateAllocation(conn2))

		_, err = relayConn.WriteTo([]byte("ping"), peer.LocalAddr())
		require.NoError(t, err)
		assert.Equal(t, "ping", readPacketString(t, peer))

		require.NoError(t, relayConn.Close())
	})

	t.Run("client without mobility", func(t *testing.T) {
		server, serverAddr := newMobilityTestServer(t, time.Minute)
		defer func() {
			assert.NoError(t, server.Close())
		}()

		peer := listenUDP(t)
		defer func() {
			assert.NoError(t, peer.Close())
		}()

		conn1 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn1.Close())
		}()
		// Server supports mobility, but the client does not request it.
		client := newMobilityTestClient(t, serverAddr, conn1, mobilityUserA, "passA", false)
		defer client.Close()

		relayConn, err := client.Allocate()
		require.NoError(t, err)
		assert.Empty(t, mobilityTicketOf(relayConn))

		conn2 := listenUDP(t)
		defer func() {
			assert.NoError(t, conn2.Close())
		}()
		assert.Error(t, client.MigrateAllocation(conn2))

		_, err = relayConn.WriteTo([]byte("ping"), peer.LocalAddr())
		require.NoError(t, err)
		assert.Equal(t, "ping", readPacketString(t, peer))

		_, err = peer.WriteTo([]byte("pong"), relayConn.LocalAddr())
		require.NoError(t, err)
		require.NoError(t, relayConn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1600)
		n, _, err := relayConn.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, "pong", string(buf[:n]))

		require.NoError(t, relayConn.Close())
	})
}
