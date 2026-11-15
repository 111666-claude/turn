// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package client

import (
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v3"
	"github.com/pion/turn/v4/internal/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummyTCPConn struct {
	transport.TCPConn
}

func buildMsg(
	transactionID [stun.TransactionIDSize]byte,
	msgType stun.MessageType,
	additional ...stun.Setter,
) []stun.Setter {
	return append([]stun.Setter{&stun.Message{TransactionID: transactionID}, msgType}, additional...)
}

func (c dummyTCPConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c dummyTCPConn) Read(b []byte) (int, error) {
	transactionID := [stun.TransactionIDSize]byte{1, 2, 3}
	messageType := stun.MessageType{Method: stun.MethodConnectionBind, Class: stun.ClassSuccessResponse}
	attrs := buildMsg(transactionID, messageType)
	msg, err := stun.Build(attrs...)
	if err != nil {
		return 0, err
	}

	copy(b, msg.Raw)

	return len(msg.Raw), nil
}

func TestTCPConn(t *testing.T) {
	t.Run("Connect()", func(t *testing.T) {
		var cid proto.ConnectionID = 5
		client := &mockClient{
			performTransaction: func(msg *stun.Message, _ net.Addr, _ bool) (TransactionResult, error) {
				if msg.Type.Class == stun.ClassRequest && msg.Type.Method == stun.MethodConnect {
					msg, err := stun.Build(
						stun.TransactionID,
						stun.NewType(stun.MethodConnect, stun.ClassSuccessResponse),
						cid,
					)
					assert.NoError(t, err)

					return TransactionResult{Msg: msg}, nil
				}

				return TransactionResult{}, errFake
			},
		}

		addr := &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		}

		pm := newPermissionMap()
		assert.True(t, pm.insert(addr, &permission{
			st: permStatePermitted,
		}))

		loggerFactory := logging.NewDefaultLoggerFactory()
		log := loggerFactory.NewLogger("test")
		alloc := TCPAllocation{
			allocation: allocation{
				client:  client,
				permMap: pm,
				log:     log,
			},
		}

		actualCid, err := alloc.Connect(addr)
		assert.NoError(t, err)
		assert.Equal(t, cid, actualCid)

		client = &mockClient{
			performTransaction: func(msg *stun.Message, _ net.Addr, _ bool) (TransactionResult, error) {
				if msg.Type.Class == stun.ClassRequest && msg.Type.Method == stun.MethodConnect {
					msg, buildErr := stun.Build(
						stun.TransactionID,
						stun.NewType(stun.MethodConnect, stun.ClassErrorResponse),
						stun.ErrorCodeAttribute{Code: stun.CodeBadRequest},
					)
					assert.NoError(t, buildErr)

					return TransactionResult{Msg: msg}, nil
				}

				return TransactionResult{}, errFake
			},
		}
		alloc = TCPAllocation{
			allocation: allocation{
				client:  client,
				permMap: pm,
				log:     log,
			},
		}

		_, err = alloc.Connect(addr)
		assert.ErrorContains(t, err, "Connect error response", "error 400")
	})

	t.Run("SetDeadline()", func(t *testing.T) {
		relayedAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:13478")
		assert.NoError(t, err)

		loggerFactory := logging.NewDefaultLoggerFactory()

		alloc := NewTCPAllocation(&AllocationConfig{
			Client:      &mockClient{},
			Lifetime:    time.Second,
			Log:         loggerFactory.NewLogger("test"),
			RelayedAddr: relayedAddr,
		})

		err = alloc.SetDeadline(time.Now())
		assert.NoError(t, err)

		cid, err := alloc.AcceptTCPWithConn(nil)
		assert.Nil(t, cid)
		assert.Contains(t, err.Error(), "i/o timeout")
	})

	t.Run("AcceptTCPWithConn()", func(t *testing.T) {
		relayedAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:13478")
		assert.NoError(t, err)

		loggerFactory := logging.NewDefaultLoggerFactory()
		alloc := NewTCPAllocation(&AllocationConfig{
			Client:      &mockClient{},
			Lifetime:    time.Second,
			Log:         loggerFactory.NewLogger("test"),
			RelayedAddr: relayedAddr,
		})

		from, err := net.ResolveTCPAddr("tcp", "127.0.0.1:11111")
		var cid proto.ConnectionID = 5
		assert.NoError(t, err)
		alloc.HandleConnectionAttempt(from, cid)

		conn := dummyTCPConn{}
		dataConn, err := alloc.AcceptTCPWithConn(conn)
		assert.Equal(t, cid, dataConn.ConnectionID)
		assert.NoError(t, err)
	})

	t.Run("DialWithConn()", func(t *testing.T) {
		relayedAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:13478")
		assert.NoError(t, err)

		var cid proto.ConnectionID = 5
		loggerFactory := logging.NewDefaultLoggerFactory()
		client := &mockClient{
			performTransaction: func(msg *stun.Message, _ net.Addr, _ bool) (TransactionResult, error) {
				typ := stun.NewType(stun.MethodConnect, stun.ClassSuccessResponse)
				if msg.Type.Method == stun.MethodCreatePermission {
					typ = stun.NewType(stun.MethodCreatePermission, stun.ClassSuccessResponse)
				}

				msg, buildErr := stun.Build(
					stun.TransactionID,
					typ,
					cid,
				)
				assert.NoError(t, buildErr)

				return TransactionResult{Msg: msg}, nil
			},
		}
		alloc := NewTCPAllocation(&AllocationConfig{
			Client:      client,
			Lifetime:    time.Second,
			Log:         loggerFactory.NewLogger("test"),
			RelayedAddr: relayedAddr,
		})

		conn := dummyTCPConn{}
		dataConn, err := alloc.DialWithConn(conn, "tcp", "127.0.0.1:11111")
		assert.Equal(t, cid, dataConn.ConnectionID)
		assert.NoError(t, err)
	})
}

type trackingTCPConn struct {
	transport.TCPConn

	closed bool
}

// Read always produces a ConnectionBind success response, which is what
// BindConnection expects as the first frame on a data connection.
func (c *trackingTCPConn) Read(b []byte) (int, error) {
	transactionID := [stun.TransactionIDSize]byte{1, 2, 3}
	messageType := stun.MessageType{Method: stun.MethodConnectionBind, Class: stun.ClassSuccessResponse}
	msg, err := stun.Build(buildMsg(transactionID, messageType)...)
	if err != nil {
		return 0, err
	}

	copy(b, msg.Raw)

	return len(msg.Raw), nil
}

func (c *trackingTCPConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *trackingTCPConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *trackingTCPConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *trackingTCPConn) SetDeadline(time.Time) error      { return nil }
func (c *trackingTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *trackingTCPConn) SetWriteDeadline(time.Time) error { return nil }
func (c *trackingTCPConn) Close() error {
	c.closed = true

	return nil
}

func newBindableTCPAllocation(t *testing.T) *TCPAllocation {
	t.Helper()

	var cid proto.ConnectionID
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	client := &mockClient{
		performTransaction: func(msg *stun.Message, _ net.Addr, _ bool) (TransactionResult, error) {
			if msg.Type.Method == stun.MethodConnect {
				cid++

				res, err := stun.Build(
					stun.TransactionID,
					stun.NewType(stun.MethodConnect, stun.ClassSuccessResponse),
					cid,
				)
				if err != nil {
					return TransactionResult{}, err
				}

				return TransactionResult{Msg: res}, nil
			}

			res, err := stun.Build(
				stun.TransactionID,
				stun.NewType(stun.MethodCreatePermission, stun.ClassSuccessResponse),
			)
			if err != nil {
				return TransactionResult{}, err
			}

			return TransactionResult{Msg: res}, nil
		},
	}

	relayedAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:13478")
	assert.NoError(t, err)

	alloc := NewTCPAllocation(&AllocationConfig{
		Client:      client,
		Lifetime:    time.Minute,
		Log:         log,
		RelayedAddr: relayedAddr,
	})

	// The test drives binds directly, so stop the background refresh timers.
	alloc.refreshAllocTimer.Stop()
	alloc.refreshPermsTimer.Stop()

	return alloc
}

// TestTCPAllocationCloseReleasesConnections verifies that Close closes every
// data connection the allocation handed out, including the first one, and
// that connections closed by the caller are no longer tracked.
func TestTCPAllocationCloseReleasesConnections(t *testing.T) {
	const (
		peerConnections = 32
		rounds          = 50
	)

	for round := 0; round < rounds; round++ {
		alloc := newBindableTCPAllocation(t)

		transports := make([]*trackingTCPConn, 0, peerConnections)
		for i := 0; i < peerConnections; i++ {
			from, err := net.ResolveTCPAddr("tcp", "127.0.0.1:20000")
			require.NoError(t, err)

			transportConn := &trackingTCPConn{}
			transports = append(transports, transportConn)
			alloc.HandleConnectionAttempt(from, proto.ConnectionID(i+1))

			_, err = alloc.AcceptTCPWithConn(transportConn)
			require.NoError(t, err, "round %d: connection %d", round, i)
		}

		require.NoError(t, alloc.Close(), "round %d", round)

		for i, transportConn := range transports {
			assert.True(t, transportConn.closed,
				"round %d: data connection %d stayed open after allocation close", round, i)
		}

		assert.Empty(t, alloc.openConns, "round %d: connections remain tracked", round)
		require.NoError(t, alloc.Close(), "round %d: second close", round)
	}
}

// TestTCPAllocationCloseUnblocksAccept verifies Close unblocks a pending
// Accept with an error instead of leaving it waiting forever.
func TestTCPAllocationCloseUnblocksAccept(t *testing.T) {
	alloc := newBindableTCPAllocation(t)

	errCh := make(chan error, 1)
	go func() {
		_, err := alloc.AcceptTCPWithConn(&trackingTCPConn{})
		errCh <- err
	}()

	// Give Accept a chance to block on the indication channel.
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, alloc.Close())

	select {
	case err := <-errCh:
		require.Error(t, err)
	case <-time.After(time.Second):
		require.FailNow(t, "Accept was not unblocked by Close")
	}
}

// TestTCPAllocationCloseIgnoresLateAttempts verifies a ConnectionAttempt that
// arrives after Close does not block the client's receive loop.
func TestTCPAllocationCloseIgnoresLateAttempts(t *testing.T) {
	alloc := newBindableTCPAllocation(t)
	require.NoError(t, alloc.Close())

	done := make(chan struct{})
	go func() {
		alloc.HandleConnectionAttempt(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, 1)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "HandleConnectionAttempt blocked after Close")
	}
}

// TestTCPConnCloseUntracks verifies that closing a data connection removes it
// from the allocation, so a later allocation Close does not double close it.
func TestTCPConnCloseUntracks(t *testing.T) {
	alloc := newBindableTCPAllocation(t)

	from, err := net.ResolveTCPAddr("tcp", "127.0.0.1:20000")
	require.NoError(t, err)
	alloc.HandleConnectionAttempt(from, 1)

	transportConn := &trackingTCPConn{}
	dataConn, err := alloc.AcceptTCPWithConn(transportConn)
	require.NoError(t, err)
	require.Len(t, alloc.openConns, 1)

	require.NoError(t, dataConn.Close())
	assert.True(t, transportConn.closed)
	assert.Empty(t, alloc.openConns, "closed connection is still tracked")

	// Allocation close must not fail on already-closed connections.
	require.NoError(t, alloc.Close())
}
