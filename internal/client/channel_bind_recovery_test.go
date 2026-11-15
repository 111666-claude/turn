// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package client

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
)

func badRequestMsg() *stun.Message {
	return stun.MustBuild(
		stun.NewType(stun.MethodChannelBind, stun.ClassErrorResponse),
		stun.ErrorCodeAttribute{Code: stun.CodeBadRequest, Reason: []byte("Bad Request")},
	)
}

func channelBindSuccessMsg(method stun.Method) *stun.Message {
	return stun.MustBuild(stun.NewType(method, stun.ClassSuccessResponse))
}

func newTestUDPConn(client *mockClient, bm *bindingManager) UDPConn {
	return UDPConn{
		allocation: allocation{
			client: client,
			log:    logging.NewDefaultLoggerFactory().NewLogger("test"),
		},
		bindingMgr:             bm,
		bindingRefreshInterval: defaultBindingRefreshInterval,
	}
}

func newMockUDPConn(client *mockClient, relayedAddr, serverAddr *net.UDPAddr) *UDPConn {
	return NewUDPConn(&AllocationConfig{
		Client:      client,
		RelayedAddr: relayedAddr,
		ServerAddr:  serverAddr,
		Username:    stun.NewUsername("user"),
		Realm:       stun.NewRealm("realm"),
		Integrity:   stun.NewShortTermIntegrity("pass"),
		Nonce:       stun.NewNonce("nonce"),
		Lifetime:    time.Hour,
		Log:         logging.NewDefaultLoggerFactory().NewLogger("test"),
	})
}

// TestChannelBindUnknownRetries verifies that an initial ChannelBind whose
// transaction ended ambiguously is retried on the next attempt, keeping the
// same channel number for the peer.
func TestChannelBindUnknownRetries(t *testing.T) {
	var attempts atomic.Int32

	bm := newBindingManager()
	bound := bm.create(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	originalCh := bound.number
	conn := newTestUDPConn(&mockClient{
		performTransaction: func(msg *stun.Message, addr net.Addr, dontWait bool) (TransactionResult, error) {
			if attempts.Add(1) == 1 {
				return TransactionResult{}, errFake
			}

			return TransactionResult{Msg: channelBindSuccessMsg(msg.Type.Method)}, nil
		},
	}, bm)

	// First attempt loses its response: the binding must not stay failed.
	conn.maybeBind(bound)
	assert.Eventually(t, func() bool {
		return bound.state() == bindingStateUnknown
	}, 5*time.Second, 10*time.Millisecond)

	// Second attempt is allowed to run and succeeds.
	conn.maybeBind(bound)
	assert.Eventually(t, func() bool {
		return bound.state() == bindingStateReady
	}, 5*time.Second, 10*time.Millisecond)

	b2, ok := bm.findByAddr(bound.addr)
	assert.True(t, ok)
	assert.Equal(t, originalCh, b2.number, "channel number must not change")
	assert.Equal(t, int32(2), attempts.Load(), "exactly two bind requests")
}

// TestChannelBindUnknownRetries100Rounds repeats the lost-response scenario 100
// times to ensure recovery is stable rather than a one-off.
func TestChannelBindUnknownRetries100Rounds(t *testing.T) {
	const rounds = 100

	for i := range rounds {
		bm := newBindingManager()
		bound := bm.create(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000 + i})
		originalCh := bound.number

		var attempts atomic.Int32
		conn := newTestUDPConn(&mockClient{
			performTransaction: func(msg *stun.Message, addr net.Addr, dontWait bool) (TransactionResult, error) {
				// The very first ChannelBind response is lost; the retry must recover.
				if attempts.Add(1) == 1 {
					return TransactionResult{}, newTimeoutError("channel bind timeout")
				}

				return TransactionResult{Msg: channelBindSuccessMsg(msg.Type.Method)}, nil
			},
		}, bm)

		conn.maybeBind(bound)
		assert.Eventuallyf(t, func() bool {
			return bound.state() == bindingStateUnknown
		}, 5*time.Second, time.Millisecond, "round %d: first attempt should be inconclusive", i)

		conn.maybeBind(bound)
		assert.Eventuallyf(t, func() bool {
			return bound.state() == bindingStateReady
		}, 5*time.Second, time.Millisecond, "round %d: retry should succeed", i)

		b2, ok := bm.findByAddr(bound.addr)
		assert.Truef(t, ok, "round %d: binding must remain registered", i)
		assert.Equalf(t, originalCh, b2.number, "round %d: channel number must stay stable", i)
		assert.Equalf(t, int32(2), attempts.Load(), "round %d: exactly two bind requests", i)
	}
}

// TestChannelBind400FreshBindingClosesAllocation verifies that an explicit
// rejection for a binding that was never confirmed still closes the allocation.
func TestChannelBind400FreshBindingClosesAllocation(t *testing.T) {
	relayedAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 3478}

	var channelBindAttempts atomic.Int32
	deallocatedCh := make(chan net.Addr, 1)

	conn := newMockUDPConn(&mockClient{
		performTransaction: func(msg *stun.Message, addr net.Addr, dontWait bool) (TransactionResult, error) {
			switch msg.Type.Method {
			case stun.MethodChannelBind:
				if channelBindAttempts.Add(1) == 1 {
					return TransactionResult{}, newTimeoutError("channel bind timeout")
				}

				return TransactionResult{Msg: badRequestMsg()}, nil
			case stun.MethodRefresh:
				return TransactionResult{}, nil
			default:
				return TransactionResult{}, errFake
			}
		},
		onDeallocated: func(addr net.Addr) {
			deallocatedCh <- addr
		},
	}, relayedAddr, serverAddr)
	defer func() { _ = conn.Close() }()

	bound := conn.bindingMgr.create(peerAddr)

	conn.maybeBind(bound)
	assert.Eventually(t, func() bool {
		return bound.state() == bindingStateUnknown
	}, 5*time.Second, 10*time.Millisecond)

	// The retry receives an explicit rejection: a new binding is not
	// recoverable, so the allocation is closed as before.
	conn.maybeBind(bound)
	assert.Eventually(t, func() bool {
		return bound.state() == bindingStateFailed && conn.isClosed()
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, int32(2), channelBindAttempts.Load())

	select {
	case deallocatedAddr := <-deallocatedCh:
		assert.Equal(t, relayedAddr, deallocatedAddr)
	case <-time.After(5 * time.Second):
		assert.Fail(t, "timed out waiting for deallocation callback")
	}
}

// TestChannelBind400ConfirmedRefreshKeepsBinding verifies that an explicit
// rejection of a refresh for an already-confirmed binding keeps the saved
// channel mapping usable instead of closing the allocation.
func TestChannelBind400ConfirmedRefreshKeepsBinding(t *testing.T) {
	relayedAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 3478}

	var channelBindAttempts atomic.Int32

	conn := newMockUDPConn(&mockClient{
		performTransaction: func(msg *stun.Message, addr net.Addr, dontWait bool) (TransactionResult, error) {
			switch msg.Type.Method {
			case stun.MethodChannelBind:
				if channelBindAttempts.Add(1) == 1 {
					return TransactionResult{}, newTimeoutError("channel bind timeout")
				}

				return TransactionResult{Msg: badRequestMsg()}, nil
			case stun.MethodRefresh:
				return TransactionResult{}, nil
			default:
				return TransactionResult{}, errFake
			}
		},
	}, relayedAddr, serverAddr)
	defer func() { _ = conn.Close() }()

	bound := conn.bindingMgr.create(peerAddr)
	staleRefreshedAt := time.Now().Add(-(defaultBindingRefreshInterval + time.Minute))
	bound.setState(bindingStateReady)
	bound.setRefreshedAt(staleRefreshedAt)

	conn.maybeBind(bound)
	assert.Eventually(t, func() bool {
		return bound.state() == bindingStateReadyUnknown
	}, 5*time.Second, 10*time.Millisecond)

	// The refresh is rejected with 400, but the mapping was confirmed before,
	// so it is kept ready instead of failing the allocation.
	conn.maybeBind(bound)
	assert.Eventually(t, func() bool {
		return channelBindAttempts.Load() == 2 && bound.state() == bindingStateReady
	}, 5*time.Second, 10*time.Millisecond)
	assert.True(t, bound.refreshedAt().Equal(staleRefreshedAt),
		"a rejected refresh must not mark the binding freshly confirmed")
	assert.False(t, conn.isClosed())

	// The kept binding stays eligible for a later refresh.
	startState, ok := conn.startBinding(bound)
	assert.True(t, ok, "recovered binding should remain eligible for refresh")
	assert.Equal(t, bindingStateReady, startState)
	assert.Equal(t, bindingStateRefresh, bound.state())
}
