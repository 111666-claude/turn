// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package turn

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cbrRealm    = "pion.ly"
	cbrUsername = "foo"
	cbrPassword = "pass"
	cbrRelayIP  = "0.0.0.0"
)

// channelBindDropConn drops inbound ChannelBind success responses while
// dropResponses is set, simulating a lossy network for the first attempt.
type channelBindDropConn struct {
	net.PacketConn

	dropResponses atomic.Bool
}

func (c *channelBindDropConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if c.dropResponses.Load() && isChannelBindResponse(p[:n]) {
			continue
		}

		return n, addr, nil
	}
}

func isChannelBindResponse(raw []byte) bool {
	msg := &stun.Message{Raw: raw}
	if err := msg.Decode(); err != nil {
		return false
	}

	return msg.Type.Method == stun.MethodChannelBind && msg.Type.Class == stun.ClassSuccessResponse
}

type channelBindRecorder struct {
	mutex       sync.Mutex
	channelNums []uint16
	txIDs       map[string]struct{}
}

func (r *channelBindRecorder) record(msg *stun.Message) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.txIDs == nil {
		r.txIDs = map[string]struct{}{}
	}
	r.txIDs[string(msg.TransactionID[:])] = struct{}{}

	var ch proto.ChannelNumber
	if err := ch.GetFrom(msg); err == nil {
		r.channelNums = append(r.channelNums, uint16(ch))
	}
}

func (r *channelBindRecorder) distinctTransactions() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return len(r.txIDs)
}

func (r *channelBindRecorder) distinctChannels() []uint16 {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	seen := map[uint16]struct{}{}
	var out []uint16
	for _, n := range r.channelNums {
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}

	return out
}

// recordingClientConn records outbound ChannelBind requests before forwarding
// them, so the test can observe retries and the channel numbers they use.
type recordingClientConn struct {
	net.PacketConn

	recorder *channelBindRecorder
}

func (c *recordingClientConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	msg := &stun.Message{Raw: p}
	if err := msg.Decode(); err == nil &&
		msg.Type.Method == stun.MethodChannelBind &&
		msg.Type.Class == stun.ClassRequest {
		c.recorder.record(msg)
	}

	return c.PacketConn.WriteTo(p, addr)
}

func startChannelBindTestServer(t *testing.T) net.PacketConn {
	t.Helper()

	listener, err := net.ListenPacket("udp4", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)

	server, err := NewServer(ServerConfig{
		AuthHandler: func(ra *RequestAttributes) (string, []byte, bool) {
			return ra.Username, GenerateAuthKey(ra.Username, ra.Realm, cbrPassword), true
		},
		PacketConnConfigs: []PacketConnConfig{
			{
				PacketConn: listener,
				RelayAddressGenerator: &RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      cbrRelayIP,
				},
			},
		},
		Realm: cbrRealm,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, server.Close()) })

	return listener
}

// readPeerPackets forwards every packet received on conn to the returned
// channel until conn is closed.
func readPeerPackets(conn net.PacketConn) <-chan string {
	packets := make(chan string, 16)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case packets <- string(buf[:n]):
			default:
			}
		}
	}()

	return packets
}

// TestClientChannelBindRecoversFromLostResponse reproduces the weak-network
// scenario: the first ChannelBind response is lost. A later write must retry
// the binding and, once it succeeds, use the same channel number.
func TestClientChannelBindRecoversFromLostResponse(t *testing.T) {
	serverListener := startChannelBindTestServer(t)

	clientListener, err := net.ListenPacket("udp4", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)
	// Close the socket last so the client's read loop and the allocation
	// shutdown have a working connection, then no goroutine outlives the test.
	t.Cleanup(func() { assert.NoError(t, clientListener.Close()) })

	dropConn := &channelBindDropConn{PacketConn: clientListener}
	dropConn.dropResponses.Store(true)

	recorder := &channelBindRecorder{}
	client, err := NewClient(&ClientConfig{
		Conn:           &recordingClientConn{PacketConn: dropConn, recorder: recorder},
		TURNServerAddr: serverListener.LocalAddr().String(),
		Username:       cbrUsername,
		Password:       cbrPassword,
		Realm:          cbrRealm,
		RTO:            10 * time.Millisecond,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)
	require.NoError(t, client.Listen())
	t.Cleanup(client.Close)

	allocation, err := client.Allocate()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, allocation.Close()) })

	peerConn, err := net.ListenPacket("udp4", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, peerConn.Close()) })

	peerAddr := peerConn.LocalAddr()
	peerPackets := readPeerPackets(peerConn)

	// First write: the ChannelBind response is lost, so the transaction
	// eventually fails without any confirmation.
	_, err = allocation.WriteTo([]byte("first"), peerAddr)
	require.NoError(t, err)

	// Wait until the first bind attempt has exhausted its retransmissions.
	require.Eventually(t, func() bool {
		return recorder.distinctTransactions() >= 1
	}, 5*time.Second, 10*time.Millisecond)
	time.Sleep(2 * time.Second)

	// Stop dropping; the next write must be allowed to retry the binding.
	dropConn.dropResponses.Store(false)

	firstChannels := recorder.distinctChannels()
	require.Len(t, firstChannels, 1, "first attempt should have used exactly one channel number")

	require.Eventually(t, func() bool {
		_, writeErr := allocation.WriteTo([]byte("retry"), peerAddr)

		return writeErr == nil && recorder.distinctTransactions() >= 2
	}, 5*time.Second, 100*time.Millisecond)

	// The retry must keep the original channel and deliver the payload.
	require.Eventually(t, func() bool {
		if recorder.distinctChannels()[0] != firstChannels[0] {
			return false
		}
		select {
		case msg := <-peerPackets:
			return msg == "retry" || msg == "first"
		default:
			return false
		}
	}, 5*time.Second, 50*time.Millisecond)

	assert.Equal(t, firstChannels, recorder.distinctChannels(),
		"retry must not change the channel number for the same peer")
}
