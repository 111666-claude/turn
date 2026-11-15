// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package allocation

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v4/internal/ipnet"
	"github.com/pion/turn/v4/internal/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPermission(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3478")
	assert.NoError(t, err)

	addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:3479")
	assert.NoError(t, err)

	addr3, err := net.ResolveUDPAddr("udp", "127.0.0.2:3478")
	assert.NoError(t, err)

	perms := &Permission{
		Addr:    addr,
		timeout: DefaultPermissionTimeout,
	}
	perms2 := &Permission{
		Addr:    addr2,
		timeout: DefaultPermissionTimeout,
	}
	perms3 := &Permission{
		Addr:    addr3,
		timeout: DefaultPermissionTimeout,
	}

	alloc.AddPermission(perms)
	alloc.AddPermission(perms2)
	alloc.AddPermission(perms3)

	foundP1 := alloc.GetPermission(addr)
	assert.Equal(t, perms, foundP1, "Should keep the first one.")

	foundP2 := alloc.GetPermission(addr2)
	assert.Equal(t, perms, foundP2, "Second one should be ignored.")

	foundP3 := alloc.GetPermission(addr3)
	assert.Equal(t, perms3, foundP3, "Permission with another IP should be found")
}

func TestAddPermission(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3478")
	assert.NoError(t, err)

	p := &Permission{
		Addr:    addr,
		timeout: DefaultPermissionTimeout,
	}

	alloc.AddPermission(p)
	assert.Equal(t, alloc, p.allocation, "Permission's allocation should be the adder.")

	foundPermission := alloc.GetPermission(p.Addr)
	assert.Equal(t, p, foundPermission)
}

func TestRemovePermission(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3478")
	assert.NoError(t, err)

	p := &Permission{
		Addr:    addr,
		timeout: DefaultPermissionTimeout,
	}

	alloc.AddPermission(p)

	foundPermission := alloc.GetPermission(p.Addr)
	assert.Equal(t, p, foundPermission, "Got permission is not same as the the added.")

	alloc.RemovePermission(p.Addr)

	foundPermission = alloc.GetPermission(p.Addr)
	assert.Nil(t, foundPermission, "Got permission should be nil after removed.")
}

func TestAddChannelBind(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3478")
	assert.NoError(t, err)

	c := NewChannelBind(proto.MinChannelNumber, addr, nil)

	err = alloc.AddChannelBind(c, proto.DefaultLifetime, DefaultPermissionTimeout)
	assert.Nil(t, err, "should succeed")
	assert.Equal(t, alloc, c.allocation, "allocation should be the caller.")

	c2 := NewChannelBind(proto.MinChannelNumber+1, addr, nil)
	err = alloc.AddChannelBind(c2, proto.DefaultLifetime, DefaultPermissionTimeout)
	assert.NotNil(t, err, "should failed with conflicted peer address")

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:3479")
	c3 := NewChannelBind(proto.MinChannelNumber, addr2, nil)
	err = alloc.AddChannelBind(c3, proto.DefaultLifetime, DefaultPermissionTimeout)
	assert.NotNil(t, err, "should fail with conflicted number.")
}

func TestGetChannelByNumber(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3478")
	assert.NoError(t, err)

	c := NewChannelBind(proto.MinChannelNumber, addr, nil)

	_ = alloc.AddChannelBind(c, proto.DefaultLifetime, DefaultPermissionTimeout)

	existChannel := alloc.GetChannelByNumber(c.Number)
	assert.Equal(t, c, existChannel)

	notExistChannel := alloc.GetChannelByNumber(proto.MinChannelNumber + 1)
	assert.Nil(t, notExistChannel, "should be nil for not existed channel.")
}

func TestGetChannelByAddr(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3478")
	assert.NoError(t, err)

	c := NewChannelBind(proto.MinChannelNumber, addr, nil)

	_ = alloc.AddChannelBind(c, proto.DefaultLifetime, DefaultPermissionTimeout)

	existChannel := alloc.GetChannelByAddr(c.Peer)
	assert.Equal(t, c, existChannel)

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:3479")
	notExistChannel := alloc.GetChannelByAddr(addr2)
	assert.Nil(t, notExistChannel, "should be nil for not existed channel.")
}

func TestRemoveChannelBind(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3478")
	assert.NoError(t, err)

	c := NewChannelBind(proto.MinChannelNumber, addr, nil)

	_ = alloc.AddChannelBind(c, proto.DefaultLifetime, DefaultPermissionTimeout)

	alloc.RemoveChannelBind(c.Number)

	channelByNumber := alloc.GetChannelByNumber(c.Number)
	assert.Nil(t, channelByNumber)

	channelByAddr := alloc.GetChannelByAddr(c.Peer)
	assert.Nil(t, channelByAddr)
}

func TestAllocationRefresh(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	alloc.lifetimeTimer = time.AfterFunc(proto.DefaultLifetime, func() {
		wg.Done()
	})
	alloc.Refresh(0)
	wg.Wait()

	// LifetimeTimer has expired
	assert.False(t, alloc.lifetimeTimer.Stop())
}

func TestAllocationClose(t *testing.T) {
	network := "udp"

	l, err := net.ListenPacket(network, "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	alloc := NewAllocation(nil, nil, EventHandler{}, nil)
	alloc.relayPacketConn = l
	// Add mock lifetimeTimer
	alloc.lifetimeTimer = time.AfterFunc(proto.DefaultLifetime, func() {})

	// Add channel
	addr, err := net.ResolveUDPAddr(network, "127.0.0.1:3478")
	assert.NoError(t, err)

	c := NewChannelBind(proto.MinChannelNumber, addr, nil)
	_ = alloc.AddChannelBind(c, proto.DefaultLifetime, DefaultPermissionTimeout)

	// Add permission
	alloc.AddPermission(NewPermission(addr, nil, DefaultPermissionTimeout))

	assert.Nil(t, alloc.Close(), "should succeed")
	assert.True(t, isClose(alloc.relayPacketConn), "should be closed")
}

func TestPacketHandler(t *testing.T) {
	network := "udp"

	manager, _ := newTestManager()

	// TURN server initialization
	turnSocket, err := net.ListenPacket(network, "127.0.0.1:0") // nolint: noctx
	assert.NoError(t, err)

	// Client listener initialization
	clientListener, err := net.ListenPacket(network, "127.0.0.1:0") // nolint: noctx
	assert.NoError(t, err)

	dataCh := make(chan []byte)
	// Client listener read data
	go func() {
		buffer := make([]byte, rtpMTU)
		for {
			n, _, err2 := clientListener.ReadFrom(buffer)
			if err2 != nil {
				return
			}

			dataCh <- buffer[:n]
		}
	}()

	alloc, err := manager.CreateAllocation(&FiveTuple{
		SrcAddr: clientListener.LocalAddr(),
		DstAddr: turnSocket.LocalAddr(),
	}, turnSocket, proto.ProtoUDP, 0, proto.DefaultLifetime, "", "")

	assert.NoError(t, err, "should succeed")

	peerListener1, err := net.ListenPacket(network, "127.0.0.1:0") // nolint: noctx
	assert.NoError(t, err)

	peerListener2, err := net.ListenPacket(network, "127.0.0.1:0") // nolint: noctx
	assert.NoError(t, err)

	// Add permission with peer1 address
	alloc.AddPermission(NewPermission(peerListener1.LocalAddr(), manager.log, DefaultPermissionTimeout))
	// Add channel with min channel number and peer2 address
	channelBind := NewChannelBind(proto.MinChannelNumber, peerListener2.LocalAddr(), manager.log)
	_ = alloc.AddChannelBind(channelBind, proto.DefaultLifetime, DefaultPermissionTimeout)

	_, port, _ := ipnet.AddrIPPort(alloc.relayPacketConn.LocalAddr())
	relayAddrWithHostStr := fmt.Sprintf("127.0.0.1:%d", port)
	relayAddrWithHost, _ := net.ResolveUDPAddr(network, relayAddrWithHostStr)

	// Test for permission and data message
	targetText := "permission"
	_, _ = peerListener1.WriteTo([]byte(targetText), relayAddrWithHost)
	data := <-dataCh

	// Resolve stun data message
	assert.True(t, stun.IsMessage(data), "should be stun message")

	var msg stun.Message
	assert.NoError(t, stun.Decode(data, &msg), "decode data to stun message failed")

	var msgData proto.Data
	assert.NoError(t, msgData.GetFrom(&msg), "get data from stun message failed")
	assert.Equal(t, targetText, string(msgData), "get message doesn't equal the target text")

	// Test for channel bind and channel data
	targetText2 := "channel bind"
	_, _ = peerListener2.WriteTo([]byte(targetText2), relayAddrWithHost)
	data = <-dataCh

	// Resolve channel data
	assert.True(t, proto.IsChannelData(data), "should be channel data")

	channelData := proto.ChannelData{
		Raw: data,
	}
	assert.NoError(t, channelData.Decode(), fmt.Sprintf("channel data decode with error: %v", err))
	assert.Equal(t, channelBind.Number, channelData.Number, "get channel data's number is invalid")
	assert.Equal(t, targetText2, string(channelData.Data), "get data doesn't equal the target text.")

	// Listeners close
	_ = manager.Close()
	_ = clientListener.Close()
	_ = peerListener1.Close()
	_ = peerListener2.Close()
}

func TestResponseCache(t *testing.T) {
	alloc := NewAllocation(nil, nil, EventHandler{}, nil)
	transactionID := [stun.TransactionIDSize]byte{1, 2, 3}
	responseAttrs := []stun.Setter{
		&proto.Lifetime{
			Duration: proto.DefaultLifetime,
		},
	}
	alloc.SetResponseCache(transactionID, responseAttrs)

	cacheID, cacheAttr := alloc.GetResponseCache()
	assert.Equal(t, transactionID, cacheID)
	assert.Equal(t, responseAttrs, cacheAttr)
}

type mockAddr string

func (d mockAddr) Network() string { return "" }
func (d mockAddr) String() string  { return string(d) }

type mockConn struct {
	remoteAddr net.Addr
	localAddr  net.Addr
	closed     atomic.Bool
}

func (c *mockConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (c *mockConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func (c *mockConn) Close() error {
	c.closed.Store(true)

	return nil
}

func (c *mockConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}

	return mockAddr("local")
}

func (c *mockConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *mockConn) SetDeadline(time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(time.Time) error { return nil }

func (c *mockConn) wasClosed() bool {
	return c.closed.Load()
}

type mockRelayListener struct {
	conn net.Conn

	haveAccepted atomic.Bool

	acceptErr  bool
	closeCalls atomic.Int32
	addr       net.Addr
}

func (l *mockRelayListener) Accept() (net.Conn, error) {
	if !l.haveAccepted.Swap(true) {
		if l.acceptErr {
			return nil, io.EOF
		}
		if l.conn == nil {
			return nil, io.EOF
		}

		return l.conn, nil
	}

	return nil, io.EOF
}

func (l *mockRelayListener) Close() error {
	l.closeCalls.Add(1)

	return nil
}

func (l *mockRelayListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}

	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (l *mockRelayListener) closeCount() int {
	return int(l.closeCalls.Load())
}

type writeErrHolder struct {
	err error
}

type mockTurnSocket struct {
	writeErr atomic.Pointer[writeErrHolder]
	writes   atomic.Int32
}

func (m *mockTurnSocket) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }

func (m *mockTurnSocket) WriteTo([]byte, net.Addr) (int, error) {
	m.writes.Add(1)
	if h := m.writeErr.Load(); h != nil {
		return 0, h.err
	}

	return 0, nil
}

func (m *mockTurnSocket) Close() error                     { return nil }
func (m *mockTurnSocket) LocalAddr() net.Addr              { return mockAddr("turnsocket") }
func (m *mockTurnSocket) SetDeadline(time.Time) error      { return nil }
func (m *mockTurnSocket) SetReadDeadline(time.Time) error  { return nil }
func (m *mockTurnSocket) SetWriteDeadline(time.Time) error { return nil }
func (m *mockTurnSocket) writeCount() int                  { return int(m.writes.Load()) }
func (m *mockTurnSocket) setWriteErr(err error) {
	if err == nil {
		m.writeErr.Store(nil)

		return
	}
	m.writeErr.Store(&writeErrHolder{err: err})
}

func newTestAllocationForConnHandler(t *testing.T, ln net.Listener, turnSocket net.PacketConn) (*Manager, *Allocation) {
	t.Helper()
	log := logging.NewDefaultLoggerFactory().NewLogger("test")

	fiveTuple := &FiveTuple{
		Protocol: TCP,
		SrcAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1111},
		DstAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222},
	}

	a := NewAllocation(turnSocket, fiveTuple, EventHandler{}, log)
	a.relayListener = ln
	a.RelayAddr = ln.Addr()
	a.lifetimeTimer = time.NewTimer(time.Hour)

	m := &Manager{
		log:         log,
		allocations: map[FiveTupleFingerprint]*Allocation{fiveTuple.Fingerprint(): a},
	}

	return m, a
}

func TestAllocationConnHandler_AcceptErrorDeletesAllocation(t *testing.T) {
	ln := &mockRelayListener{
		acceptErr: true,
	}
	turnSocket := &mockTurnSocket{}
	m, a := newTestAllocationForConnHandler(t, ln, turnSocket)

	a.connHandler(m)

	assert.Nil(t, m.GetAllocation(a.fiveTuple))
	assert.Equal(t, 1, ln.closeCount())
}

func TestAllocationConnHandler_RemoteAddrCastFailureClosesConn(t *testing.T) {
	badConn := &mockConn{remoteAddr: mockAddr("")}
	ln := &mockRelayListener{
		conn: badConn,
	}
	turnSocket := &mockTurnSocket{}
	m, a := newTestAllocationForConnHandler(t, ln, turnSocket)

	a.connHandler(m)

	assert.True(t, badConn.wasClosed())
	assert.Equal(t, 0, turnSocket.writeCount())
}

func TestAllocationConnHandler_AddTCPConnectionErrorClosesConn(t *testing.T) {
	remote := &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5555}
	existingConn := &mockConn{remoteAddr: remote}
	newConn := &mockConn{remoteAddr: remote}

	ln := &mockRelayListener{
		conn: newConn,
	}
	turnSocket := &mockTurnSocket{}
	m, a := newTestAllocationForConnHandler(t, ln, turnSocket)

	a.tcpConnections[proto.ConnectionID(1)] = &tcpConnection{Conn: existingConn}

	a.connHandler(m)

	assert.True(t, newConn.wasClosed())
	assert.Equal(t, 0, turnSocket.writeCount())
}

func TestAllocationConnHandler_StunBuildErrorRemovesConnection(t *testing.T) {
	conn := &mockConn{remoteAddr: &net.TCPAddr{IP: net.IP{1, 2, 3}, Port: 5555}}

	ln := &mockRelayListener{
		conn: conn,
	}
	turnSocket := &mockTurnSocket{}
	m, a := newTestAllocationForConnHandler(t, ln, turnSocket)

	a.connHandler(m)

	assert.True(t, conn.wasClosed())
	assert.Empty(t, a.tcpConnections)
	assert.Equal(t, 0, turnSocket.writeCount())
}

func TestAllocationConnHandler_TurnSocketWriteErrorRemovesConnection(t *testing.T) {
	conn := &mockConn{remoteAddr: &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5555}}

	ln := &mockRelayListener{
		conn: conn,
	}
	turnSocket := &mockTurnSocket{}
	turnSocket.setWriteErr(io.EOF)

	m, a := newTestAllocationForConnHandler(t, ln, turnSocket)

	a.connHandler(m)

	assert.True(t, conn.wasClosed())
	assert.Empty(t, a.tcpConnections)
	assert.Equal(t, 1, turnSocket.writeCount())
}

// newMockTCPConn returns a mock connection with the given peer address.
func newMockTCPConn(port int) *mockConn {
	return &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
	}
}

// newTestTCPAllocation builds a Manager with a TCP allocation registered at
// the given five-tuple. The relay listener is a mock, so no accept loop runs.
func newTestTCPAllocation(t *testing.T, fiveTuple *FiveTuple) (*Manager, *Allocation) {
	t.Helper()

	log := logging.NewDefaultLoggerFactory().NewLogger("test")

	a := NewAllocation(&mockTurnSocket{}, fiveTuple, EventHandler{}, log)
	a.relayListener = &mockRelayListener{}
	a.RelayAddr = a.relayListener.Addr()
	a.lifetimeTimer = time.NewTimer(time.Hour)

	m := &Manager{
		log:                      log,
		tcpConnectionBindTimeout: time.Hour,
		allocations:              map[FiveTupleFingerprint]*Allocation{fiveTuple.Fingerprint(): a},
	}

	return m, a
}

func (a *Allocation) tcpConnectionCount() int {
	a.tcpConnectionsLock.Lock()
	defer a.tcpConnectionsLock.Unlock()

	return len(a.tcpConnections)
}

func (a *Allocation) tcpConnection(id proto.ConnectionID) *tcpConnection {
	a.tcpConnectionsLock.Lock()
	defer a.tcpConnectionsLock.Unlock()

	return a.tcpConnections[id]
}

// TestAllocationCloseReleasesAllTCPConnections reproduces the reported
// scenario: a TCP allocation holds a batch of peer data connections. Closing
// the allocation must release all of them (the first one included) and leave
// other allocations untouched, consistently across repeated rounds.
func TestAllocationCloseReleasesAllTCPConnections(t *testing.T) {
	const (
		peerConnections = 32
		rounds          = 50
	)

	for round := 0; round < rounds; round++ {
		fiveTuple := &FiveTuple{
			Protocol: TCP,
			SrcAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000 + round},
			DstAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222},
		}
		otherFiveTuple := &FiveTuple{
			Protocol: TCP,
			SrcAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 1000 + round},
			DstAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 4), Port: 2222},
		}

		mgr, alloc := newTestTCPAllocation(t, fiveTuple)

		// A second allocation with a peer connection of its own, to prove
		// closing the first one does not touch it.
		other := NewAllocation(&mockTurnSocket{}, otherFiveTuple, EventHandler{}, mgr.log)
		other.relayListener = &mockRelayListener{}
		other.RelayAddr = other.relayListener.Addr()
		other.lifetimeTimer = time.NewTimer(time.Hour)
		otherConn := newMockTCPConn(30000)
		other.tcpConnections[proto.ConnectionID(999)] = &tcpConnection{Conn: otherConn}
		mgr.allocations[otherFiveTuple.Fingerprint()] = other

		conns := make([]*mockConn, 0, peerConnections)
		for i := 0; i < peerConnections; i++ {
			conn := newMockTCPConn(20000 + i)
			conns = append(conns, conn)

			_, err := mgr.addTCPConnection(alloc, conn)
			require.NoError(t, err, "round %d: peer connection %d", round, i)
		}

		// Bind timeout is irrelevant for this test; stop the timers so they
		// do not fire while the test holds connections.
		alloc.tcpConnectionsLock.Lock()
		for _, tcpConn := range alloc.tcpConnections {
			if tcpConn.bindTimer != nil {
				tcpConn.bindTimer.Stop()
			}
		}
		alloc.tcpConnectionsLock.Unlock()

		require.Equal(t, peerConnections, alloc.tcpConnectionCount(), "round %d", round)

		// Closing through the manager is the path the server takes.
		mgr.DeleteAllocation(fiveTuple)

		for i, conn := range conns {
			assert.True(t, conn.wasClosed(),
				"round %d: peer connection %d remained open after allocation close", round, i)
		}
		assert.Equal(t, 0, alloc.tcpConnectionCount(), "round %d: connections remain registered", round)

		// Repeated close must be a no-op and must not disturb other allocations.
		require.NoError(t, alloc.Close(), "round %d: second close", round)
		assert.Equal(t, 0, alloc.tcpConnectionCount(), "round %d: connections reappeared", round)
		assert.False(t, otherConn.wasClosed(), "round %d: other allocation connection was closed", round)
		assert.Equal(t, 1, mgr.AllocationCount(), "round %d: unrelated allocation was removed", round)

		mgr.DeleteAllocation(otherFiveTuple)
		assert.True(t, otherConn.wasClosed(), "round %d: other allocation connection leaked", round)
		assert.Equal(t, 0, mgr.AllocationCount(), "round %d", round)
	}
}

// TestAllocationCloseReleasesPendingBind makes sure a peer data connection
// that a ConnectionBind has not claimed yet is closed when the allocation is
// released, so a pending bind cannot keep it alive.
func TestAllocationCloseReleasesPendingBind(t *testing.T) {
	fiveTuple := &FiveTuple{
		Protocol: TCP,
		SrcAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1111},
		DstAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222},
	}

	conn := newMockTCPConn(1)
	mgr, alloc := newTestTCPAllocation(t, fiveTuple)

	connectionID, err := mgr.addTCPConnection(alloc, conn)
	require.NoError(t, err)

	// Not bound yet: GetTCPConnection would hand it to a ConnectionBind.
	tcpConn := alloc.tcpConnection(connectionID)
	require.NotNil(t, tcpConn)
	require.False(t, tcpConn.isBound.Load())

	require.NoError(t, alloc.Close())

	assert.True(t, conn.wasClosed(), "peer connection with a pending bind was not released")
	assert.Nil(t, mgr.GetTCPConnection("", connectionID), "released connection is still bindable")
}

// TestAllocationCloseIsIdempotentAndConcurrencySafe exercises Close against
// concurrent RemoveTCPConnection calls: no connection may survive and Close
// must stay a no-op when repeated.
func TestAllocationCloseIsIdempotentAndConcurrencySafe(t *testing.T) {
	const peerConnections = 32

	for round := 0; round < 50; round++ {
		fiveTuple := &FiveTuple{
			Protocol: TCP,
			SrcAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000 + round},
			DstAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222},
		}

		mgr, alloc := newTestTCPAllocation(t, fiveTuple)

		conns := make([]*mockConn, 0, peerConnections)
		ids := make([]proto.ConnectionID, 0, peerConnections)
		for i := 0; i < peerConnections; i++ {
			conn := newMockTCPConn(40000 + i)
			conns = append(conns, conn)

			connectionID, err := mgr.addTCPConnection(alloc, conn)
			require.NoError(t, err)
			ids = append(ids, connectionID)
		}

		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Add(1)
			go func(id proto.ConnectionID) {
				defer wg.Done()

				alloc.RemoveTCPConnection(id)
			}(id)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			_ = alloc.Close()
		}()

		wg.Wait()

		for i, conn := range conns {
			assert.True(t, conn.wasClosed(), "round %d: connection %d leaked", round, i)
		}
		assert.Equal(t, 0, alloc.tcpConnectionCount(), "round %d", round)
		require.NoError(t, alloc.Close(), "round %d: repeated close", round)
	}
}

// TestTCPConnectionBindTimeoutClosesUnbound makes sure a peer data connection
// that never receives a ConnectionBind is closed when the bind timer fires,
// and that a connection which was bound is left alone.
func TestTCPConnectionBindTimeoutClosesUnbound(t *testing.T) {
	fiveTuple := &FiveTuple{
		Protocol: TCP,
		SrcAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1111},
		DstAddr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222},
	}

	mgr, alloc := newTestTCPAllocation(t, fiveTuple)
	mgr.tcpConnectionBindTimeout = time.Millisecond

	unbound := newMockTCPConn(1)
	unboundID, err := mgr.addTCPConnection(alloc, unbound)
	require.NoError(t, err)

	bound := newMockTCPConn(2)
	boundID, err := mgr.addTCPConnection(alloc, bound)
	require.NoError(t, err)

	require.NotNil(t, mgr.GetTCPConnection("", boundID))

	require.Eventually(t, func() bool {
		return unbound.wasClosed()
	}, time.Second, time.Millisecond, "unbound connection was never closed")

	assert.Nil(t, mgr.GetTCPConnection("", unboundID), "timed out connection is still bindable")
	assert.False(t, bound.wasClosed(), "bound connection was closed by the bind timer")
	assert.NotNil(t, alloc.tcpConnection(boundID), "bound connection was removed")
}
