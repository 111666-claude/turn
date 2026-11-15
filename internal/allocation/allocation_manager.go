// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package allocation

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/randutil"
	"github.com/pion/turn/v4/internal/proto"
)

// If no ConnectionBind request associated with a peer data connection is
// received within this duration, the peer data connection MUST be closed.
// See: https://datatracker.ietf.org/doc/html/rfc6062#section-5.4
const defaultTCPConnectionBindTimeout = 30 * time.Second

// ManagerConfig a bag of config params for Manager.
type ManagerConfig struct {
	LeveledLogger      logging.LeveledLogger
	AllocatePacketConn func(network string, requestedPort int) (net.PacketConn, net.Addr, error)
	AllocateListener   func(network string, requestedPort int) (net.Listener, net.Addr, error)
	PermissionHandler  func(sourceAddr net.Addr, peerIP net.IP) bool
	EventHandler       EventHandler

	tcpConnectionBindTimeout time.Duration
}

type reservation struct {
	token string
	port  int
}

// Manager is used to hold active allocations.
type Manager struct {
	lock                     sync.RWMutex
	log                      logging.LeveledLogger
	tcpConnectionBindTimeout time.Duration

	allocations  map[FiveTupleFingerprint]*Allocation
	reservations []*reservation

	allocatePacketConn func(network string, requestedPort int) (net.PacketConn, net.Addr, error)
	allocateListener   func(network string, requestedPort int) (net.Listener, net.Addr, error)
	permissionHandler  func(sourceAddr net.Addr, peerIP net.IP) bool
	EventHandler       EventHandler
}

// NewManager creates a new instance of Manager.
func NewManager(config ManagerConfig) (*Manager, error) {
	switch {
	case config.AllocatePacketConn == nil:
		return nil, errAllocatePacketConnMustBeSet
	case config.AllocateListener == nil:
		return nil, errAllocateListenerMustBeSet
	case config.LeveledLogger == nil:
		return nil, errLeveledLoggerMustBeSet
	}

	tcpConnectionBindTimeout := config.tcpConnectionBindTimeout
	if tcpConnectionBindTimeout == 0 {
		tcpConnectionBindTimeout = defaultTCPConnectionBindTimeout
	}

	return &Manager{
		log:                      config.LeveledLogger,
		allocations:              make(map[FiveTupleFingerprint]*Allocation, 64),
		allocatePacketConn:       config.AllocatePacketConn,
		allocateListener:         config.AllocateListener,
		permissionHandler:        config.PermissionHandler,
		EventHandler:             config.EventHandler,
		tcpConnectionBindTimeout: tcpConnectionBindTimeout,
	}, nil
}

// GetAllocation fetches the allocation matching the passed FiveTuple.
func (m *Manager) GetAllocation(fiveTuple *FiveTuple) *Allocation {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.allocations[fiveTuple.Fingerprint()]
}

// GetAllocationForUsername fetches the allocation matching the passed FiveTuple and Username.
func (m *Manager) GetAllocationForUsername(fiveTuple *FiveTuple, username string) *Allocation {
	allocation := m.GetAllocation(fiveTuple)
	if allocation != nil && allocation.username == username {
		return allocation
	}

	return nil
}

// AllocationCount returns the number of existing allocations.
func (m *Manager) AllocationCount() int {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return len(m.allocations)
}

// Close closes the manager and closes all allocations it manages.
func (m *Manager) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, a := range m.allocations {
		if err := a.Close(); err != nil {
			return err
		}
	}

	return nil
}

// CreateAllocation creates a new allocation and starts relaying.
func (m *Manager) CreateAllocation( // nolint: cyclop
	fiveTuple *FiveTuple,
	turnSocket net.PacketConn,
	protocol proto.Protocol,
	requestedPort int,
	lifetime time.Duration,
	username, realm string,
) (*Allocation, error) {
	switch {
	case fiveTuple == nil:
		return nil, errNilFiveTuple
	case fiveTuple.SrcAddr == nil:
		return nil, errNilFiveTupleSrcAddr
	case fiveTuple.DstAddr == nil:
		return nil, errNilFiveTupleDstAddr
	case turnSocket == nil:
		return nil, errNilTurnSocket
	case lifetime == 0:
		return nil, errLifetimeZero
	}

	if alloc := m.GetAllocation(fiveTuple); alloc != nil {
		return nil, fmt.Errorf("%w: %v", errDupeFiveTuple, fiveTuple)
	}
	alloc := NewAllocation(turnSocket, fiveTuple, m.EventHandler, m.log)
	alloc.username = username
	alloc.realm = realm

	if protocol == proto.ProtoUDP {
		conn, relayAddr, err := m.allocatePacketConn("udp4", requestedPort)
		if err != nil {
			return nil, err
		}

		alloc.relayPacketConn = conn
		alloc.RelayAddr = relayAddr
	} else if protocol == proto.ProtoTCP {
		ln, relayAddr, err := m.allocateListener("tcp4", requestedPort)
		if err != nil {
			return nil, err
		}

		alloc.relayListener = ln
		alloc.RelayAddr = relayAddr
	}

	m.log.Debugf("Listening on relay address: %s", alloc.RelayAddr)

	alloc.lifetimeTimer = time.AfterFunc(lifetime, func() {
		m.deleteAllocation(alloc.fiveTuple, alloc)
	})

	m.lock.Lock()
	m.allocations[fiveTuple.Fingerprint()] = alloc
	m.lock.Unlock()

	if m.EventHandler.OnAllocationCreated != nil {
		m.EventHandler.OnAllocationCreated(fiveTuple.SrcAddr, fiveTuple.DstAddr,
			fiveTuple.Protocol.String(), username, realm, alloc.RelayAddr, requestedPort)
	}

	// Only start the UDP relay loop for UDP allocations.
	if alloc.relayPacketConn != nil {
		go alloc.packetConnHandler(m)
	}
	// For TCP allocations, accept inbound connections on the relayed listener and notify the client.
	if alloc.relayListener != nil {
		go alloc.connHandler(m)
	}

	return alloc, nil
}

// DeleteAllocation removes an allocation.
func (m *Manager) DeleteAllocation(fiveTuple *FiveTuple) {
	m.deleteAllocation(fiveTuple, nil)
}

// deleteAllocation removes an allocation. When expected is non-nil the
// allocation is only removed if it is still the one registered for the
// five-tuple. This keeps a lifetime timer or relay loop belonging to an
// allocation that has already been replaced from tearing down its successor.
func (m *Manager) deleteAllocation(fiveTuple *FiveTuple, expected *Allocation) {
	fingerprint := fiveTuple.Fingerprint()

	m.lock.Lock()
	allocation := m.allocations[fingerprint]
	if allocation == nil || (expected != nil && allocation != expected) {
		m.lock.Unlock()

		return
	}
	delete(m.allocations, fingerprint)
	m.lock.Unlock()

	if err := allocation.Close(); err != nil {
		m.log.Errorf("Failed to close allocation: %v", err)
	}

	if m.EventHandler.OnAllocationDeleted != nil {
		m.EventHandler.OnAllocationDeleted(fiveTuple.SrcAddr, fiveTuple.DstAddr,
			fiveTuple.Protocol.String(), allocation.username, allocation.realm)
	}
}

// CreateReservation stores the reservation for the token+port.
func (m *Manager) CreateReservation(reservationToken string, port int) {
	time.AfterFunc(30*time.Second, func() {
		m.lock.Lock()
		defer m.lock.Unlock()
		for i := len(m.reservations) - 1; i >= 0; i-- {
			if m.reservations[i].token == reservationToken {
				m.reservations = append(m.reservations[:i], m.reservations[i+1:]...)

				return
			}
		}
	})

	m.lock.Lock()
	m.reservations = append(m.reservations, &reservation{
		token: reservationToken,
		port:  port,
	})
	m.lock.Unlock()
}

// GetReservation returns the port for a given reservation if it exists.
func (m *Manager) GetReservation(reservationToken string) (int, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	for _, r := range m.reservations {
		if r.token == reservationToken {
			return r.port, true
		}
	}

	return 0, false
}

// GetRandomEvenPort returns a random un-allocated udp4 port.
func (m *Manager) GetRandomEvenPort() (int, error) {
	for i := 0; i < 128; i++ {
		conn, addr, err := m.allocatePacketConn("udp4", 0)
		if err != nil {
			return 0, err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		err = conn.Close()
		if err != nil {
			return 0, err
		}

		if !ok {
			return 0, errFailedToCastUDPAddr
		}
		if udpAddr.Port%2 == 0 {
			return udpAddr.Port, nil
		}
	}

	return 0, errFailedToAllocateEvenPort
}

// GrantPermission handles permission requests by calling the permission handler callback
// associated with the TURN server listener socket.
func (m *Manager) GrantPermission(sourceAddr net.Addr, peerIP net.IP) error {
	// No permission handler: open
	if m.permissionHandler == nil {
		return nil
	}

	if m.permissionHandler(sourceAddr, peerIP) {
		return nil
	}

	return errAdminProhibited
}

// CreateTCPConnection creates a new outbound TCP Connection and returns the Connection-ID
// if it succeeds.
func (m *Manager) CreateTCPConnection( // nolint: cyclop
	allocation *Allocation,
	peerAddress proto.PeerAddress,
) (proto.ConnectionID, error) {
	if len(peerAddress.IP) == 0 || peerAddress.Port == 0 {
		return 0, errInvalidPeerAddress
	}

	conn, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: peerAddress.IP, Port: peerAddress.Port}) // nolint: noctx
	if err != nil {
		m.log.Warnf("Failed to create TCP Connection: %v", err)

		return 0, ErrTCPConnectionTimeoutOrFailure
	}

	connectionID, err := m.addTCPConnection(allocation, conn)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			m.log.Warnf("Failed to close TCP connection after ConnectionID generation failed: %v", closeErr)
		}
	}

	return connectionID, err
}

func (m *Manager) addTCPConnection(allocation *Allocation, conn net.Conn) (proto.ConnectionID, error) { //nolint:cyclop
	rand64, err := randutil.CryptoUint64()
	if err != nil {
		return 0, err
	}

	connectionID := proto.ConnectionID(uint32(rand64 >> 32)) // nolint: gosec

	newConnAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return 0, ErrDupeTCPConnection
	}

	// The manager lock is held until the connection has been inserted so
	// ConnectionIDs stay globally unique across allocations. The allocation
	// lock is taken inside it; lock order is always manager then allocation.
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, a := range m.allocations {
		a.tcpConnectionsLock.Lock()
		_, exists := a.tcpConnections[connectionID]
		a.tcpConnectionsLock.Unlock()

		if exists {
			return 0, errFailedToGenerateConnectionID
		}
	}

	allocation.tcpConnectionsLock.Lock()
	defer allocation.tcpConnectionsLock.Unlock()

	// The allocation may have been closed between the call that produced
	// conn and this point (for example an inbound connection accepted while
	// a Refresh with lifetime 0 tears the allocation down). Refuse to add a
	// connection that would never be closed.
	if allocation.closed.Load() {
		return 0, errAllocationClosed
	}

	for _, tcpConn := range allocation.tcpConnections {
		tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return 0, ErrDupeTCPConnection
		} else if tcpAddr.IP.Equal(newConnAddr.IP) && tcpAddr.Port == newConnAddr.Port {
			return 0, ErrDupeTCPConnection
		}
	}

	tcpConn := &tcpConnection{Conn: conn}
	allocation.tcpConnections[connectionID] = tcpConn

	bindTimeout := m.tcpConnectionBindTimeout
	if bindTimeout == 0 {
		bindTimeout = defaultTCPConnectionBindTimeout
	}
	tcpConn.bindTimer = time.AfterFunc(bindTimeout, func() {
		if allocation.removeTCPConnectionIfUnbound(connectionID) {
			m.log.Warnf("Removed TCP Connection that was never bound %v %v", connectionID, allocation.fiveTuple)
		}
	})

	return connectionID, nil
}

// GetTCPConnection returns the TCP Connection for the given ConnectionID.
//
// A connection can only be bound once. A connection that is already bound or
// that belongs to another user is not returned.
func (m *Manager) GetTCPConnection(username string, connectionID proto.ConnectionID) net.Conn {
	m.lock.RLock()
	allocations := make([]*Allocation, 0, len(m.allocations))
	for _, a := range m.allocations {
		allocations = append(allocations, a)
	}
	m.lock.RUnlock()

	for _, a := range allocations {
		a.tcpConnectionsLock.Lock()
		tcpConn, ok := a.tcpConnections[connectionID]
		if !ok || a.username != username || tcpConn.isBound.Swap(true) {
			a.tcpConnectionsLock.Unlock()

			continue
		}

		if tcpConn.bindTimer != nil {
			tcpConn.bindTimer.Stop()
		}
		a.tcpConnectionsLock.Unlock()

		return tcpConn
	}

	return nil
}

// RemoveTCPConnection closes and removes the TCP Connection with the given
// ConnectionID from whichever allocation owns it.
func (m *Manager) RemoveTCPConnection(connectionID proto.ConnectionID) {
	m.lock.RLock()
	allocations := make([]*Allocation, 0, len(m.allocations))
	for _, a := range m.allocations {
		allocations = append(allocations, a)
	}
	m.lock.RUnlock()

	for _, a := range allocations {
		a.RemoveTCPConnection(connectionID)
	}
}
