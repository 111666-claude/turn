// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package allocation

import (
	"crypto/rand"
	"net"
	"time"
)

// mobilityTicketSize is the size in bytes of the opaque mobility tickets
// issued by the server. 256 bits of entropy makes tickets unguessable and
// therefore tamper-proof: a modified ticket simply does not exist in the
// server's ticket store.
const mobilityTicketSize = 32

// mobilityTicket is the server-side record of an issued MOBILITY-TICKET (RFC 8016).
type mobilityTicket struct {
	alloc     *Allocation
	userID    string
	expiresAt time.Time

	// consumed is set once the ticket has been presented in a mobility
	// Refresh. A consumed ticket can never migrate the allocation again, but
	// while it maps to the allocation's current 5-tuple it is answered
	// idempotently with its replacement, so that a retransmitted Refresh
	// (e.g. because the first success response was lost) still succeeds.
	consumed    bool
	replacement []byte
}

// MobilityEnabled reports whether RFC 8016 allocation mobility is enabled
// on this manager.
func (m *Manager) MobilityEnabled() bool {
	return m.mobilityTicketLifetime > 0
}

// CreateMobilityTicket issues a new mobility ticket bound to the given
// allocation and user. It returns ErrInvalidMobilityTicket-like errors only
// on internal failures; callers should treat the ticket as opaque.
func (m *Manager) CreateMobilityTicket(alloc *Allocation, userID string) ([]byte, error) {
	if !m.MobilityEnabled() {
		return nil, errMobilityDisabled
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	return m.newMobilityTicketLocked(alloc, userID)
}

func (m *Manager) newMobilityTicketLocked(alloc *Allocation, userID string) ([]byte, error) {
	ticket := make([]byte, mobilityTicketSize)
	if _, err := rand.Read(ticket); err != nil {
		return nil, err
	}

	m.mobilityTickets[string(ticket)] = &mobilityTicket{
		alloc:     alloc,
		userID:    userID,
		expiresAt: time.Now().Add(m.mobilityTicketLifetime),
	}

	return ticket, nil
}

// MigrateAllocation implements the server side of an RFC 8016 mobility event:
// the client presented a mobility ticket in an authenticated Refresh request
// arriving from a (usually new) 5-tuple. On success the allocation is moved to
// the new 5-tuple and a fresh ticket is returned for the next mobility event.
//
// All failure cases return ErrInvalidMobilityTicket so that a rejected ticket
// does not reveal anything about other allocations' relay state.
func (m *Manager) MigrateAllocation(
	ticket []byte,
	userID string,
	fiveTuple *FiveTuple,
	turnSocket net.PacketConn,
) (*Allocation, []byte, error) {
	if !m.MobilityEnabled() {
		return nil, nil, errMobilityDisabled
	}
	if len(ticket) == 0 || fiveTuple == nil {
		return nil, nil, ErrInvalidMobilityTicket
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	record, ok := m.mobilityTickets[string(ticket)]
	if !ok {
		return nil, nil, ErrInvalidMobilityTicket
	}
	if time.Now().After(record.expiresAt) {
		delete(m.mobilityTickets, string(ticket))

		return nil, nil, ErrInvalidMobilityTicket
	}

	alloc := record.alloc

	// A ticket is only ever valid for the user it was issued to. Rejecting
	// with the generic error prevents one user from probing or hijacking
	// another user's allocation.
	if alloc.userID != userID {
		return nil, nil, ErrInvalidMobilityTicket
	}

	if record.consumed {
		// The ticket was already used. Only answer idempotently (with the
		// same replacement ticket) when the request comes from the 5-tuple
		// the allocation was migrated to; anything else is a replay.
		if alloc.FiveTuple().Fingerprint() != fiveTuple.Fingerprint() {
			return nil, nil, ErrInvalidMobilityTicket
		}

		return alloc, record.replacement, nil
	}

	if alloc.FiveTuple().Fingerprint() == fiveTuple.Fingerprint() {
		// The 5-tuple did not change: nothing to migrate, the presented
		// ticket stays valid.
		return alloc, ticket, nil
	}

	if existing := m.allocations[fiveTuple.Fingerprint()]; existing != nil && existing != alloc {
		return nil, nil, errFiveTupleInUse
	}

	newTicket, err := m.newMobilityTicketLocked(alloc, userID)
	if err != nil {
		return nil, nil, err
	}

	record.consumed = true
	record.replacement = newTicket

	delete(m.allocations, alloc.FiveTuple().Fingerprint())
	alloc.setEndpoint(fiveTuple, turnSocket)
	m.allocations[fiveTuple.Fingerprint()] = alloc

	return alloc, newTicket, nil
}

// removeMobilityTicketsLocked drops every ticket issued for the allocation.
// The caller must hold m.lock.
func (m *Manager) removeMobilityTicketsLocked(alloc *Allocation) {
	for key, ticket := range m.mobilityTickets {
		if ticket.alloc == alloc {
			delete(m.mobilityTickets, key)
		}
	}
}
