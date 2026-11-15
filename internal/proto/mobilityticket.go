// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import "github.com/pion/stun/v4"

// AttrMobilityTicket is the MOBILITY-TICKET attribute type (0x8030),
// a comprehension-optional attribute defined by RFC 8016 Section 3.
const AttrMobilityTicket stun.AttrType = 0x8030

// MobilityTicket represents the MOBILITY-TICKET attribute.
//
// The MOBILITY-TICKET attribute carries an opaque ticket that the server
// issues to the client and that the client later presents to prove that it
// is the same client, after its transport address changed. The client
// includes an empty MOBILITY-TICKET attribute in the Allocate request to
// indicate that it supports mobility; the server returns the ticket in the
// Allocate (and mobility Refresh) success response, and the client sends
// the ticket back in a Refresh request when its 5-tuple changes.
//
// RFC 8016 Section 3.
type MobilityTicket []byte

// AddTo adds MOBILITY-TICKET to message.
func (t MobilityTicket) AddTo(m *stun.Message) error {
	m.Add(AttrMobilityTicket, t)

	return nil
}

// GetFrom decodes MOBILITY-TICKET from message.
func (t *MobilityTicket) GetFrom(m *stun.Message) error {
	v, err := m.Get(AttrMobilityTicket)
	if err != nil {
		return err
	}
	*t = v

	return nil
}
