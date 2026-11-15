// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import (
	"testing"

	"github.com/pion/stun/v4"
)

func TestMobilityTicket(t *testing.T) {
	t.Run("AddTo", func(t *testing.T) {
		m := new(stun.Message)
		ticket := MobilityTicket([]byte("opaque-ticket"))
		if err := ticket.AddTo(m); err != nil {
			t.Fatal(err)
		}
		m.WriteHeader()

		t.Run("GetFrom", func(t *testing.T) {
			decoded := new(stun.Message)
			decoded.Raw = m.Raw
			if err := decoded.Decode(); err != nil {
				t.Fatal(err)
			}
			var got MobilityTicket
			if err := got.GetFrom(decoded); err != nil {
				t.Fatal(err)
			}
			if string(got) != string(ticket) {
				t.Fatalf("expected %q, got %q", ticket, got)
			}
		})
	})

	t.Run("Empty", func(t *testing.T) {
		m := new(stun.Message)
		if err := (MobilityTicket{}).AddTo(m); err != nil {
			t.Fatal(err)
		}
		m.WriteHeader()

		decoded := new(stun.Message)
		decoded.Raw = m.Raw
		if err := decoded.Decode(); err != nil {
			t.Fatal(err)
		}
		var got MobilityTicket
		if err := got.GetFrom(decoded); err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty ticket, got %v", got)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		m := new(stun.Message)
		m.WriteHeader()
		var got MobilityTicket
		if err := got.GetFrom(m); err == nil {
			t.Fatal("expected error for missing attribute")
		}
	})
}
