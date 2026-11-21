// SPDX-License-Identifier: AGPL-3.0-only

package events_test

import (
	"testing"

	"github.com/heliopsy/scrim/internal/events/eventstest"
	"github.com/heliopsy/scrim/internal/state/memstate"
)

// TestContractMemory runs the events contract against the in-memory
// reference backend.
func TestContractMemory(t *testing.T) {
	eventstest.Run(t, eventstest.Harness{
		Backend: "memory",
		Replicas: func(t *testing.T, n int) []eventstest.Replica {
			hub := eventstest.NewHub()
			out := make([]eventstest.Replica, n)
			for i, st := range eventstest.Shared(memstate.New(), n) {
				hn := hub.Notifier(st)
				out[i] = eventstest.Replica{State: st, Notifier: hn, Interrupt: hn.Interrupt}
			}
			return out
		},
	})
}
