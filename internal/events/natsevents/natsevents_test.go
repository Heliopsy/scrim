// SPDX-License-Identifier: AGPL-3.0-only

package natsevents_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/events/eventstest"
	"github.com/heliopsy/scrim/internal/events/natsevents"
	"github.com/heliopsy/scrim/internal/natsconn"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

var natsSvc = podtest.NATS()

func TestMain(m *testing.M) {
	code := m.Run()
	natsSvc.Stop()
	os.Exit(code)
}

func natsURL(t *testing.T) string {
	a := natsSvc.Addr(t)
	if strings.Contains(a, "://") {
		return a
	}
	return "nats://" + a
}

// TestContractNATS runs the events contract against NATS core pub/sub;
// a cut replica loses its connection until it is restored.
func TestContractNATS(t *testing.T) {
	url := natsURL(t)
	eventstest.Run(t, eventstest.Harness{
		Backend: events.NATS,
		Replicas: func(t *testing.T, n int) []eventstest.Replica {
			subject := "scrim.test." + podtest.RandHex(4)
			out := make([]eventstest.Replica, n)
			for i, st := range eventstest.Shared(memstate.New(), n) {
				cut := &eventstest.Cutter{}
				nt := natsevents.New(natsconn.Options{Servers: []string{url}, Timeout: time.Second,
					Dialer: cut, ReconnectWait: 50 * time.Millisecond}, subject, nil)
				if err := events.OnLocalCommit(st, nt.Hint); err != nil {
					t.Fatal(err)
				}
				out[i] = eventstest.Replica{State: st, Notifier: nt, Interrupt: cut.Cut}
			}
			return out
		},
	})
}

func TestFactory(t *testing.T) {
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_EVENTS_BACKEND=nats"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := events.NotifierFor(cfg, memstate.New(), nil); err == nil || !strings.Contains(err.Error(), "nats.servers") {
		t.Fatalf("nats events without servers: %v", err)
	}
	cfg, err = config.Load(config.Default, config.EnvLayer([]string{"SCRIM_EVENTS_BACKEND=nats", "SCRIM_NATS_SERVERS=nats://127.0.0.1:1"}))
	if err != nil {
		t.Fatal(err)
	}
	n, err := events.NotifierFor(cfg, memstate.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := n.(*natsevents.Notifier); !ok {
		t.Fatalf("notifier is %T", n)
	}
}
