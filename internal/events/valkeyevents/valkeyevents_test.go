// SPDX-License-Identifier: AGPL-3.0-only

package valkeyevents_test

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/events/eventstest"
	"github.com/heliopsy/scrim/internal/events/valkeyevents"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/testing/podtest"
	"github.com/heliopsy/scrim/internal/valkeyconn"
)

var valkeySvc = podtest.Valkey()

func TestMain(m *testing.M) {
	code := m.Run()
	valkeySvc.Stop()
	os.Exit(code)
}

// TestContractValkey runs the events contract against Valkey pub/sub: each
// replica has its own client, and a cut replica loses every connection to
// Valkey (subscription and publishing) until it is restored.
func TestContractValkey(t *testing.T) {
	addr := valkeySvc.Addr(t)
	eventstest.Run(t, eventstest.Harness{
		Backend: events.Valkey,
		Replicas: func(t *testing.T, n int) []eventstest.Replica {
			channel := "scrim:test:" + podtest.RandHex(4)
			out := make([]eventstest.Replica, n)
			for i, st := range eventstest.Shared(memstate.New(), n) {
				cut := &eventstest.Cutter{}
				c, err := valkeyconn.New(valkeyconn.Options{Addresses: []string{addr}, Timeout: time.Second,
					ClientName: "scrim-events-test",
					Dial: func(ctx context.Context, a string, _ *net.Dialer, _ *tls.Config) (net.Conn, error) {
						return cut.DialContext(ctx, "tcp", a)
					}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				nt := valkeyevents.New(c, channel, nil)
				nt.Min, nt.SubscribeTimeout = 50*time.Millisecond, 2*time.Second
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
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_EVENTS_BACKEND=valkey"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := events.NotifierFor(cfg, memstate.New(), nil); err == nil || !strings.Contains(err.Error(), "valkey.addresses") {
		t.Fatalf("valkey events without addresses: %v", err)
	}
	addr := valkeySvc.Addr(t)
	cfg, err = config.Load(config.Default, config.EnvLayer([]string{"SCRIM_EVENTS_BACKEND=valkey", "SCRIM_VALKEY_ADDRESSES=" + addr}))
	if err != nil {
		t.Fatal(err)
	}
	n, err := events.NotifierFor(cfg, memstate.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := n.(*valkeyevents.Notifier); !ok {
		t.Fatalf("notifier is %T", n)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	upc := make(chan bool, 4)
	go func() { n.Run(ctx, func() {}, func(v bool) { upc <- v }); close(done) }()
	select {
	case v := <-upc:
		if !v {
			t.Fatal("first state reported is down")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("subscription never came up")
	}
	cancel()
	<-done
}
