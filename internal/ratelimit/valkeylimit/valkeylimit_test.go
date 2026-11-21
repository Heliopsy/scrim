// SPDX-License-Identifier: AGPL-3.0-only

package valkeylimit_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/ratelimit"
	"github.com/heliopsy/scrim/internal/ratelimit/ratelimittest"
	"github.com/heliopsy/scrim/internal/ratelimit/valkeylimit"
	"github.com/heliopsy/scrim/internal/testing/podtest"
	"github.com/heliopsy/scrim/internal/valkeyconn"
)

var valkeySvc = podtest.Valkey()

func TestMain(m *testing.M) {
	code := m.Run()
	valkeySvc.Stop()
	os.Exit(code)
}

// TestContractValkey: two clients, as two replicas, share one exact limit.
func TestContractValkey(t *testing.T) {
	addr := valkeySvc.Addr(t)
	ratelimittest.Run(t, ratelimittest.Harness{Shared: true, New: func(t *testing.T) (a, b ratelimit.Limiter) {
		mk := func() ratelimit.Limiter {
			c, err := valkeyconn.New(valkeyconn.Options{Addresses: []string{addr}, Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			return valkeylimit.New(c, "scrim:test:rl:")
		}
		return mk(), mk()
	}})
}

func TestFromConfigFailsClosed(t *testing.T) {
	addr := valkeySvc.Addr(t)
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_RATELIMIT_BACKEND=valkey", "SCRIM_VALKEY_ADDRESSES=" + addr}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ratelimit.FromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if s.Limiter.Backend() != "valkey" {
		t.Fatalf("backend %s", s.Limiter.Backend())
	}
	if err := s.Check(t.Context(), ratelimit.ClassAsks, "agent"); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(config.Default, config.EnvLayer([]string{"SCRIM_RATELIMIT_BACKEND=valkey"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ratelimit.FromConfig(cfg, nil); err == nil || !strings.Contains(err.Error(), "valkey.addresses") {
		t.Fatalf("valkey without addresses: %v", err)
	}
}
