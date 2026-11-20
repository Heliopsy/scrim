// SPDX-License-Identifier: AGPL-3.0-only

package memstate_test

import (
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/state/statetest"
)

func TestContract(t *testing.T) {
	statetest.Run(t, func(*testing.T) state.Store { return memstate.New() })
}

func TestOpenByName(t *testing.T) {
	s, err := state.Open(t.Context(), config.MustLoadDefaults(config.Default))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if s.Backend() != memstate.Name {
		t.Fatalf("backend = %s", s.Backend())
	}
}
