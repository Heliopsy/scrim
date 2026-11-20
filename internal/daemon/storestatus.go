// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"strings"

	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
)

// watchFirstLoads stops the daemon when a store's first load finds a redact
// target that matches nothing (specs/secret-stores "Empty redact targets
// refuse start-up"). An unreachable store does not stop it: redaction stays
// not ready and provider requests are refused until the store answers.
func (d *Daemon) watchFirstLoads(ctx context.Context) {
	for _, r := range d.app.Refreshers {
		d.goRun("store "+r.Store(), func() error {
			err := r.FirstLoad(ctx)
			if errors.Is(err, refresh.ErrEmptyTarget) {
				return err
			}
			return nil
		})
	}
}

// storeStatus reports every store's freshness and the values each of its
// redact targets holds. Names, counts and times only.
func (d *Daemon) storeStatus() []status.Store {
	kinds := map[string]string{}
	for _, inst := range storeconfig.Collection.Get(d.app.Config.Current()) {
		if k, ok := inst.Fields[storeconfig.FieldKind].(string); ok {
			kinds[inst.Name] = k
		}
	}
	out := make([]status.Store, 0, len(d.app.Refreshers))
	for _, r := range d.app.Refreshers {
		st := r.Status()
		s := status.Store{
			Name: st.Store, Kind: kinds[st.Store], Reachable: st.State != refresh.StateUnavailable,
			LastRefresh: st.LastSuccess, Values: st.Values, Degraded: st.State != refresh.StateReady,
			Reason: st.LastError, Targets: []status.StoreTarget{},
		}
		if s.Degraded && s.Reason == "" {
			s.Reason = string(st.State)
		}
		for _, t := range st.Targets {
			s.Targets = append(s.Targets, status.StoreTarget{Target: t.Target, Values: t.Values})
		}
		out = append(out, s)
	}
	return out
}

// emptyTargets names every redact target holding no value.
func emptyTargets(ss []status.Store) []string {
	var out []string
	for _, s := range ss {
		for _, t := range s.Targets {
			if t.Values == 0 {
				out = append(out, t.Target)
			}
		}
	}
	return out
}

func redactionDetail(dpUp bool, empty []string) string {
	switch {
	case !dpUp:
		return "data plane not ready: provider traffic is refused"
	case len(empty) > 0:
		return "redact target " + strings.Join(empty, ", ") + " holds 0 values: those secrets are not protected"
	}
	return "every provider request is redacted and checked by the guard"
}
