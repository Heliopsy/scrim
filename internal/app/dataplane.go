// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"

	"github.com/heliopsy/scrim/internal/dataplane"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/obs"
)

// DataPlane returns a supervisor for the data plane configured by
// dataplane.*, with its readiness wired into Health. The caller runs it.
//
// The snapshot holds no values yet: the store refresher (group 6) and the
// policy compiler (group 7) fill SnapshotSource.
func (a *App) DataPlane() (*dataplane.Supervisor, error) {
	cfg := a.Config.Current()
	bin, err := dataplane.Resolve(dataplane.PathSetting.Get(cfg))
	if err != nil {
		return nil, err
	}
	s := &dataplane.Supervisor{
		Binary:       bin,
		Options:      dataplane.StartOptions{Mlock: dataplane.MlockSetting.Get(cfg)},
		Log:          obs.WithComponent(a.Log, "dataplane"),
		Snapshot:     a.SnapshotSource,
		StartTimeout: dataplane.StartTimeout.Get(cfg),
		MaxBackoff:   dataplane.MaxBackoff.Get(cfg),
	}
	if s.Snapshot == nil {
		s.Snapshot = emptySnapshot
	}
	a.Health.Ready("dataplane", s.Health)
	return s, nil
}

func emptySnapshot(context.Context) (*pb.Snapshot, error) {
	return &pb.Snapshot{Policy: &pb.Policy{DefaultEffect: pb.Effect_EFFECT_DENY}}, nil
}
