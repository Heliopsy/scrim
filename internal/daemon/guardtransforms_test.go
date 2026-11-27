// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/status"
)

// The guard transform lists reach the snapshot, are validated, show in
// status and doctor, and turning a default one off is a weakening.
func TestGuardTransformSettings(t *testing.T) {
	s, err := detectorSnapshot(t, "").Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := s.GetRedaction(); len(r.GetGuardDisabled()) != 0 || len(r.GetGuardEnabled()) != 0 {
		t.Fatalf("defaults: %v", r)
	}
	def := buildConfig(t, "")
	if p := guardProtection(def); !p.Active || p.Detail != "on: confusables, spelled-out, split-fragments, cross-request; off: base85, compressed" {
		t.Fatalf("default protection: %+v", p)
	}
	if f := GuardTransformFinding(def); f.Outcome != status.Pass {
		t.Fatalf("default doctor: %+v", f)
	}
	body := "redaction:\n  guard:\n    disable: [spelled-out]\n    enable: [compressed]\n"
	s, err = detectorSnapshot(t, body).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := s.GetRedaction()
	if strings.Join(r.GetGuardDisabled(), ",") != "spelled-out" || strings.Join(r.GetGuardEnabled(), ",") != "compressed" {
		t.Fatalf("settings: %v", r)
	}
	cfg := buildConfig(t, body)
	if p := guardProtection(cfg); p.Detail != "on: confusables, compressed, split-fragments, cross-request; off: base85, spelled-out" {
		t.Fatalf("protection: %+v", p)
	}
	if f := GuardTransformFinding(cfg); f.Outcome != status.Warn || !strings.Contains(f.Message, "spelled-out") {
		t.Fatalf("doctor: %+v", f)
	}
	weak := false
	for _, w := range cfg.Weakened() {
		weak = weak || w.Setting.Key == "redaction.guard.disable"
	}
	if !weak {
		t.Fatal("redaction.guard.disable is not reported as weakening")
	}
	if _, err := detectorSnapshot(t, "redaction:\n  guard:\n    disable: [spelled-out]\n    enable: [spelled-out]\n").Build(context.Background()); !errors.Is(err, errGuardBoth) {
		t.Fatalf("a transform in both lists built: %v", err)
	}
	if err := knownTransforms([]string{"rot26"}); err == nil {
		t.Fatal("unknown transform accepted")
	}
}
