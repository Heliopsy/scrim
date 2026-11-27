// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

func detectorSnapshot(t *testing.T, body string) *SnapshotBuilder {
	t.Helper()
	cfg := buildConfig(t, body)
	b := &SnapshotBuilder{Config: func() *config.Config { return cfg }}
	b.SetKeys(testRing(t))
	return b
}

func TestDetectorSettingsReachTheSnapshot(t *testing.T) {
	b := detectorSnapshot(t, "")
	s, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := s.GetRedaction(); r.GetDetectorsOff() || len(r.GetDetectorsDisabled()) != 0 || len(r.GetDetectorsEnabled()) != 0 {
		t.Fatalf("defaults: %v", r)
	}
	b = detectorSnapshot(t, `redaction:
  detectors:
    enabled: false
    disable: [slack-webhook-url, jwt]
    enable: [generic-secret-assignment]
`)
	s, err = b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := s.GetRedaction()
	if !r.GetDetectorsOff() || strings.Join(r.GetDetectorsDisabled(), ",") != "slack-webhook-url,jwt" ||
		strings.Join(r.GetDetectorsEnabled(), ",") != "generic-secret-assignment" {
		t.Fatalf("settings: %v", r)
	}
}

func TestDetectorSettingsAreValidated(t *testing.T) {
	b := detectorSnapshot(t, `redaction:
  detectors:
    disable: [jwt]
    enable: [jwt]
`)
	if _, err := b.Build(context.Background()); !errors.Is(err, errDetectorBoth) {
		t.Fatalf("a rule in both lists built: %v", err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := "apiVersion: " + config.APIVersion + "\nkind: Config\nredaction:\n  detectors:\n    disable: [no-such-rule]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{p}, Environ: []string{}}); err == nil ||
		!strings.Contains(err.Error(), "no-such-rule") {
		t.Fatalf("unknown rule accepted: %v", err)
	}
}

// The rule list is shared with the data plane, which checks the same file
// (scrim-redact's tests/detectors.rs).
func TestDetectorRuleList(t *testing.T) {
	names := detectorNames(false, true)
	if len(names) < 35 || !slices.Contains(names, "private-key") {
		t.Fatalf("rules: %v", names)
	}
	if off := detectorNames(false, false); strings.Join(off, ",") != "generic-secret-assignment" {
		t.Fatalf("off by default: %v", off)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("duplicate rule %s", n)
		}
		seen[n] = true
	}
}

// Encoded forms and entropy are opt-in; their settings reach the snapshot
// and show in the status line and the doctor finding.
func TestEncodedAndEntropySettings(t *testing.T) {
	b := detectorSnapshot(t, "")
	s, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := s.GetRedaction(); r.GetDetectorsEncoded() || r.GetEntropy() != nil {
		t.Fatalf("defaults: %v", r)
	}
	def := buildConfig(t, "")
	if p := detectorProtection(def); !p.Active || !strings.Contains(p.Detail, "encoded forms off") ||
		!strings.Contains(p.Detail, "entropy off") || !strings.HasPrefix(p.Detail, fmt.Sprintf("%d of %d pattern rules", len(DetectorRules)-1, len(DetectorRules))) {
		t.Fatalf("default protection: %+v", p)
	}
	body := `redaction:
  detectors:
    encoded: true
    entropy:
      enabled: true
      context: any
      threshold: 4.5
      min-length: 40
      min-classes: 2
`
	b = detectorSnapshot(t, body)
	s, err = b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := s.GetRedaction()
	e := r.GetEntropy()
	if !r.GetDetectorsEncoded() || !e.GetEnabled() || !e.GetAnyContext() || e.GetThresholdBits() != 4.5 ||
		e.GetMinLength() != 40 || e.GetMinClasses() != 2 {
		t.Fatalf("settings: %v", r)
	}
	cfg := buildConfig(t, body)
	if p := detectorProtection(cfg); !strings.Contains(p.Detail, "encoded forms (base64, hex, percent) on") ||
		!strings.Contains(p.Detail, "entropy on (any context)") {
		t.Fatalf("protection: %+v", p)
	}
	off := buildConfig(t, "redaction:\n  detectors:\n    enabled: false\n")
	if p := detectorProtection(off); p.Active {
		t.Fatalf("detectors off reported active: %+v", p)
	}
	if f := DetectorFinding(off); f.Outcome != "warn" {
		t.Fatalf("doctor: %+v", f)
	}
	for _, bad := range []string{"min-length: 4", "threshold: 9", "min-classes: 5", "context: words"} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		y := "apiVersion: " + config.APIVersion + "\nkind: Config\nredaction:\n  detectors:\n    entropy:\n      " + bad + "\n"
		if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{p}, Environ: []string{}}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
