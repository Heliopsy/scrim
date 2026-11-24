// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// DetectorRule is one fallback pattern rule of the data plane.
type DetectorRule struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
}

//go:embed detectors.json
var detectorsJSON []byte

// DetectorRules lists the data plane's fallback pattern rules in the order it
// compiles them. The Rust redaction core checks the same file.
var DetectorRules = func() []DetectorRule {
	var f struct {
		Rules []DetectorRule `json:"rules"`
	}
	if err := json.Unmarshal(detectorsJSON, &f); err != nil || len(f.Rules) == 0 {
		panic("daemon: detectors.json is invalid")
	}
	return f.Rules
}()

func detectorNames(defaultOn bool, all bool) []string {
	var out []string
	for _, r := range DetectorRules {
		if all || r.Default == defaultOn {
			out = append(out, r.Name)
		}
	}
	return out
}

func knownDetectors(names []string) error {
	all := detectorNames(false, true)
	for _, n := range names {
		if !slices.Contains(all, n) {
			return fmt.Errorf("unknown detector %q (known: %s)", n, strings.Join(all, ", "))
		}
	}
	return nil
}

var (
	// DetectorsEnabled switches every fallback pattern rule.
	DetectorsEnabled = config.Register(config.Spec[bool]{
		Key:     "redaction.detectors.enabled",
		Default: true,
		Description: "Run the fallback pattern rules, which replace secrets in known formats (cloud keys, API tokens, " +
			"private keys, database URL passwords) that no store holds. false turns every rule off, whatever " +
			"redaction.detectors.enable names. Values your stores hold are redacted either way.",
	})
	// DetectorsDisable switches rules off by name.
	DetectorsDisable = config.Register(config.Spec[[]string]{
		Key: "redaction.detectors.disable",
		Description: "Fallback pattern rules to turn off, by name: " +
			strings.Join(detectorNames(true, false), ", ") + ".",
		Validate: knownDetectors,
	})
	// DetectorsEnable switches on rules that are off by default.
	DetectorsEnable = config.Register(config.Spec[[]string]{
		Key: "redaction.detectors.enable",
		Description: "Fallback pattern rules that are off by default to turn on, by name: " +
			strings.Join(detectorNames(false, false), ", ") + ". A rule may not be in both lists.",
		Validate: knownDetectors,
	})
)

// errDetectorBoth is returned when a rule is both enabled and disabled.
var errDetectorBoth = errors.New("redaction.detectors.enable and redaction.detectors.disable both name")

// detectorSettings adds the redaction.detectors.* settings to rs.
func detectorSettings(cfg *config.Config, rs *pb.RedactionSettings) error {
	dis, en := DetectorsDisable.Get(cfg), DetectorsEnable.Get(cfg)
	for _, n := range en {
		if slices.Contains(dis, n) {
			return fmt.Errorf("%w %q", errDetectorBoth, n)
		}
	}
	rs.DetectorsOff = !DetectorsEnabled.Get(cfg)
	rs.DetectorsDisabled = slices.Clone(dis)
	rs.DetectorsEnabled = slices.Clone(en)
	return nil
}
