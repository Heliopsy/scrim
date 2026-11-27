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
	"github.com/heliopsy/scrim/internal/status"
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

// Encoded and entropy detection, both opt-in (docs/configuration.md gives
// the cost and false-positive measurements behind the defaults).
var (
	// DetectorsEncoded runs the pattern rules over decoded base64, hex and
	// percent-encoded text.
	DetectorsEncoded = config.Register(config.Spec[bool]{
		Key: "redaction.detectors.encoded",
		Description: "Also run the fallback pattern rules over the decoded form of base64 runs, hex runs and percent-encoded text " +
			"(a token in a Kubernetes secret, a base64 .env file, an escaped query string) and replace the characters that encode a match. " +
			"Off by default: it costs about 0.5 ms per MB of request on one core, a third of the redactor's throughput.",
	})
	// EntropyEnabled turns the entropy detector on.
	EntropyEnabled = config.Register(config.Spec[bool]{
		Key: "redaction.detectors.entropy.enabled",
		Description: "Replace high-entropy values that no store holds and no pattern rule knows, such as random passwords and API keys " +
			"without a prefix. With the default key-name context only values assigned to a key name that says secret " +
			"(token, secret, password, api_key, a name ending in key or auth, Bearer) are looked at. Off by default: " +
			"pagination cursors, nonces and test values that look random would become placeholders the agent cannot send back.",
	})
	// EntropyContext chooses which tokens the entropy detector looks at.
	EntropyContext = config.Register(config.Spec[string]{
		Key:     "redaction.detectors.entropy.context",
		Default: "key-name",
		Enum:    []string{"key-name", "any"},
		Description: "Which tokens the entropy detector looks at: key-name, values after a key name that says secret; any, every token " +
			"(hashes and base64 data trip it, so it needs a longer and more random token).",
	})
	// EntropyThreshold is the minimum Shannon entropy.
	EntropyThreshold = config.Register(config.Spec[float64]{
		Key:         "redaction.detectors.entropy.threshold",
		Description: "Minimum Shannon entropy of a value, in bits per byte. 0 takes the context's default: 3.5 for key-name, 4.3 for any.",
		Validate: func(v float64) error {
			if v < 0 || v > 8 {
				return errors.New("must be between 0 and 8")
			}
			return nil
		},
	})
	// EntropyMinLength is the shortest value considered.
	EntropyMinLength = config.Register(config.Spec[int]{
		Key:         "redaction.detectors.entropy.min-length",
		Description: "Shortest value the entropy detector considers, in bytes, at least 8. 0 takes the context's default: 16 for key-name, 32 for any.",
		Validate: func(n int) error {
			if n != 0 && (n < 8 || n > 1024) {
				return errors.New("must be 0 or between 8 and 1024")
			}
			return nil
		},
	})
	// EntropyMinClasses is how many character classes a value mixes.
	EntropyMinClasses = config.Register(config.Spec[int]{
		Key: "redaction.detectors.entropy.min-classes",
		Description: "How many character classes a value must mix: lower case, upper case, digits and, with the key-name context, " +
			"symbols. 0 takes the default, 3.",
		Validate: func(n int) error {
			if n < 0 || n > 4 {
				return errors.New("must be between 0 and 4")
			}
			return nil
		},
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
	rs.DetectorsEncoded = DetectorsEncoded.Get(cfg)
	if EntropyEnabled.Get(cfg) {
		rs.Entropy = &pb.EntropySettings{
			Enabled:       true,
			ThresholdBits: EntropyThreshold.Get(cfg),
			MinLength:     uint32(EntropyMinLength.Get(cfg)),  //nolint:gosec // validated to 0..1024
			MinClasses:    uint32(EntropyMinClasses.Get(cfg)), //nolint:gosec // validated to 0..4
			AnyContext:    EntropyContext.Get(cfg) == "any",
		}
	}
	return nil
}

// detectorProtection is the fallback detectors line of `scrim status` and
// `scrim doctor`: which rules run and whether encoded forms and entropy
// are on.
func detectorProtection(cfg *config.Config) status.Protection {
	on := DetectorsEnabled.Get(cfg)
	if !on {
		return status.Protection{Name: "fallback detectors", Active: false,
			Detail: "redaction.detectors.enabled is false: secrets in no store are not detected by format"}
	}
	dis, en := DetectorsDisable.Get(cfg), DetectorsEnable.Get(cfg)
	n := 0
	for _, r := range DetectorRules {
		if !slices.Contains(dis, r.Name) && (r.Default || slices.Contains(en, r.Name)) {
			n++
		}
	}
	d := fmt.Sprintf("%d of %d pattern rules", n, len(DetectorRules))
	if DetectorsEncoded.Get(cfg) {
		d += "; encoded forms (base64, hex, percent) on"
	} else {
		d += "; encoded forms off (redaction.detectors.encoded)"
	}
	if EntropyEnabled.Get(cfg) {
		d += "; entropy on (" + EntropyContext.Get(cfg) + " context)"
	} else {
		d += "; entropy off (redaction.detectors.entropy.enabled)"
	}
	return status.Protection{Name: "fallback detectors", Active: true, Detail: d}
}

// DetectorFinding is detectorProtection as a `scrim doctor` finding.
func DetectorFinding(cfg *config.Config) status.Finding {
	p := detectorProtection(cfg)
	if !p.Active {
		return status.Finding{Outcome: status.Warn, Message: p.Detail,
			Fix: "set redaction.detectors.enabled: true, or point a store at every secret the agent can reach"}
	}
	return status.Finding{Outcome: status.Pass, Message: "fallback detectors: " + p.Detail}
}
