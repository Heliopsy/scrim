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

// GuardTransform is one optional transform decoder of the data plane's guard.
type GuardTransform struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
}

//go:embed guard_transforms.json
var guardTransformsJSON []byte

// GuardTransforms lists the guard's optional transform decoders. The Rust
// redaction core checks the same file.
var GuardTransforms = func() []GuardTransform {
	var f struct {
		Transforms []GuardTransform `json:"transforms"`
	}
	if err := json.Unmarshal(guardTransformsJSON, &f); err != nil || len(f.Transforms) == 0 {
		panic("daemon: guard_transforms.json is invalid")
	}
	return f.Transforms
}()

func transformNames(defaultOn bool) []string {
	var out []string
	for _, t := range GuardTransforms {
		if t.Default == defaultOn {
			out = append(out, t.Name)
		}
	}
	return out
}

func knownTransforms(names []string) error {
	var all []string
	for _, t := range GuardTransforms {
		all = append(all, t.Name)
	}
	for _, n := range names {
		if !slices.Contains(all, n) {
			return fmt.Errorf("unknown guard transform %q (known: %s)", n, strings.Join(all, ", "))
		}
	}
	return nil
}

var (
	// GuardDisable switches guard transform decoders off by name.
	GuardDisable = config.Register(config.Spec[[]string]{
		Key: "redaction.guard.disable",
		Description: "Guard transform decoders to turn off, by name: " + strings.Join(transformNames(true), ", ") +
			". confusables reads look-alike Unicode, tag and invisible characters as ASCII, spelled-out reads values written as " +
			"NATO, digit and symbol words, split-fragments joins short fragments of a value spread over one request. " +
			"Turning one off lets that form of a value through.",
		Validate:  knownTransforms,
		Weakening: true,
	})
	// GuardEnable switches on guard transform decoders that are off by default.
	GuardEnable = config.Register(config.Spec[[]string]{
		Key: "redaction.guard.enable",
		Description: "Guard transform decoders that are off by default to turn on, by name: " + strings.Join(transformNames(false), ", ") +
			". base85 indexes the Ascii85, Z85 and RFC 1924 base85 forms of each value; it costs nothing per request with a " +
			"thousand values and a third more guard time with ten thousand. compressed inflates gzip, zlib, zstd, brotli and raw " +
			"deflate streams in base64 runs (64 MiB per request at most) and checks their text; it adds about a third to the " +
			"guard's time on a request with base64 data. A name may not be in both lists.",
		Validate: knownTransforms,
	})
)

// errGuardBoth is returned when a transform is both enabled and disabled.
var errGuardBoth = errors.New("redaction.guard.enable and redaction.guard.disable both name")

// guardSettings adds the redaction.guard.* settings to rs.
func guardSettings(cfg *config.Config, rs *pb.RedactionSettings) error {
	dis, en := GuardDisable.Get(cfg), GuardEnable.Get(cfg)
	for _, n := range en {
		if slices.Contains(dis, n) {
			return fmt.Errorf("%w %q", errGuardBoth, n)
		}
	}
	rs.GuardDisabled = slices.Clone(dis)
	rs.GuardEnabled = slices.Clone(en)
	return nil
}

// guardTransformsOn lists which transforms are on and off under cfg.
func guardTransformsOn(cfg *config.Config) (on, off []string) {
	dis, en := GuardDisable.Get(cfg), GuardEnable.Get(cfg)
	for _, t := range GuardTransforms {
		if !slices.Contains(dis, t.Name) && (t.Default || slices.Contains(en, t.Name)) {
			on = append(on, t.Name)
		} else {
			off = append(off, t.Name)
		}
	}
	return on, off
}

// guardProtection is the guard transforms line of `scrim status`.
func guardProtection(cfg *config.Config) status.Protection {
	on, off := guardTransformsOn(cfg)
	d := "on: " + orNone(on) + "; off: " + orNone(off)
	return status.Protection{Name: "guard transforms", Active: len(on) > 0, Detail: d}
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "none"
	}
	return strings.Join(v, ", ")
}

// GuardTransformFinding is the guard transforms as a `scrim doctor` finding:
// a warning when a transform that is on by default is off.
func GuardTransformFinding(cfg *config.Config) status.Finding {
	p := guardProtection(cfg)
	if dis := GuardDisable.Get(cfg); len(dis) > 0 {
		return status.Finding{Outcome: status.Warn,
			Message: "guard transforms turned off (redaction.guard.disable): " + strings.Join(dis, ", ") + "; " + p.Detail,
			Fix:     "unset redaction.guard.disable unless you accept those forms of a value reaching the provider"}
	}
	return status.Finding{Outcome: status.Pass, Message: "guard transforms " + p.Detail}
}
