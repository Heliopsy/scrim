// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v4"

	"github.com/heliopsy/scrim/internal/config"
)

// RulesFile names the rules file.
var RulesFile = config.Register(config.Spec[string]{
	Key:         "policy.rules-file",
	Default:     "",
	Description: "Path of the policy rules file (YAML or JSON with default and rules). Empty means no rules: every request gets policy.default.",
	Flag:        true,
})

// maxRulesFile bounds the rules file size.
const maxRulesFile = 4 << 20

// LoadFile reads a rules file. YAML and JSON are accepted; unknown keys are
// an error, so a misspelt `when` cannot silently widen a rule.
func LoadFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("policy: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxRulesFile+1))
	if err != nil {
		return Config{}, fmt.Errorf("policy: reading %s: %w", path, err)
	}
	if len(data) > maxRulesFile {
		return Config{}, fmt.Errorf("policy: %s is larger than %d bytes", path, maxRulesFile)
	}
	return Parse(data, strings.EqualFold(filepath.Ext(path), ".json"))
}

// Parse decodes rules from YAML, or JSON when asJSON is set.
func Parse(data []byte, asJSON bool) (Config, error) {
	var c Config
	if asJSON {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return Config{}, fmt.Errorf("policy: %w", err)
		}
		return c, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("policy: %w", err)
	}
	return c, nil
}

// FromConfig loads the rules named by policy.rules-file, appends the built-in
// rules ([WithBuiltins]) and fills an empty default from policy.default.
func FromConfig(cfg *config.Config) (Config, error) {
	var c Config
	if p := RulesFile.Get(cfg); p != "" {
		var err error
		if c, err = LoadFile(p); err != nil {
			return Config{}, err
		}
	}
	if c.Default == "" {
		c.Default = DefaultEffect.Get(cfg)
	}
	return WithBuiltins(cfg, c)
}
