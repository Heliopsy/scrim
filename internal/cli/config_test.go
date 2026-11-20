// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

// The committed schema and settings reference are generated from the
// registry of the real binary (every package cli links in). This test is the
// CI check that they never drift: run `just config-docs` after changing a
// setting.
func TestGeneratedConfigArtifactsUpToDate(t *testing.T) {
	root := filepath.Join("..", "..")
	schema, err := config.Schema(config.Default)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join(root, "schema", "config-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(schema, committed) {
		t.Error("schema/config-v1.json is out of date: run `just config-docs`")
	}

	docPath := filepath.Join(root, "docs", "configuration.md")
	doc, err := os.ReadFile(docPath) // #nosec G304 -- fixed path in the repository
	if err != nil {
		t.Fatal(err)
	}
	want, err := config.SpliceReference(doc, config.Reference(config.Default))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(doc, want) {
		t.Error("docs/configuration.md settings reference is out of date: run `just config-docs`")
	}
	for _, s := range config.Default.Settings() {
		if !bytes.Contains(doc, []byte("#### `"+s.Key+"`")) {
			t.Errorf("setting %s is not documented", s.Key)
		}
	}
}

// Every weakening setting compiled into scrim defaults to its safe value,
// is warned about at start-up when changed, and is listed for status.
func TestEveryWeakeningSettingIsReported(t *testing.T) {
	var found int
	for _, s := range config.Default.Settings() {
		if !s.Weakening {
			continue
		}
		found++
		t.Run(s.Key, func(t *testing.T) {
			base, err := config.Build(config.Options{Registry: config.Default, Environ: []string{}, SystemDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			if len(base.Weakened()) != 0 {
				t.Fatalf("weakened by default: %v", config.WeakenedSettings(base))
			}
			val := weakValue(t, s)
			var logs bytes.Buffer
			m, err := config.NewManager(config.Options{
				Registry: config.Default, Environ: []string{s.EnvVar() + "=" + val}, SystemDir: t.TempDir(),
			}, slog.New(slog.NewTextHandler(&logs, nil)))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(logs.String(), "weakened protection active") || !strings.Contains(logs.String(), s.Key) {
				t.Fatalf("no start-up warning: %s", logs.String())
			}
			st := m.Status()
			if len(st.Weakened) != 1 || st.Weakened[0].Key != s.Key {
				t.Fatalf("status weakened = %+v", st.Weakened)
			}
		})
	}
	if found == 0 {
		t.Skip("no weakening settings registered yet")
	}
}

// weakValue returns a value different from the safe default.
func weakValue(t *testing.T, s *config.Setting) string {
	t.Helper()
	switch s.Kind {
	case config.KindBool:
		return "true"
	case config.KindString:
		for _, v := range s.Enum {
			if v != s.Default {
				return v
			}
		}
	case config.KindInt:
		return "999999"
	case config.KindDuration:
		return "999h"
	case config.KindFloat, config.KindList, config.KindMap, config.KindSecretRef:
	}
	t.Skipf("no generic weakened value for %s (%s); cover it in its package", s.Key, s.Kind)
	return ""
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: scrim.dev/v1\nkind: Config\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigValidate(t *testing.T) {
	p := writeConfig(t, "log:\n  level: debug\n")
	e, out, _ := newEnv()
	if code := Run(context.Background(), e, []string{"config", "validate", "--config", p}); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out.String(), "configuration is valid") || !strings.Contains(out.String(), p) {
		t.Fatalf("output %q", out)
	}

	bad := writeConfig(t, "log:\n  level: loud\naprovals.timeout: 60s\n")
	e, out, errb := newEnv("SCRIM_LOG_FORMAT=xml")
	if code := Run(context.Background(), e, []string{"config", "validate", "--config", bad}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	for _, want := range []string{"log.level (file:" + bad + ":4)", "aprovals.timeout", "log.format (env:SCRIM_LOG_FORMAT)", "invalid: 3 problem"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errb.String(), "configuration is invalid") {
		t.Errorf("stderr %q", errb)
	}

	e, out, _ = newEnv()
	Run(context.Background(), e, []string{"config", "validate", "--config", bad, "-o", "json"})
	var rep validationReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Valid || len(rep.Problems) != 2 || rep.Problems[0].Source == "" {
		t.Fatalf("report = %+v", rep)
	}

	e, _, _ = newEnv("SCRIM_CONFIG=/nonexistent.yaml")
	if code := Run(context.Background(), e, []string{"config", "validate"}); code != 1 {
		t.Fatalf("missing explicit file: exit %d", code)
	}
}

func TestConfigShow(t *testing.T) {
	p := writeConfig(t, "log:\n  level: warn\n")
	e, out, _ := newEnv("SCRIM_LOG_FORMAT=json")
	if code := Run(context.Background(), e, []string{"config", "show", "--config", p, "--log-level", "debug"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	for _, want := range []string{"log.level", "flag:--log-level", "log.format", "env:SCRIM_LOG_FORMAT"} {
		if !strings.Contains(s, want) {
			t.Errorf("show lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "policy.default") {
		t.Error("show without --effective lists defaults")
	}

	e, out, _ = newEnv()
	if code := Run(context.Background(), e, []string{"config", "show", "--effective", "-o", "json"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Settings []config.EffectiveEntry `json:"settings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Settings) != len(config.Default.Settings()) {
		t.Fatalf("effective lists %d settings, registry has %d", len(doc.Settings), len(config.Default.Settings()))
	}
}

func TestConfigSchemaAndDocs(t *testing.T) {
	e, out, _ := newEnv()
	if code := Run(context.Background(), e, []string{"config", "schema"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), config.APIVersion) {
		t.Fatal("schema output is not the JSON Schema")
	}
	e, out, _ = newEnv()
	if code := Run(context.Background(), e, []string{"config", "docs"}); code != 0 || !strings.Contains(out.String(), "#### `log.level`") {
		t.Fatalf("docs: exit %d", code)
	}
}
