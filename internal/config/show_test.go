// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

var padding = regexp.MustCompile(`  +`)

var update = flag.Bool("update", false, "rewrite golden files")

// golden compares got with testdata/name, or rewrites it under -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- fixed test path
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden file (run go test -update after checking):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// showWorld is a configuration touching every kind of source and setting.
func showWorld(t *testing.T) (*world, *config.Config) {
	t.Helper()
	w := newWorld(t)
	tokenFile := w.file("secrets/bao-token", seeded)
	w.file("etc/config.yaml", header+`approvals:
  timeout: 120s
proxy:
  upstream:
    openai: http://127.0.0.1:8001
  no-proxy: [localhost, 127.0.0.1]
stores:
  openbao:
    token: file:`+tokenFile+`
  infisical:
    client-secret: env:INF_SECRET
interception.ca-key: `+seeded+`
notifiers:
  ops-slack:
    kind: slack
    token: env:INF_SECRET
    retry: {attempts: 3}
include: conf.d
`)
	w.file("etc/conf.d/10-approvals.yaml", header+"approvals.timeout: 60s\n")
	w.setenv("INF_SECRET="+seeded, "SCRIM_PROXY_UPSTREAM_ANTHROPIC=http://127.0.0.1:9000",
		"SCRIM_LOG_LEVEL=warn", "SCRIM_STATE_SQLITE_ALLOW_NETWORK_FILESYSTEM=true", "SCRIM_PROFILE=ci")
	w.parseFlags("--log-level", "debug")
	return w, w.build()
}

func TestShowEffectiveGolden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the golden files hold Unix paths; TestShowEffectiveContract runs on Windows")
	}
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			w, c := showWorld(t)
			var out bytes.Buffer
			if err := config.WriteEffective(&out, c, config.ShowOptions{Format: format}); err != nil {
				t.Fatal(err)
			}
			// Temporary paths vary in length, which moves the table
			// columns; compare with runs of padding collapsed.
			got := strings.ReplaceAll(out.String(), w.dir, "$DIR")
			if format == "text" {
				got = padding.ReplaceAllString(got, "  ")
			}
			assertNoSeed(t, "show --effective", got)
			golden(t, "effective."+format, []byte(got))
		})
	}
}

func TestShowEffectiveContract(t *testing.T) {
	_, c := showWorld(t)
	var out bytes.Buffer
	if err := config.WriteEffective(&out, c, config.ShowOptions{Format: "text"}); err != nil {
		t.Fatal(err)
	}
	s := padding.ReplaceAllString(out.String(), "  ")
	if runtime.GOOS == "windows" {
		s = strings.ReplaceAll(s, `\`, "/")
	}
	mustContain(t, s,
		"stores.infisical.client-secret  [scrim:redacted] (env:INF_SECRET)",
		"interception.ca-key  [scrim:redacted] (<literal>)",
		"conf.d/10-approvals.yaml:3",
		"flag:--log-level",
		"proxy.upstream.anthropic",
		"env:SCRIM_PROXY_UPSTREAM_ANTHROPIC",
		"profile:ci",
		"WEAKENED",
	)
	if err := config.WriteEffective(&out, c, config.ShowOptions{Format: "yaml"}); err == nil {
		t.Fatal("unknown format accepted")
	}
}
