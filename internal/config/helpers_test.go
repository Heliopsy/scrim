// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/heliopsy/scrim/internal/config"
)

// world is a registry plus an isolated filesystem and environment, so a
// test controls every source Build reads.
type world struct {
	t       *testing.T
	reg     *config.Registry
	dir     string
	sysDir  string
	environ []string
	flags   *pflag.FlagSet

	timeout   config.Key[time.Duration]
	level     config.Key[string]
	listen    config.Key[string]
	backend   config.Key[string]
	noProxy   config.Key[[]string]
	upstream  config.Key[map[string]string]
	unsafe    config.Key[bool]
	netfs     config.Key[bool]
	token     config.Key[config.SecretRef]
	infSec    config.Key[config.SecretRef]
	caKey     config.Key[config.SecretRef]
	workers   config.Key[int]
	ratio     config.Key[float64]
	notifiers config.Collection
}

func newWorld(t *testing.T) *world {
	t.Helper()
	r := config.NewRegistry()
	config.RegisterBuiltins(r)
	dir := t.TempDir()
	w := &world{
		t: t, reg: r, dir: dir, sysDir: filepath.Join(dir, "etc"),
		environ: []string{"HOME=" + filepath.Join(dir, "home")},
	}
	w.timeout = config.MustRegisterIn(r, config.Spec[time.Duration]{
		Key: "approvals.timeout", Default: 2 * time.Minute, Flag: true,
		Description: "How long an approval waits for a decision.",
	})
	w.level = config.MustRegisterIn(r, config.Spec[string]{
		Key: "log.level", Default: "info", Flag: true, Enum: []string{"debug", "info", "warn", "error"},
		Description: "Minimum level of log records.",
	})
	w.listen = config.MustRegisterIn(r, config.Spec[string]{
		Key: "proxy.listen", Default: "127.0.0.1:9790", Flag: true, RestartRequired: true,
		Description: "Address the LLM proxy listens on.",
	})
	w.backend = config.MustRegisterIn(r, config.Spec[string]{
		Key: "state.backend", Default: "sqlite", Enum: []string{"memory", "sqlite", "postgres"}, Flag: true,
		RestartRequired: true, Profiles: map[string]string{"ci": "memory", "k8s": "postgres"},
		Description: "Where scrim keeps its state.",
	})
	w.noProxy = config.MustRegisterIn(r, config.Spec[[]string]{
		Key: "proxy.no-proxy", Description: "Hosts reached without the proxy.",
	})
	w.upstream = config.MustRegisterIn(r, config.Spec[map[string]string]{
		Key: "proxy.upstream", Default: map[string]string{"anthropic": "https://api.anthropic.com"},
		Profiles:    map[string]map[string]string{"ci": {"openai": "http://127.0.0.1:9999"}},
		Description: "Upstream base URL per provider.",
	})
	w.unsafe = config.MustRegisterIn(r, config.Spec[bool]{
		Key: "redaction.allow-unredacted-on-error", Weakening: true, Flag: true,
		Description: "Forward a request unredacted when redaction fails.",
	})
	w.netfs = config.MustRegisterIn(r, config.Spec[bool]{
		Key: "state.sqlite.allow-network-filesystem", Weakening: true,
		Description: "Allow the SQLite database on a network filesystem.",
	})
	w.token = config.MustRegisterIn(r, config.Spec[config.SecretRef]{
		Key: "stores.openbao.token", RequireReference: true,
		Description: "Token scrim uses to read OpenBao.",
	})
	w.infSec = config.MustRegisterIn(r, config.Spec[config.SecretRef]{
		Key: "stores.infisical.client-secret", Description: "Infisical machine identity secret.",
	})
	w.caKey = config.MustRegisterIn(r, config.Spec[config.SecretRef]{
		Key: "interception.ca-key", RestartRequired: true, Description: "CA private key.",
	})
	w.workers = config.MustRegisterIn(r, config.Spec[int]{
		Key: "proxy.workers", Default: 4, Description: "Worker count.",
		Validate: func(n int) error {
			if n < 1 {
				return errors.New("must be at least 1")
			}
			return nil
		},
	})
	w.ratio = config.MustRegisterIn(r, config.Spec[float64]{
		Key: "redaction.entropy-threshold", Default: 4.5, Description: "Entropy threshold.",
	})
	w.notifiers, _ = config.RegisterCollectionIn(r, config.CollectionSpec{
		Key: "notifiers", Description: "Approval notifiers by name.",
		SecretFields: []string{"token"}, RequiredFields: []string{"kind"},
		Validate: func(i config.Instance) error {
			if k := i.String("kind"); k != "slack" && k != "ntfy" {
				return fmt.Errorf("kind %q is not slack or ntfy", k)
			}
			return nil
		},
	})
	return w
}

// file writes a file under the world directory and returns its path.
func (w *world) file(rel, content string) string {
	w.t.Helper()
	p := filepath.Join(w.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *world) setenv(kv ...string) { w.environ = append(w.environ, kv...) }

func (w *world) parseFlags(args ...string) {
	w.t.Helper()
	w.flags = pflag.NewFlagSet("scrim", pflag.ContinueOnError)
	w.reg.BindFlags(w.flags)
	if err := w.flags.Parse(args); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) opts(paths ...string) config.Options {
	return config.Options{
		Registry: w.reg, ConfigPaths: paths, Environ: w.environ, Flags: w.flags, SystemDir: w.sysDir,
	}
}

func (w *world) build(paths ...string) *config.Config {
	w.t.Helper()
	c, err := config.Build(w.opts(paths...))
	if err != nil {
		w.t.Fatalf("Build: %v", err)
	}
	return c
}

func (w *world) buildErr(paths ...string) error {
	w.t.Helper()
	c, err := config.Build(w.opts(paths...))
	if err == nil {
		w.t.Fatalf("Build succeeded with %d settings, want an error", len(c.Entries()))
	}
	return err
}

const header = "apiVersion: scrim.dev/v1\nkind: Config\n"

func source(t *testing.T, c *config.Config, key string) string {
	t.Helper()
	e, ok := c.Entry(key)
	if !ok {
		t.Fatalf("no entry %s", key)
	}
	return e.Source.String()
}

func mustContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%q does not contain %q", s, sub)
		}
	}
}
