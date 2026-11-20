// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// TestPrecedenceTable checks every pair of layers: flag over environment
// over file over profile over default, with the reported source.
func TestPrecedenceTable(t *testing.T) {
	cases := []struct {
		name               string
		profile, file, env string
		flag               string
		want, wantSource   string
	}{
		{name: "default", want: "info", wantSource: "default"},
		{name: "file", file: "warn", want: "warn", wantSource: "file:"},
		{name: "env over file", file: "warn", env: "error", want: "error", wantSource: "env:SCRIM_LOG_LEVEL"},
		{name: "flag over env and file", file: "info", env: "warn", flag: "debug", want: "debug", wantSource: "flag:--log-level"},
		{name: "flag over file", file: "warn", flag: "debug", want: "debug", wantSource: "flag:--log-level"},
		{name: "flag over env", env: "warn", flag: "error", want: "error", wantSource: "flag:--log-level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			var paths []string
			if tc.file != "" {
				paths = append(paths, w.file("c.yaml", header+"log:\n  level: "+tc.file+"\n"))
			}
			if tc.env != "" {
				w.setenv("SCRIM_LOG_LEVEL=" + tc.env)
			}
			var args []string
			if tc.flag != "" {
				args = append(args, "--log-level", tc.flag)
			}
			w.parseFlags(args...)
			c := w.build(paths...)
			if got := w.level.Get(c); got != tc.want {
				t.Fatalf("log.level = %q, want %q", got, tc.want)
			}
			if got := source(t, c, "log.level"); !strings.HasPrefix(got, tc.wantSource) {
				t.Fatalf("source = %q, want prefix %q", got, tc.wantSource)
			}
		})
	}
}

func TestProfileLayer(t *testing.T) {
	t.Run("profile over default", func(t *testing.T) {
		w := newWorld(t)
		w.setenv("SCRIM_PROFILE=ci")
		c := w.build()
		if got := w.backend.Get(c); got != "memory" {
			t.Fatalf("state.backend = %q, want memory from profile ci", got)
		}
		if got := source(t, c, "state.backend"); got != "profile:ci" {
			t.Fatalf("source = %q", got)
		}
		if c.Profile() != "ci" {
			t.Fatalf("profile = %q", c.Profile())
		}
		// Maps merge: the profile adds an entry and keeps the default one.
		up := w.upstream.Get(c)
		if up["anthropic"] != "https://api.anthropic.com" || up["openai"] != "http://127.0.0.1:9999" {
			t.Fatalf("upstream = %v", up)
		}
	})
	t.Run("file over profile", func(t *testing.T) {
		w := newWorld(t)
		p := w.file("c.yaml", header+"profile: ci\nstate:\n  backend: sqlite\n")
		c := w.build(p)
		if got := w.backend.Get(c); got != "sqlite" {
			t.Fatalf("state.backend = %q, want the file's sqlite over profile ci", got)
		}
	})
	t.Run("profile chosen by flag", func(t *testing.T) {
		w := newWorld(t)
		w.parseFlags("--profile", "k8s")
		if got := w.backend.Get(w.build()); got != "postgres" {
			t.Fatalf("state.backend = %q", got)
		}
	})
	t.Run("unknown profile", func(t *testing.T) {
		w := newWorld(t)
		w.setenv("SCRIM_PROFILE=prod")
		mustContain(t, w.buildErr().Error(), "profile", `"prod" is not one of local, k8s, ci`)
	})
}

func TestEnvironmentMapping(t *testing.T) {
	w := newWorld(t)
	w.setenv(
		"SCRIM_PROXY_UPSTREAM_ANTHROPIC=http://127.0.0.1:9000",
		`SCRIM_PROXY_NO_PROXY=["127.0.0.1","localhost"]`,
		"SCRIM_APPROVALS_TIMEOUT=45s",
		"SCRIM_PROXY_WORKERS=8",
		"SCRIM_REDACTION_ENTROPY_THRESHOLD=3.25",
		"SCRIM_REDACTION_ALLOW_UNREDACTED_ON_ERROR=false",
		"SCRIM_SOMETHING_ELSE=ignored",
	)
	c := w.build()
	if got := w.upstream.Get(c)["anthropic"]; got != "http://127.0.0.1:9000" {
		t.Fatalf("proxy.upstream.anthropic = %q", got)
	}
	if got := w.noProxy.Get(c); !slices.Equal(got, []string{"127.0.0.1", "localhost"}) {
		t.Fatalf("proxy.no-proxy = %#v", got)
	}
	if w.timeout.Get(c) != 45*time.Second || w.workers.Get(c) != 8 || w.ratio.Get(c) != 3.25 {
		t.Fatal("scalar env values not applied")
	}
	e, _ := c.Entry("proxy.upstream")
	if e.Sources["anthropic"].String() != "env:SCRIM_PROXY_UPSTREAM_ANTHROPIC" {
		t.Fatalf("entry source = %v", e.Sources)
	}
}

func TestEnvironmentMapEntriesMergeOverWholeMap(t *testing.T) {
	w := newWorld(t)
	// Listed in reverse, to show the result does not depend on order.
	w.setenv(
		"SCRIM_PROXY_UPSTREAM_OPEN_AI=http://b",
		`SCRIM_PROXY_UPSTREAM={"anthropic":"http://a","gemini":"http://g"}`,
	)
	got := w.upstream.Get(w.build())
	want := map[string]string{"anthropic": "http://a", "gemini": "http://g", "open-ai": "http://b"}
	if len(got) != len(want) {
		t.Fatalf("upstream = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("upstream = %v, want %v", got, want)
		}
	}
}

// TestListEncodingRoundTrips checks the documented environment encoding
// carries every value a file can hold.
func TestListEncodingRoundTrips(t *testing.T) {
	values := [][]string{
		{}, {""}, {"a"}, {"a,b", `c\d`, "e f"}, {`\`, `,`, `\,`, "ü", `"q"`},
	}
	for _, v := range values {
		w := newWorld(t)
		w.setenv("SCRIM_PROXY_NO_PROXY=" + config.FormatValue(v))
		if got := w.noProxy.Get(w.build()); !slices.Equal(got, v) {
			t.Errorf("round trip of %#v gave %#v", v, got)
		}
	}
	w := newWorld(t)
	w.setenv(`SCRIM_PROXY_NO_PROXY=a\,b,c`)
	if got := w.noProxy.Get(w.build()); !slices.Equal(got, []string{"a,b", "c"}) {
		t.Errorf("comma form gave %#v", got)
	}
}

func TestDiscovery(t *testing.T) {
	t.Run("explicit path missing", func(t *testing.T) {
		w := newWorld(t)
		w.setenv("SCRIM_CONFIG=/nonexistent.yaml")
		mustContain(t, w.buildErr().Error(), "/nonexistent.yaml", "no such file")
	})
	t.Run("flag path beats SCRIM_CONFIG", func(t *testing.T) {
		w := newWorld(t)
		a := w.file("a.yaml", header+"log.level: warn\n")
		w.setenv("SCRIM_CONFIG=/nonexistent.yaml")
		if got := w.level.Get(w.build(a)); got != "warn" {
			t.Fatalf("log.level = %q", got)
		}
	})
	t.Run("SCRIM_CONFIG list, later file wins", func(t *testing.T) {
		w := newWorld(t)
		a := w.file("a.yaml", header+"log.level: warn\nproxy.workers: 2\n")
		b := w.file("b.yaml", header+"log.level: error\n")
		w.setenv("SCRIM_CONFIG=" + a + string(os.PathListSeparator) + b)
		c := w.build()
		if w.level.Get(c) != "error" || w.workers.Get(c) != 2 {
			t.Fatalf("log.level = %q, workers = %d", w.level.Get(c), w.workers.Get(c))
		}
		if !slices.Equal(c.Files(), []string{a, b}) {
			t.Fatalf("files = %v", c.Files())
		}
	})
	t.Run("search order", func(t *testing.T) {
		w := newWorld(t)
		sys := w.file("etc/config.yaml", header+"log.level: error\n")
		c := w.build()
		if !slices.Equal(c.Files(), []string{sys}) {
			t.Fatalf("only the system file exists, loaded %v", c.Files())
		}
		home := w.file("home/.config/scrim/config.yaml", header+"log.level: warn\n")
		if c := w.build(); !slices.Equal(c.Files(), []string{home}) {
			t.Fatalf("home file should win over system, loaded %v", c.Files())
		}
		xdg := w.file("xdg/scrim/config.yaml", header+"log.level: debug\n")
		w.setenv("XDG_CONFIG_HOME=" + filepath.Dir(filepath.Dir(xdg)))
		if c := w.build(); !slices.Equal(c.Files(), []string{xdg}) || w.level.Get(c) != "debug" {
			t.Fatalf("XDG file should win, loaded %v", c.Files())
		}
	})
	t.Run("no file is fine", func(t *testing.T) {
		w := newWorld(t)
		if c := w.build(); len(c.Files()) != 0 || w.level.Get(c) != "info" {
			t.Fatal("defaults expected without any file")
		}
	})
}

func TestVersionedFile(t *testing.T) {
	cases := map[string]struct{ content, want string }{
		"unsupported": {"apiVersion: scrim.dev/v9\nkind: Config\n", `apiVersion "scrim.dev/v9" is not supported (supported: scrim.dev/v1)`},
		"missing":     {"kind: Config\nlog.level: info\n", "missing apiVersion (supported: scrim.dev/v1)"},
		"no kind":     {"apiVersion: scrim.dev/v1\n", "missing kind"},
		"wrong kind":  {"apiVersion: scrim.dev/v1\nkind: Policy\n", `kind "Policy" is not supported`},
		"empty":       {"", "empty file"},
		"not a map":   {"- a\n", "must be a mapping"},
		"bad yaml":    {"apiVersion: [\n", "invalid YAML"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			p := w.file("c.yaml", tc.content)
			mustContain(t, w.buildErr(p).Error(), p, tc.want)
		})
	}
}

func TestFileShapes(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+`
approvals.timeout: 90s
log:
  level: warn
proxy:
  no-proxy: [localhost, "::1"]
  upstream:
    anthropic: http://127.0.0.1:1
  upstream.openai: http://127.0.0.1:2
  workers: 3
redaction:
  entropy-threshold: 3
`)
	c := w.build(p)
	if w.timeout.Get(c) != 90*time.Second || w.level.Get(c) != "warn" || w.workers.Get(c) != 3 || w.ratio.Get(c) != 3 {
		t.Fatal("values not applied")
	}
	if got := w.noProxy.Get(c); !slices.Equal(got, []string{"localhost", "::1"}) {
		t.Fatalf("no-proxy = %v", got)
	}
	up := w.upstream.Get(c)
	if up["anthropic"] != "http://127.0.0.1:1" || up["openai"] != "http://127.0.0.1:2" {
		t.Fatalf("upstream = %v", up)
	}
	if got := source(t, c, "approvals.timeout"); got != "file:"+p+":4" {
		t.Fatalf("source = %q, want the file and line", got)
	}
}

func TestEveryProblemListed(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+`
approvals:
  timeout: soon
log.level: loud
proxy:
  workers: 0
  no-proxy: localhost
aprovals.timeout: 60s
state: sqlite
`)
	w.setenv("SCRIM_PROXY_WORKERS=many")
	err := w.buildErr(p)
	probs := config.Problems(err)
	byKey := map[string]*config.Problem{}
	for _, pr := range probs {
		byKey[pr.Key] = pr
	}
	for _, key := range []string{"approvals.timeout", "log.level", "proxy.no-proxy", "aprovals.timeout", "state"} {
		pr, ok := byKey[key]
		if !ok {
			t.Errorf("no problem reported for %s; got %v", key, err)
			continue
		}
		if !strings.HasPrefix(pr.Source.Name, p+":") {
			t.Errorf("%s: source %q does not name the file and line", key, pr.Source)
		}
	}
	mustContain(t, err.Error(), `did you mean "approvals.timeout"?`, "SCRIM_PROXY_WORKERS", "must be at least 1")
	if !errors.Is(err, config.ErrUnknownKey) {
		t.Error("unknown key error does not wrap ErrUnknownKey")
	}
}

func TestDuplicateKeyInOneFile(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"log:\n  level: warn\nlog.level: error\n")
	mustContain(t, w.buildErr(p).Error(), "log.level", "set twice in this file")
}

func TestNonStrictUnknownKeys(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"config:\n  strict: false\naprovals:\n  timeout: 60s\n")
	c := w.build(p)
	warns := c.Warnings()
	if len(warns) != 1 || warns[0].Key != "aprovals.timeout" {
		t.Fatalf("warnings = %v", warns)
	}
	mustContain(t, warns[0].String(), "approvals.timeout")

	// The environment can relax strictness for a file it cannot edit.
	w = newWorld(t)
	p = w.file("c.yaml", header+"unknown.key: 1\n")
	w.setenv("SCRIM_CONFIG_STRICT=false")
	if c := w.build(p); len(c.Warnings()) != 1 {
		t.Fatalf("warnings = %v", c.Warnings())
	}
}

func TestYAMLTypes(t *testing.T) {
	cases := map[string]string{
		"log.level: 1":                               "expected a string written as a string",
		"approvals.timeout: 60":                      "expected a duration written as a string",
		"proxy.workers: [1]":                         "expected a int value, got a list",
		"proxy.upstream: [a]":                        "expected a mapping",
		"proxy.upstream: {a: [b]}":                   "map keys and values must be strings",
		"proxy.no-proxy: [a, [b]]":                   "list items must be strings",
		"log.level:":                                 "has no value",
		"proxy.workers: 1.5":                         "expected int",
		"redaction.allow-unredacted-on-error: maybe": "invalid syntax",
	}
	for line, want := range cases {
		t.Run(line, func(t *testing.T) {
			w := newWorld(t)
			p := w.file("c.yaml", header+line+"\n")
			mustContain(t, w.buildErr(p).Error(), want)
		})
	}
}

func TestIncludes(t *testing.T) {
	t.Run("drop-in overrides base", func(t *testing.T) {
		w := newWorld(t)
		base := w.file("etc/config.yaml", header+"approvals:\n  timeout: 120s\ninclude: conf.d\n")
		drop := w.file("etc/conf.d/10-approvals.yaml", header+"approvals:\n  timeout: 60s\n")
		w.file("etc/conf.d/README", "not yaml")
		c := w.build(base)
		if w.timeout.Get(c) != time.Minute {
			t.Fatalf("timeout = %v", w.timeout.Get(c))
		}
		if got := source(t, c, "approvals.timeout"); !strings.HasPrefix(got, "file:"+drop+":") {
			t.Fatalf("source = %q, want the drop-in", got)
		}
	})
	t.Run("lexical order and glob", func(t *testing.T) {
		w := newWorld(t)
		base := w.file("c.yaml", header+"include:\n  - d/*.yaml\n  - {path: missing.yaml, optional: true}\n")
		w.file("d/20.yaml", header+"log.level: error\n")
		w.file("d/10.yaml", header+"log.level: warn\nproxy.workers: 9\n")
		c := w.build(base)
		if w.level.Get(c) != "error" || w.workers.Get(c) != 9 {
			t.Fatalf("level = %s, workers = %d", w.level.Get(c), w.workers.Get(c))
		}
		if len(c.Files()) != 3 {
			t.Fatalf("files = %v", c.Files())
		}
	})
	t.Run("maps merge across files", func(t *testing.T) {
		w := newWorld(t)
		base := w.file("c.yaml", header+"proxy.upstream: {openai: http://o}\ninclude: [more.yaml]\n")
		w.file("more.yaml", header+"proxy.upstream: {gemini: http://g}\nproxy.no-proxy: [x]\n")
		up := w.upstream.Get(w.build(base))
		if len(up) != 3 || up["openai"] != "http://o" || up["gemini"] != "http://g" {
			t.Fatalf("upstream = %v", up)
		}
	})
	t.Run("missing required include", func(t *testing.T) {
		w := newWorld(t)
		base := w.file("c.yaml", header+"include: [gone.yaml]\n")
		mustContain(t, w.buildErr(base).Error(), "gone.yaml", "no such file")
	})
	t.Run("cycle", func(t *testing.T) {
		w := newWorld(t)
		a := w.file("a.yaml", header+"include: b.yaml\n")
		w.file("b.yaml", header+"include: a.yaml\n")
		mustContain(t, w.buildErr(a).Error(), "include cycle")
	})
	t.Run("included file must be versioned", func(t *testing.T) {
		w := newWorld(t)
		a := w.file("a.yaml", header+"include: b.yaml\n")
		w.file("b.yaml", "log.level: warn\n")
		mustContain(t, w.buildErr(a).Error(), "b.yaml", "missing apiVersion")
	})
	t.Run("bad include entry", func(t *testing.T) {
		w := newWorld(t)
		a := w.file("a.yaml", header+"include: [{path: b.yaml, required: true}]\n")
		w.file("b.yaml", header)
		mustContain(t, w.buildErr(a).Error(), `unknown field "required"`)
	})
}

func TestChecksRejectConfig(t *testing.T) {
	w := newWorld(t)
	w.reg.AddCheck("proxy", func(c *config.Config) []error {
		if w.workers.Get(c) > 8 && w.level.Get(c) == "debug" {
			return []error{errors.New("debug logging with more than 8 workers")}
		}
		return nil
	})
	w.setenv("SCRIM_PROXY_WORKERS=9", "SCRIM_LOG_LEVEL=debug")
	mustContain(t, w.buildErr().Error(), "proxy: debug logging")
}

func TestRegistryAdditions(t *testing.T) {
	r := config.NewRegistry()
	bad := []func() error{
		func() error {
			_, err := config.RegisterIn(r, config.Spec[string]{Key: "a.b", Description: "x", RequireReference: true})
			return err
		},
		func() error {
			_, err := config.RegisterIn(r, config.Spec[string]{Key: "a.c", Description: "x", Profiles: map[string]string{"prod": "y"}})
			return err
		},
		func() error {
			_, err := config.RegisterIn(r, config.Spec[bool]{Key: "a.d", Description: "x", Weakening: true, Profiles: map[string]bool{"ci": true}})
			return err
		},
		func() error {
			_, err := config.RegisterIn(r, config.Spec[config.SecretRef]{Key: "a.e", Description: "x", Default: "hunter2hunter2"})
			return err
		},
		func() error {
			_, err := config.RegisterIn(r, config.Spec[string]{Key: "a.f", Description: "x", Enum: []string{"p"}, Default: "p", Profiles: map[string]string{"ci": "q"}})
			return err
		},
	}
	for i, f := range bad {
		if f() == nil {
			t.Errorf("case %d: registration accepted, want error", i)
		}
	}
}
