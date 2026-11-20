// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/heliopsy/scrim/internal/config"
)

type fixture struct {
	reg      *config.Registry
	timeout  config.Key[time.Duration]
	level    config.Key[string]
	noProxy  config.Key[[]string]
	upstream config.Key[map[string]string]
	unsafe   config.Key[bool]
	token    config.Key[config.SecretRef]
	workers  config.Key[int]
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	r := config.NewRegistry()
	return fixture{
		reg: r,
		timeout: config.MustRegisterIn(r, config.Spec[time.Duration]{
			Key: "approvals.timeout", Default: 2 * time.Minute, Description: "Approval timeout.", Flag: true,
		}),
		level: config.MustRegisterIn(r, config.Spec[string]{
			Key: "log.level", Default: "info", Description: "Log level.", Flag: true,
			Enum: []string{"debug", "info", "warn", "error"},
		}),
		noProxy: config.MustRegisterIn(r, config.Spec[[]string]{
			Key: "proxy.no-proxy", Description: "Hosts not proxied.",
		}),
		upstream: config.MustRegisterIn(r, config.Spec[map[string]string]{
			Key: "proxy.upstream", Description: "Upstreams by provider.",
		}),
		unsafe: config.MustRegisterIn(r, config.Spec[bool]{
			Key: "redaction.allow-unredacted-on-error", Description: "Weakens fail-closed.", Weakening: true, Flag: true,
		}),
		token: config.MustRegisterIn(r, config.Spec[config.SecretRef]{
			Key: "stores.openbao.token", Description: "OpenBao token reference.",
		}),
		workers: config.MustRegisterIn(r, config.Spec[int]{
			Key: "proxy.workers", Default: 4, Description: "Workers.",
			Validate: func(n int) error {
				if n < 1 {
					return errors.New("must be at least 1")
				}
				return nil
			},
		}),
	}
}

func TestNames(t *testing.T) {
	cases := map[string][2]string{
		"approvals.timeout":                   {"SCRIM_APPROVALS_TIMEOUT", "approvals-timeout"},
		"proxy.no-proxy":                      {"SCRIM_PROXY_NO_PROXY", "proxy-no-proxy"},
		"redaction.allow-unredacted-on-error": {"SCRIM_REDACTION_ALLOW_UNREDACTED_ON_ERROR", "redaction-allow-unredacted-on-error"},
	}
	for key, want := range cases {
		if got := config.EnvVar(key); got != want[0] {
			t.Errorf("EnvVar(%s) = %s, want %s", key, got, want[0])
		}
		if got := config.FlagName(key); got != want[1] {
			t.Errorf("FlagName(%s) = %s, want %s", key, got, want[1])
		}
	}
}

func TestRegisterRejects(t *testing.T) {
	r := config.NewRegistry()
	config.MustRegisterIn(r, config.Spec[string]{Key: "a.b", Description: "x"})
	bad := []config.Spec[string]{
		{Key: "a.b", Description: "duplicate"},
		{Key: "a.b.c", Description: "value and section"},
		{Key: "a", Description: "section and value"},
		{Key: "A.b", Description: "upper case"},
		{Key: "a..b", Description: "empty word"},
		{Key: "a.c"},
		{Key: "a.d", Description: "bad default", Enum: []string{"x"}, Default: "y"},
	}
	for _, s := range bad {
		if _, err := config.RegisterIn(r, s); err == nil {
			t.Errorf("RegisterIn(%q) succeeded, want error", s.Key)
		}
	}
	if _, err := config.RegisterIn(r, config.Spec[bool]{Key: "x.weak", Description: "w", Weakening: true, Default: true}); err == nil {
		t.Error("weakening setting defaulting to true was accepted")
	}
	if _, err := config.RegisterIn(r, config.Spec[int]{Key: "x.one-two", Description: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := config.RegisterIn(r, config.Spec[int]{Key: "x.one_two", Description: "x"}); err == nil {
		t.Error("key with underscore accepted")
	}
}

func TestDefaults(t *testing.T) {
	f := newFixture(t)
	c := config.MustLoadDefaults(f.reg)
	if f.timeout.Get(c) != 2*time.Minute || f.level.Get(c) != "info" || f.workers.Get(c) != 4 {
		t.Fatal("defaults not applied")
	}
	if got := f.noProxy.Get(c); got == nil || len(got) != 0 {
		t.Fatalf("nil list default should read as empty, got %#v", got)
	}
	if e, _ := c.Entry("log.level"); e.Source.Kind != config.SourceDefault {
		t.Fatalf("source = %v", e.Source)
	}
	if len(c.Weakened()) != 0 {
		t.Fatal("nothing should be weakened by default")
	}
}

func TestEnvLayer(t *testing.T) {
	f := newFixture(t)
	c, err := config.Load(f.reg, config.EnvLayer([]string{
		"SCRIM_APPROVALS_TIMEOUT=45s",
		`SCRIM_PROXY_NO_PROXY=["127.0.0.1","localhost"]`,
		"SCRIM_PROXY_UPSTREAM=anthropic=http://127.0.0.1:9000,openai=http://127.0.0.1:9001",
		"SCRIM_STORES_OPENBAO_TOKEN=file:/run/secrets/bao",
		"SCRIM_REDACTION_ALLOW_UNREDACTED_ON_ERROR=true",
		"SCRIM_CONFIG=/etc/scrim/config.yaml",
		"HOME=/home/x",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if f.timeout.Get(c) != 45*time.Second {
		t.Fatal("timeout not read from env")
	}
	if got := f.noProxy.Get(c); !slices.Equal(got, []string{"127.0.0.1", "localhost"}) {
		t.Fatalf("no-proxy = %v", got)
	}
	if got := f.upstream.Get(c); got["anthropic"] != "http://127.0.0.1:9000" || len(got) != 2 {
		t.Fatalf("upstream = %v", got)
	}
	if f.token.Get(c) != "file:/run/secrets/bao" {
		t.Fatal("secret ref not read")
	}
	e, _ := c.Entry("approvals.timeout")
	if e.Source.String() != "env:SCRIM_APPROVALS_TIMEOUT" {
		t.Fatalf("source = %s", e.Source)
	}
	w := c.Weakened()
	if len(w) != 1 || w[0].Setting.Key != "redaction.allow-unredacted-on-error" {
		t.Fatalf("weakened = %v", w)
	}
}

func TestListEncoding(t *testing.T) {
	f := newFixture(t)
	c, err := config.Load(f.reg, config.EnvLayer([]string{`SCRIM_PROXY_NO_PROXY=a\,b,c\\,`}))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.noProxy.Get(c); !slices.Equal(got, []string{"a,b", `c\`, ""}) {
		t.Fatalf("got %q", got)
	}
	s, _ := f.reg.Lookup("proxy.no-proxy")
	for _, in := range [][]string{{"a,b", `c\`, ""}, {}, {"x"}} {
		back, err := config.Parse(s, config.FormatValue(in))
		if err != nil || !slices.Equal(back.([]string), in) {
			t.Fatalf("round trip %q -> %q (%v)", in, back, err)
		}
	}
}

func TestPrecedenceAndErrors(t *testing.T) {
	f := newFixture(t)
	file := config.LayerFunc(func(*config.Registry) ([]config.Raw, error) {
		return []config.Raw{
			{Key: "log.level", Value: "info", Source: config.Source{Kind: config.SourceFile, Name: "/etc/scrim/config.yaml"}},
			{Key: "proxy.workers", Value: 8, Source: config.Source{Kind: config.SourceFile, Name: "/etc/scrim/config.yaml"}},
			{Key: "proxy.no-proxy", Value: []any{"a"}, Source: config.Source{Kind: config.SourceFile, Name: "/etc/scrim/config.yaml"}},
		}, nil
	})
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	f.reg.BindFlags(fs)
	if err := fs.Parse([]string{"--log-level", "debug"}); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(f.reg, file, config.EnvLayer([]string{"SCRIM_LOG_LEVEL=warn"}), config.FlagLayer(fs))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := c.Entry("log.level")
	if f.level.Get(c) != "debug" || e.Source.String() != "flag:--log-level" {
		t.Fatalf("level = %s from %s", f.level.Get(c), e.Source)
	}
	if f.workers.Get(c) != 8 || f.timeout.Get(c) != 2*time.Minute {
		t.Fatal("file value or untouched default wrong")
	}

	bad := config.LayerFunc(func(*config.Registry) ([]config.Raw, error) {
		src := config.Source{Kind: config.SourceFile, Name: "x.yaml"}
		return []config.Raw{
			{Key: "aprovals.timeout", Value: "1s", Source: src},
			{Key: "log.level", Value: "loud", Source: src},
			{Key: "proxy.workers", Value: 0, Source: src},
			{Key: "approvals.timeout", Value: 5, Source: src},
		}, nil
	})
	_, err = config.Load(f.reg, bad)
	if err == nil {
		t.Fatal("invalid layer accepted")
	}
	msg := err.Error()
	for _, want := range []string{`did you mean "approvals.timeout"`, `"loud" is not one of`, "must be at least 1", "expected duration"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q:\n%s", want, msg)
		}
	}
	if !errors.Is(err, config.ErrUnknownKey) {
		t.Error("unknown key error not wrapped")
	}
}

func TestGetReturnsCopies(t *testing.T) {
	f := newFixture(t)
	c, _ := config.Load(f.reg, config.EnvLayer([]string{"SCRIM_PROXY_NO_PROXY=a,b"}))
	got := f.noProxy.Get(c)
	got[0] = "mutated"
	if f.noProxy.Get(c)[0] != "a" {
		t.Fatal("Get exposed shared state")
	}
}

func TestHolder(t *testing.T) {
	f := newFixture(t)
	a := config.MustLoadDefaults(f.reg)
	b, _ := config.Load(f.reg, config.EnvLayer([]string{"SCRIM_APPROVALS_TIMEOUT=1m"}))
	h := config.NewHolder(a)
	var seen []time.Duration
	cancel := h.Subscribe(func(old, cur *config.Config) {
		seen = append(seen, f.timeout.Get(old), f.timeout.Get(cur))
	})
	h.Swap(b)
	cancel()
	h.Swap(a)
	if h.Current() != a || len(seen) != 2 || seen[1] != time.Minute {
		t.Fatalf("seen = %v", seen)
	}
}

func TestBoolFlag(t *testing.T) {
	f := newFixture(t)
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	f.reg.BindFlags(fs)
	if err := fs.Parse([]string{"--redaction-allow-unredacted-on-error"}); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(f.reg, config.FlagLayer(fs))
	if err != nil || !f.unsafe.Get(c) {
		t.Fatalf("bool flag not applied: %v", err)
	}
}
