// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

func TestCollectionFromFiles(t *testing.T) {
	w := newWorld(t)
	tok := w.file("slack-token", seeded)
	base := w.file("c.yaml", header+`
notifiers:
  ops-slack:
    kind: slack
    channel: "#approvals"
    token: file:`+tok+`
    retry:
      attempts: 3
      backoff: 2s
  phone:
    kind: ntfy
notifiers.phone.topic: scrim
include: more.yaml
`)
	more := w.file("more.yaml", header+"notifiers:\n  ops-slack:\n    retry: {attempts: 5}\n")
	c := w.build(base)
	insts := w.notifiers.Get(c)
	if len(insts) != 2 || insts[0].Name != "ops-slack" || insts[1].Name != "phone" {
		t.Fatalf("instances = %+v", insts)
	}
	slack := insts[0]
	if slack.String("channel") != "#approvals" || slack.String("retry.backoff") != "2s" {
		t.Fatalf("fields = %v", slack.Fields)
	}
	if v, _ := slack.Field("retry.attempts"); v != 5 {
		t.Fatalf("attempts = %v (%T), want 5 merged from the include", v, v)
	}
	if !strings.HasPrefix(slack.Sources["retry.attempts"].Name, more+":") || !strings.HasPrefix(slack.Sources["retry.backoff"].Name, base+":") {
		t.Fatalf("sources = %v", slack.Sources)
	}
	if insts[1].String("topic") != "scrim" {
		t.Fatal("dotted instance key not applied")
	}
	v, ok := c.SecretAt("notifiers.ops-slack.token")
	if !ok || expose(t, v) != seeded {
		t.Fatal("secret field not resolved")
	}
	// Mutating a returned instance does not change the Config.
	slack.Fields["channel"] = "changed"
	if w.notifiers.Get(c)[0].String("channel") != "#approvals" {
		t.Fatal("Get returned shared state")
	}
}

func TestCollectionEnvironment(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"notifiers:\n  ops-slack:\n    kind: slack\n    retry: {attempts: 3}\n")
	w.setenv(
		"SCRIM_NOTIFIERS_OPS_SLACK_RETRY_ATTEMPTS=7", // existing leaf keeps its type
		"SCRIM_NOTIFIERS_OPS_SLACK_CHANNEL=#ops",     // new field on a known instance
		"SCRIM_NOTIFIERS_OPS_SLACK_TOKEN=env:SLACK",
		"SLACK="+seeded,
		"SCRIM_NOTIFIERS_PAGER_TOKEN=env:SLACK", // unknown instance
	)
	c := w.build(p)
	inst := w.notifiers.Get(c)[0]
	if v, _ := inst.Field("retry.attempts"); v != 7 {
		t.Fatalf("attempts = %v (%T)", v, v)
	}
	if inst.String("channel") != "#ops" || inst.Sources["channel"].String() != "env:SCRIM_NOTIFIERS_OPS_SLACK_CHANNEL" {
		t.Fatalf("channel = %q from %v", inst.String("channel"), inst.Sources["channel"])
	}
	if v, ok := c.SecretAt("notifiers.ops-slack.token"); !ok || expose(t, v) != seeded {
		t.Fatal("token from env reference not resolved")
	}
	warns := c.Warnings()
	if len(warns) != 1 || warns[0].Source.Name != "SCRIM_NOTIFIERS_PAGER_TOKEN" {
		t.Fatalf("warnings = %v", warns)
	}

	t.Run("whole collection as JSON", func(t *testing.T) {
		w := newWorld(t)
		p := w.file("c.yaml", header+"notifiers:\n  old:\n    kind: slack\n")
		w.setenv(`SCRIM_NOTIFIERS={"new-one":{"kind":"ntfy","retry":{"attempts":2}}}`, "SCRIM_NOTIFIERS_NEW_ONE_TOPIC=t")
		insts := w.notifiers.Get(w.build(p))
		if len(insts) != 1 || insts[0].Name != "new-one" || insts[0].String("topic") != "t" {
			t.Fatalf("instances = %+v", insts)
		}
		if v, _ := insts[0].Field("retry.attempts"); v != 2 {
			t.Fatalf("attempts = %v (%T)", v, v)
		}
	})
	t.Run("typed override rejects bad value", func(t *testing.T) {
		w := newWorld(t)
		p := w.file("c.yaml", header+"notifiers:\n  a:\n    kind: slack\n    retry: {attempts: 3}\n")
		w.setenv("SCRIM_NOTIFIERS_A_RETRY_ATTEMPTS=lots")
		mustContain(t, w.buildErr(p).Error(), "notifiers.a.retry.attempts", "SCRIM_NOTIFIERS_A_RETRY_ATTEMPTS")
	})
}

func TestCollectionProblems(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"required field": {"notifiers:\n  a:\n    channel: x\n", "notifiers.a.kind"},
		"validate hook":  {"notifiers:\n  a:\n    kind: email\n", `kind "email" is not slack or ntfy`},
		"bad name":       {"notifiers:\n  Ops_Slack:\n    kind: slack\n", "instance name"},
		"not a mapping":  {"notifiers: [a]\n", "needs a mapping of named instances"},
		"scalar body":    {"notifiers:\n  a: slack\n", "must be a mapping of fields"},
		"secret not str": {"notifiers:\n  a:\n    kind: slack\n    token: [x]\n", "expected a secret reference string"},
		"unresolvable":   {"notifiers:\n  a:\n    kind: slack\n    token: file:/nonexistent/tok\n", "notifiers.a.token"},
		"duplicate":      {"notifiers:\n  a:\n    kind: slack\nnotifiers.a.kind: ntfy\n", "set twice"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			p := w.file("c.yaml", header+tc.doc)
			mustContain(t, w.buildErr(p).Error(), tc.want)
		})
	}
}

func TestCollectionLiteralSecret(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"notifiers:\n  a:\n    kind: slack\n    token: "+seeded+"\n")
	c := w.build(p)
	if warns := c.Warnings(); len(warns) != 1 || warns[0].Key != "notifiers.a.token" {
		t.Fatalf("warnings = %v", warns)
	}
	var out bytes.Buffer
	if err := config.WriteEffective(&out, c, config.ShowOptions{Format: "json"}); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteEffective(&out, c, config.ShowOptions{Format: "text"}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), "notifiers.a.token", "<literal>")
	assertNoSeed(t, "show", out.String(), c.String(), (&struct{ C *config.Config }{c}).C.GoString())

	r := config.NewRegistry()
	_, err := config.RegisterCollectionIn(r, config.CollectionSpec{Key: "stores", Description: "Stores.", SecretFields: []string{"token"}, RequireReference: true})
	if err != nil {
		t.Fatal(err)
	}
	p = w.file("s.yaml", header+"stores:\n  openbao:\n    token: "+seeded+"\n")
	_, err = config.Build(config.Options{Registry: r, ConfigPaths: []string{p}, Environ: []string{}})
	if err == nil {
		t.Fatal("literal accepted where a reference is required")
	}
	mustContain(t, err.Error(), "stores.openbao.token", "literal secret is not accepted")
	assertNoSeed(t, "error", err.Error())
}

func TestCollectionRegistration(t *testing.T) {
	r := config.NewRegistry()
	config.MustRegisterIn(r, config.Spec[string]{Key: "stores.default", Description: "x"})
	for _, spec := range []config.CollectionSpec{
		{Key: "stores", Description: "conflicts with a setting"},
		{Key: "stores.default.x", Description: "below a setting"},
		{Key: "Bad", Description: "bad key"},
		{Key: "c", Description: ""},
		{Key: "d", Description: "bad field", SecretFields: []string{"a.b"}},
	} {
		if _, err := config.RegisterCollectionIn(r, spec); err == nil {
			t.Errorf("collection %q accepted", spec.Key)
		}
	}
	if _, err := config.RegisterCollectionIn(r, config.CollectionSpec{Key: "notifiers", Description: "ok"}); err != nil {
		t.Fatal(err)
	}
	if _, err := config.RegisterIn(r, config.Spec[string]{Key: "notifiers.default", Description: "x"}); err == nil {
		t.Error("setting inside a collection accepted")
	}
}

func TestCollectionReload(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"notifiers:\n  a:\n    kind: slack\n")
	m, _ := newManager(t, w, p)
	w.file("c.yaml", header+"notifiers:\n  a:\n    kind: ntfy\n  b:\n    kind: slack\n")
	res := m.Reload(context.Background(), "test")
	if !res.Applied || strings.Join(res.Changed, ",") != "notifiers.a,notifiers.b" {
		t.Fatalf("result = %+v", res)
	}
	w.file("c.yaml", header+"notifiers:\n  a:\n    kind: email\n")
	if res := m.Reload(context.Background(), "test"); res.Applied {
		t.Fatal("invalid instance applied")
	}
	if len(w.notifiers.Get(m.Current())) != 2 {
		t.Fatal("running collection changed after a rejected reload")
	}
}

func TestCollectionRestartRequired(t *testing.T) {
	r := config.NewRegistry()
	col, _ := config.RegisterCollectionIn(r, config.CollectionSpec{Key: "listeners", Description: "Listeners.", RestartRequired: true})
	dir := t.TempDir()
	w := &world{t: t, dir: dir}
	p := w.file("c.yaml", header+"listeners:\n  main:\n    addr: 127.0.0.1:1\n")
	m, err := config.NewManager(config.Options{Registry: r, ConfigPaths: []string{p}, Environ: []string{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.file("c.yaml", header+"listeners:\n  main:\n    addr: 127.0.0.1:2\n")
	res := m.Reload(context.Background(), "test")
	if strings.Join(res.PendingRestart, ",") != "listeners" {
		t.Fatalf("result = %+v", res)
	}
	if got := col.Get(m.Current())[0].String("addr"); got != "127.0.0.1:1" {
		t.Fatalf("addr = %s, want the running value", got)
	}
}

func TestResolveRef(t *testing.T) {
	w := newWorld(t)
	w.setenv("X=" + seeded)
	c := w.build()
	v, err := c.ResolveRef(context.Background(), "env:X")
	if err != nil || expose(t, v) != seeded {
		t.Fatalf("ResolveRef: %v", err)
	}
	if _, err := c.ResolveRef(context.Background(), "bao://kv/x"); err == nil {
		t.Fatal("store reference resolved without a resolver")
	}
	if _, err := c.ResolveRef(context.Background(), ""); err == nil {
		t.Fatal("empty reference resolved")
	}
}
