// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

type fakeValues struct {
	store string
	vals  []fakeValue
}

type fakeValue struct {
	src refresh.Source
	v   secret.Value
}

func (f *fakeValues) Store() string { return f.store }
func (f *fakeValues) EachValue(fn func(refresh.Source, secret.Value)) {
	for _, v := range f.vals {
		fn(v.src, v.v)
	}
}

func buildConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: "+config.APIVersion+"\nkind: Config\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{p}, Environ: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testRing(t *testing.T) *placeholder.Ring {
	t.Helper()
	return &placeholder.Ring{Keys: []placeholder.Key{
		{Version: 2, Key: secret.FromString(seed(t, "key2-"))},
		{Version: 1, Key: secret.FromString(seed(t, "key1-"))},
	}}
}

func TestSnapshotBuilderBindsCurrentValuesOnly(t *testing.T) {
	cur, old, pend, cred := seed(t, "cur-"), seed(t, "old-"), seed(t, "pend-"), seed(t, "cred-")
	ref := stores.MustParseRef("bao://kv/agents/github#token")
	src := &fakeValues{store: "bao", vals: []fakeValue{
		{refresh.Source{Ref: ref}, secret.FromString(cur)},
		{refresh.Source{Ref: ref, Retained: true}, secret.FromString(old)},
		{refresh.Source{Ref: stores.MustParseRef("bao://kv/agents/new#value"), Pending: true}, secret.FromString(pend)},
		{refresh.Source{}, secret.FromString(cred)},
		{refresh.Source{Ref: stores.MustParseRef("bao://kv/empty#value")}, secret.FromString("")},
	}}
	cfg := buildConfig(t, `catalog:
  entries:
    github:
      ref: bao://kv/agents/github#token
      hosts: [api.github.com]
      placeholder: SCRIM_GITHUB_TOKEN
      inject: ["header:Authorization"]
proxy:
  listen: 127.0.0.1:9790
  socket: /run/scrim/llm.sock
  chain: {url: "http://127.0.0.1:9000", on-unavailable: direct}
redaction:
  min-value-length: 12
restore:
  display-mode: placeholders
  builtin-tools: false
  allow-reveal-credentials: ["bao://kv/agents/*"]
  tools:
    run-shell: {name: run_shell, role: shell, command-field: cmd}
    patch: {role: edit, old-fields: [before], new-fields: [after]}
`)
	cat, err := catalog.Load(context.Background(), cfg, nil, catalog.SelectionFrom(cfg))
	if err != nil {
		t.Fatal(err)
	}
	caKey := seed(t, "-----BEGIN PRIVATE KEY-----")
	b := &SnapshotBuilder{
		Config: func() *config.Config { return cfg }, Values: []ValueSource{src},
		Catalog: func() *catalog.Catalog { return cat }, Listeners: ListenersFrom(cfg),
		Policy: func() *pb.Policy { return &pb.Policy{Version: 3, DefaultEffect: pb.Effect_EFFECT_ASK} },
		CA: func() []CAGeneration {
			return []CAGeneration{{CertPEM: "cert", Key: secret.FromString(caKey), Current: true}}
		},
	}
	b.SetKeys(testRing(t))
	s, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(s.GetValues()) != 4 {
		t.Fatalf("values = %d, want 4 (the empty one is skipped)", len(s.GetValues()))
	}
	byVal := map[string]*pb.ValueEntry{}
	for _, v := range s.GetValues() {
		byVal[string(v.GetValue())] = v
	}
	c := byVal[cur]
	if c.GetSlug() != "github" || c.GetName() != "github" || c.GetStore() != "bao" ||
		strings.Join(c.GetBoundHosts(), ",") != "api.github.com" || strings.Join(c.GetDeclaredPlaceholders(), ",") != "SCRIM_GITHUB_TOKEN" ||
		strings.Join(c.GetInjectLocations(), ",") != "header:Authorization" {
		t.Fatalf("current = %v", c)
	}
	if o := byVal[old]; len(o.GetBoundHosts()) != 0 || len(o.GetDeclaredPlaceholders()) != 0 || o.GetSlug() != "github" {
		t.Fatalf("retained value is bound: %v", o)
	}
	if p := byVal[pend]; len(p.GetBoundHosts()) != 0 || p.GetSlug() != "bao-kv-agents-new-value" {
		t.Fatalf("pending = %v", p)
	}
	if cr := byVal[cred]; cr.GetRef() != "store:bao" || len(cr.GetBoundHosts()) != 0 || cr.GetSlug() != "bao-credential" {
		t.Fatalf("store credential = %v", cr)
	}
	if k := s.GetPlaceholderKeys(); len(k) != 2 || k[0].GetVersion() != 2 || !k[0].GetCurrent() || k[1].GetCurrent() {
		t.Fatalf("keys = %v", k)
	}
	if s.GetRedaction().GetMinValueLength() != 12 || s.GetPolicy().GetVersion() != 3 {
		t.Fatalf("redaction %v policy %v", s.GetRedaction(), s.GetPolicy())
	}
	rs := s.GetRestore()
	if rs.GetDisplayMode() != pb.DisplayMode_DISPLAY_MODE_PLACEHOLDERS || !rs.GetBuiltinToolsDisabled() ||
		strings.Join(rs.GetRevealCredentialRefs(), ",") != "bao://kv/agents/*" || len(rs.GetTools()) != 2 {
		t.Fatalf("restore = %v", rs)
	}
	for _, a := range rs.GetTools() {
		if a.GetName() == "run_shell" && (a.GetRole() != pb.ToolRole_TOOL_ROLE_SHELL || a.GetCommandField() != "cmd") ||
			a.GetName() == "patch" && (a.GetRole() != pb.ToolRole_TOOL_ROLE_EDIT || strings.Join(a.GetOldFields(), ",") != "before") {
			t.Fatalf("alias = %v", a)
		}
	}
	hosts := map[string]string{}
	for _, rt := range s.GetRoutes() {
		for _, h := range rt.GetHosts() {
			hosts[h] = rt.GetName() + " " + rt.GetProvider() + " " + rt.GetUpstream()
		}
	}
	for h, want := range map[string]string{
		"api.anthropic.com":                 "anthropic anthropic https://api.anthropic.com",
		"api.openai.com":                    "openai openai https://api.openai.com",
		"chatgpt.com":                       "chatgpt openai https://chatgpt.com",
		"ab.chatgpt.com":                    "chatgpt-ab openai https://ab.chatgpt.com",
		"generativelanguage.googleapis.com": "gemini gemini https://generativelanguage.googleapis.com",
	} {
		if hosts[h] != want {
			t.Fatalf("host %s routed to %q, want %q", h, hosts[h], want)
		}
	}
	r := s.GetRoutes()[0]
	if r.GetName() != "anthropic" || r.GetUpstream() != "https://api.anthropic.com" || r.GetPathPrefix() != "/anthropic" ||
		r.GetChain().GetUrl() != "http://127.0.0.1:9000" || !r.GetChain().GetDirectOnUnavailable() {
		t.Fatalf("route = %v", r)
	}
	if l := s.GetListeners(); len(l) != 3 || l[2].GetKind() != pb.ListenerKind_LISTENER_KIND_FORWARD_PROXY || l[0].GetKind() != pb.ListenerKind_LISTENER_KIND_BASE_URL || l[1].GetKind() != pb.ListenerKind_LISTENER_KIND_UNIX {
		t.Fatalf("listeners = %v", l)
	}
	if ca := s.GetToolProxyCa(); len(ca) != 1 || string(ca[0].GetKeyPem()) != caKey || !ca[0].GetCurrent() {
		t.Fatalf("ca = %v", ca)
	}

	// Each Build returns fresh copies: wiping one snapshot (as the
	// supervisor does after sending) leaves the next intact.
	wipeSnapshot(s)
	s2, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if valueFor(s2, ref.String()) == nil || !bytes.Contains(s2.GetValues()[0].GetValue(), []byte("cur-")) && !bytes.Contains(s2.GetValues()[1].GetValue(), []byte("cur-")) {
		t.Fatal("second build lost the value")
	}
	if len(s2.GetPlaceholderKeys()[0].GetKey()) == 0 || bytes.Count(s2.GetPlaceholderKeys()[0].GetKey(), []byte{0}) == len(s2.GetPlaceholderKeys()[0].GetKey()) {
		t.Fatal("second build has a wiped key")
	}
}

// Seeded values and keys never appear in what the builder's output prints:
// the generated Go types print secret fields like any other, so this checks
// that nothing on the daemon's path formats a snapshot into a log.
func TestSnapshotValuesNeverLogged(t *testing.T) {
	token := seed(t, "tok-")
	h := newHarness(t, token)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	// A config reload and a push under debug logging.
	if res := d.App().Config.Reload(ctx, "test"); !res.Applied {
		t.Fatalf("reload = %+v", res)
	}
	if err := d.Supervisor().Push(ctx); err != nil {
		t.Fatal(err)
	}
	key := ""
	for _, k := range h.snapshot(t).GetPlaceholderKeys() {
		key = string(k.GetKey())
	}
	_ = d.Shutdown(context.Background())
	logs := h.logs.String()
	if strings.Contains(logs, token) || key == "" || strings.Contains(logs, key) || strings.Contains(logs, fmt.Sprintf("%x", key)) {
		t.Fatal("a seeded value or the placeholder key reached the log")
	}
}

func TestPlaceholderForMatchesDerivation(t *testing.T) {
	v := seed(t, "val-")
	ref := stores.MustParseRef("env://ACME_KEY")
	src := &fakeValues{store: "env", vals: []fakeValue{{refresh.Source{Ref: ref.WithField("value")}, secret.FromString(v)}}}
	ring := testRing(t)
	want, err := placeholder.Derive(ring.Current(), "env-acme-key-value", secret.FromString(v))
	if err != nil {
		t.Fatal(err)
	}
	b := &SnapshotBuilder{Values: []ValueSource{src}}
	b.SetKeys(ring)
	if got := b.PlaceholderFor(ref); got != want {
		t.Fatalf("PlaceholderFor = %q, want %q", got, want)
	}
	if got := b.PlaceholderFor(stores.MustParseRef("env://OTHER")); got != "" {
		t.Fatalf("unknown ref = %q", got)
	}
}

func TestBuildWithoutKeyFails(t *testing.T) {
	cfg := buildConfig(t, "")
	b := &SnapshotBuilder{Config: func() *config.Config { return cfg }}
	if _, err := b.Build(context.Background()); err == nil {
		t.Fatal("snapshot built without a placeholder key")
	}
}

type fakeTarget struct {
	ready  atomic.Bool
	pushes atomic.Int32
	fail   atomic.Int32
}

func (f *fakeTarget) Ready() bool { return f.ready.Load() }
func (f *fakeTarget) Push(context.Context) error {
	if f.fail.Load() > 0 {
		f.fail.Add(-1)
		return errors.New("rejected")
	}
	f.pushes.Add(1)
	return nil
}

func TestPusherDebouncesAndWaitsForReady(t *testing.T) {
	tgt := &fakeTarget{}
	p := newPusher(tgt, func() time.Duration { return 50 * time.Millisecond }, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	for range 20 {
		p.Trigger()
	}
	time.Sleep(200 * time.Millisecond)
	if n := tgt.pushes.Load(); n != 0 {
		t.Fatalf("pushed %d times while not ready", n)
	}
	tgt.ready.Store(true)
	eventually(t, "a push once ready", func() bool { return tgt.pushes.Load() == 1 })
	time.Sleep(150 * time.Millisecond)
	if n := tgt.pushes.Load(); n != 1 {
		t.Fatalf("a burst of 20 triggers gave %d pushes, want 1", n)
	}
	tgt.fail.Store(1)
	p.Trigger()
	eventually(t, "a retried push", func() bool { return tgt.pushes.Load() == 2 })
}

// A value written to a store reaches the data plane in a new snapshot.
func TestStoreWriteIsPushed(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // let start-up pushes settle
	written := seed(t, "new-")
	ref := stores.MustParseRef("vault://agents/new")
	r, err := d.refresherFor(ref)
	if err != nil {
		t.Fatal(err)
	}
	v := secret.FromString(written)
	if _, err := r.Write(ctx, ref, map[string]secret.Value{"value": v}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the written value in a snapshot", func() bool {
		e := valueFor(h.snapshot(t), "vault://agents/new#value")
		return e != nil && string(e.GetValue()) == written
	})
}

func TestRestoreDefaultsResolveValues(t *testing.T) {
	r := restoreSettings(buildConfig(t, ""))
	if r.GetDisplayMode() != pb.DisplayMode_DISPLAY_MODE_VALUES || r.GetBuiltinToolsDisabled() || len(r.GetRevealCredentialRefs()) != 0 || len(r.GetTools()) != 0 {
		t.Fatalf("defaults = %v", r)
	}
}

func TestRestoreAliasValidation(t *testing.T) {
	for _, body := range []string{
		"restore:\n  tools:\n    x: {role: fly}\n",
		"restore:\n  tools:\n    x: {role: read, command-field: c}\n",
		"restore:\n  tools:\n    x: {role: shell, colour: red}\n",
	} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte("apiVersion: "+config.APIVersion+"\nkind: Config\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{p}, Environ: []string{}}); err == nil {
			t.Errorf("accepted %q", body)
		}
	}
}

func TestAskTimeoutMillis(t *testing.T) {
	cfg := policy.Config{Rules: []policy.RuleSpec{
		{Name: "a", Decision: "ask", Approval: policy.ApprovalSettings{Timeout: policy.Duration(10 * time.Minute)}},
		{Name: "b", Decision: "ask", Approval: policy.ApprovalSettings{Timeout: policy.Duration(time.Second)}},
	}}
	if got := askTimeoutMillis(2*time.Minute, cfg); got != 600_000 {
		t.Errorf("longest rule timeout: %d", got)
	}
	if got := askTimeoutMillis(2*time.Minute, policy.Config{}); got != 120_000 {
		t.Errorf("approvals.timeout: %d", got)
	}
	if got := askTimeoutMillis(0, policy.Config{}); got != 1 {
		t.Errorf("zero must not mean the data plane default: %d", got)
	}
}

// TestSnapshotCredentialNamesUnique checks every credential entry gets its own
// name and no value is sent twice under one slug: the data plane refuses a
// snapshot with two credentials of one name or one placeholder, and a store's
// own credentials (a static token counted twice, a role and a secret ID) or a
// retained rotated value would otherwise collide. The bound current value
// keeps its catalog name.
func TestSnapshotCredentialNamesUnique(t *testing.T) {
	cur, old, cred, cred2 := seed(t, "cur-"), seed(t, "old-"), seed(t, "cred-"), seed(t, "cred2-")
	ref := stores.MustParseRef("bao://kv/agents/github#token")
	src := &fakeValues{store: "bao", vals: []fakeValue{
		{refresh.Source{Ref: ref}, secret.FromString(cur)},
		{refresh.Source{Ref: ref, Retained: true}, secret.FromString(old)},
		{refresh.Source{}, secret.FromString(cred)},
		{refresh.Source{}, secret.FromString(cred)},
		{refresh.Source{}, secret.FromString(cred2)},
	}}
	cfg := buildConfig(t, `catalog:
  entries:
    github:
      ref: bao://kv/agents/github#token
      hosts: [api.github.com]
`)
	cat, err := catalog.Load(context.Background(), cfg, nil, catalog.SelectionFrom(cfg))
	if err != nil {
		t.Fatal(err)
	}
	b := &SnapshotBuilder{Config: func() *config.Config { return cfg }, Values: []ValueSource{src},
		Catalog: func() *catalog.Catalog { return cat }, Listeners: ListenersFrom(cfg)}
	b.SetKeys(testRing(t))
	s, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, v := range s.GetValues() {
		n := v.GetName()
		if n == "" {
			n = v.GetRef()
		}
		if names[n] {
			t.Fatalf("credential name %q is used twice", n)
		}
		names[n] = true
		if string(v.GetValue()) == cur && (n != "github" || len(v.GetBoundHosts()) == 0) {
			t.Fatalf("the bound current value is %q, bound to %v", n, v.GetBoundHosts())
		}
	}
	if len(names) != 4 || !names["store:bao~2"] || len(s.GetValues()) != 4 {
		t.Fatalf("names = %v, %d values (the repeated token is sent once)", names, len(s.GetValues()))
	}
}

// TestSnapshotListsUnavailableCredentials: a catalog credential bound to a
// host whose value no store holds yet goes to Snapshot.unavailable with its
// binding and declared placeholder and no value, so the tool proxy refuses
// its placeholder instead of forwarding it as text. A loaded one does not.
func TestSnapshotListsUnavailableCredentials(t *testing.T) {
	cur := seed(t, "cur-")
	src := &fakeValues{store: "bao", vals: []fakeValue{
		{refresh.Source{Ref: stores.MustParseRef("bao://kv/agents/github#token")}, secret.FromString(cur)},
	}}
	cfg := buildConfig(t, `catalog:
  entries:
    github:
      ref: bao://kv/agents/github#token
      hosts: [api.github.com]
      placeholder: SCRIM_GITHUB_TOKEN
    later:
      ref: bao://kv/agents/later#token
      hosts: [api.later.test]
      placeholder: SCRIM_LATER_TOKEN
      inject: ["header:Authorization"]
    nohost:
      ref: bao://kv/agents/nohost#token
`)
	cat, err := catalog.Load(context.Background(), cfg, nil, catalog.SelectionFrom(cfg))
	if err != nil {
		t.Fatal(err)
	}
	b := &SnapshotBuilder{Config: func() *config.Config { return cfg }, Values: []ValueSource{src},
		Catalog: func() *catalog.Catalog { return cat }}
	b.SetKeys(testRing(t))
	s, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u := s.GetUnavailable()
	if len(u) != 1 {
		t.Fatalf("unavailable = %v", u)
	}
	if u[0].GetRef() != "bao://kv/agents/later#token" || u[0].GetName() != "later" || len(u[0].GetValue()) != 0 ||
		strings.Join(u[0].GetBoundHosts(), ",") != "api.later.test" ||
		strings.Join(u[0].GetDeclaredPlaceholders(), ",") != "SCRIM_LATER_TOKEN" ||
		strings.Join(u[0].GetInjectLocations(), ",") != "header:Authorization" {
		t.Fatalf("unavailable entry = %v", u[0])
	}
}

// Catalog entries asking for a format-preserving placeholder, AWS SigV4
// re-signing and a client certificate carry those settings into the
// snapshot; the SigV4 link names the access key id entry by reference.
func TestSnapshotCarriesSigV4ShapeAndClientCertificate(t *testing.T) {
	akid, sk, cert := seed(t, "akid-"), seed(t, "sk-"), seed(t, "cert-")
	src := &fakeValues{store: "bao", vals: []fakeValue{
		{refresh.Source{Ref: stores.MustParseRef("bao://kv/agents/aws#access_key_id")}, secret.FromString(akid)},
		{refresh.Source{Ref: stores.MustParseRef("bao://kv/agents/aws#secret_access_key")}, secret.FromString(sk)},
		{refresh.Source{Ref: stores.MustParseRef("bao://kv/agents/kind#client")}, secret.FromString(cert)},
	}}
	cfg := buildConfig(t, `catalog:
  entries:
    aws-akid:
      ref: bao://kv/agents/aws#access_key_id
      hosts: [sts.amazonaws.com]
      placeholder_format: shape
      inject: ["header:Authorization", query]
    aws-secret:
      ref: bao://kv/agents/aws#secret_access_key
      hosts: [sts.amazonaws.com]
      placeholder_format: shape
      aws_sigv4: {access_key_id: aws-akid, regions: [us-east-1], services: [sts]}
    kind-admin:
      ref: bao://kv/agents/kind#client
      hosts: [kind.test]
      client_certificate: true
`)
	cat, err := catalog.Load(context.Background(), cfg, nil, catalog.SelectionFrom(cfg))
	if err != nil {
		t.Fatal(err)
	}
	b := &SnapshotBuilder{Config: func() *config.Config { return cfg }, Values: []ValueSource{src},
		Catalog: func() *catalog.Catalog { return cat }}
	b.SetKeys(testRing(t))
	s, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*pb.ValueEntry{}
	for _, v := range s.GetValues() {
		byName[v.GetName()] = v
	}
	if a := byName["aws-akid"]; a.GetPlaceholderFormat() != "shape" || a.GetAwsSigv4() != nil {
		t.Fatalf("aws-akid = %v", a)
	}
	sig := byName["aws-secret"].GetAwsSigv4()
	if sig.GetAccessKeyIdRef() != "bao://kv/agents/aws#access_key_id" ||
		strings.Join(sig.GetRegions(), ",") != "us-east-1" || strings.Join(sig.GetServices(), ",") != "sts" {
		t.Fatalf("aws-secret sigv4 = %v", sig)
	}
	if c := byName["kind-admin"]; !c.GetClientCertificate() || c.GetPlaceholderFormat() != "" {
		t.Fatalf("kind-admin = %v", c)
	}
}

// TestSnapshotSendsOnlyLabelsRulesRead: a rule on
// vaultwarden.collection.Prod sends that key and nothing else of each
// value's labels; a policy change re-sends them on the next build.
func TestSnapshotSendsOnlyLabelsRulesRead(t *testing.T) {
	ref := stores.MustParseRef("vw://Prod/db#password")
	src := &fakeValues{store: "vw", vals: []fakeValue{
		{refresh.Source{Ref: ref, Labels: map[string]string{
			"vaultwarden.collection": "Prod,Shared", "vaultwarden.collection.Prod": "true",
			"vaultwarden.collection.Shared": "true", "vaultwarden.org": "Acme",
		}}, secret.FromString(seed(t, "prod-"))},
		{refresh.Source{Ref: stores.MustParseRef("vw://Dev/db#password"), Labels: map[string]string{
			"vaultwarden.collection": "Dev", "vaultwarden.org": "Acme",
		}}, secret.FromString(seed(t, "dev-"))},
	}}
	cfg := buildConfig(t, "")
	rules := []string{}
	set := stores.NewSet()
	set.SetLabeling("vw", "vaultwarden", nil)
	b := &SnapshotBuilder{
		Config: func() *config.Config { return cfg }, Values: []ValueSource{src},
		Labels: set.Labels,
		Policy: func() *pb.Policy {
			c := policy.Config{Default: "allow"}
			for i, w := range rules {
				c.Rules = append(c.Rules, policy.RuleSpec{Name: fmt.Sprintf("r%d", i), Decision: "deny", When: w})
			}
			rs, err := policy.Compile(c)
			if err != nil {
				t.Fatal(err)
			}
			snap := rs.Snapshot(1, false)
			return snap.Proto()
		},
	}
	b.SetKeys(testRing(t))
	build := func() map[string]map[string]string {
		t.Helper()
		s, err := b.Build(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !s.GetValueLabels() {
			t.Fatal("value_labels not set")
		}
		out := map[string]map[string]string{}
		for _, v := range s.GetValues() {
			out[v.GetRef()] = v.GetLabels()
		}
		return out
	}
	for r, l := range build() {
		if len(l) != 0 {
			t.Fatalf("no label rule, yet %s carries %v", r, l)
		}
	}
	rules = []string{`op == "restore" && "vaultwarden.collection.Prod" in secret.labels`}
	got := build()
	if l := got["vw://Prod/db#password"]; len(l) != 1 || l["vaultwarden.collection.Prod"] != "true" {
		t.Fatalf("Prod value labels = %v", l)
	}
	if l := got["vw://Dev/db#password"]; len(l) != 0 {
		t.Fatalf("Dev value labels = %v", l)
	}
}

// A loopback Gemini upstream (a local fake or chained proxy) is reached
// directly, like every other loopback upstream; a remote one is not listed.
func TestBypassListsLoopbackGeminiUpstream(t *testing.T) {
	cfg := buildConfig(t, "proxy:\n  upstream:\n    gemini: http://127.0.0.1:18089\n    openai: https://api.example.test\n")
	if got := strings.Join(bypass(cfg), ","); got != "127.0.0.1:18089" {
		t.Fatalf("bypass = %q", got)
	}
	for _, r := range routes(cfg) {
		if r.GetName() == "gemini" && (r.GetUpstream() != "http://127.0.0.1:18089" || r.GetPathPrefix() != "/gemini" || r.GetProvider() != "gemini") {
			t.Fatalf("gemini route = %v", r)
		}
	}
}
