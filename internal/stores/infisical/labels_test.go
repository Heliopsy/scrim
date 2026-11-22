// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// put stores a secret in the fake directly, with attributes the adapter
// cannot write (tags, rotation, reminder, comment, encrypted metadata).
func (f *fake) put(env, folder, key, value string, mod func(*fakeSecret)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var pid string
	for _, id := range f.projects {
		pid = id // the fake's only project
	}
	acc := ""
	for _, seg := range strings.Split(strings.Trim(folder, "/"), "/") {
		if seg != "" {
			acc += "/" + seg
			f.folders[pid+"|"+env+"|"+acc] = true
		}
	}
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	s := &fakeSecret{env: env, key: key, path: folder, versions: []string{value}, created: now, updated: now.Add(time.Hour)}
	if mod != nil {
		mod(s)
	}
	f.secrets[skey(pid, env, folder, key)] = s
}

func readLabels(t *testing.T, a *Adapter, path string) map[string]string {
	t.Helper()
	s, err := a.Read(t.Context(), stores.Ref{Scheme: "inf", Path: path})
	if err != nil {
		t.Fatalf("Read %s: %v", path, err)
	}
	s.Wipe()
	return s.Meta.Labels
}

func listLabels(t *testing.T, a *Adapter, prefix, path string) map[string]string {
	t.Helper()
	ms, err := a.List(t.Context(), stores.Ref{Scheme: "inf", Path: prefix})
	if err != nil {
		t.Fatalf("List %s: %v", prefix, err)
	}
	for _, m := range ms {
		if m.Ref.Path == path {
			return m.Labels
		}
	}
	t.Fatalf("List %s: %s missing", prefix, path)
	return nil
}

func wantLabels(t *testing.T, where string, got, want map[string]string) {
	t.Helper()
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if g, ok := got[k]; !ok || g != want[k] {
			t.Errorf("%s: label %s = %q (present %v), want %q", where, k, g, ok, want[k])
		}
	}
}

func absent(t *testing.T, where string, got map[string]string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if v, ok := got[k]; ok {
			t.Errorf("%s: label %s = %q, want it absent", where, k, v)
		}
	}
}

func TestLabelsNative(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	pid := f.projects["proj"]
	f.put("prod", "/db/Primary", "PASSWORD", "v-"+randID(8), func(s *fakeSecret) {
		s.tags = []apiTag{{Slug: "pci", Name: "PCI DSS"}, {Slug: "prod", Name: "Prod"}}
		s.metadata = []kv{{Key: "owner", Value: "payments-team"}, {Key: "scrim.hosts", Value: "db.example.test"}}
		s.rotation = "11111111-2222-4333-8444-555555555555"
		s.reminder = 30
	})
	want := map[string]string{
		"infisical.org.id":            f.orgID,
		"infisical.project":           "proj",
		"infisical.project.id":        pid,
		"infisical.project.slug":      "proj",
		"infisical.project.name":      "Project PROJ",
		"infisical.environment":       "prod",
		"infisical.environment.name":  "Production",
		"infisical.environment.id":    "env-prod-id",
		"infisical.folder":            "/db/Primary",
		"infisical.folder.db":         "true",
		"infisical.folder.db.Primary": "true",
		"infisical.key":               "PASSWORD",
		"infisical.path":              "/db/Primary/PASSWORD",
		"infisical.type":              "shared",
		"infisical.version":           "1",
		"infisical.created":           "2026-03-04T05:06:07Z",
		"infisical.updated":           "2026-03-04T06:06:07Z",
		"infisical.tag":               "pci,prod",
		"infisical.tag.pci":           "true",
		"infisical.tag.prod":          "true",
		"infisical.meta.owner":        "payments-team",
		"infisical.meta.scrim.hosts":  "db.example.test",
		"infisical.rotation":          "true",
		"infisical.rotation.id":       "11111111-2222-4333-8444-555555555555",
		"infisical.imported":          "false",
		// Secret metadata keeps arriving under its own key, as before.
		"owner":       "payments-team",
		"scrim.hosts": "db.example.test",
	}
	path := "proj/prod/db/Primary/PASSWORD"
	r := readLabels(t, a, path)
	wantLabels(t, "Read", r, want)
	absent(t, "Read", r, "infisical.folder./", "infisical.folder.Primary", "infisical.folder.db.primary",
		"infisical.import.environment", "infisical.encrypted-meta")
	absent(t, "Read", r, "infisical.reminder", "infisical.reminder.days")
	l := listLabels(t, a, "proj/prod", path)
	wantLabels(t, "List", l, want)
	// Reminders are reported by listings only.
	wantLabels(t, "List", l, map[string]string{"infisical.reminder": "true", "infisical.reminder.days": "30"})
	delete(l, "infisical.reminder")
	delete(l, "infisical.reminder.days")
	if !maps.Equal(r, l) {
		t.Errorf("Read and List labels differ:\nRead %v\nList %v", r, l)
	}

	// A secret at the root, without tags, rotation or reminder.
	f.put("prod", "/", "ROOT", "v-"+randID(8), nil)
	r = readLabels(t, a, "proj/prod/ROOT")
	wantLabels(t, "root", r, map[string]string{
		"infisical.folder": "/", "infisical.path": "/ROOT", "infisical.rotation": "false",
	})
	absent(t, "root", r, "infisical.tag", "infisical.encrypted-meta")
	wantLabels(t, "root", listLabels(t, a, "proj/prod", "proj/prod/ROOT"), map[string]string{"infisical.reminder": "false"})
	for k := range r {
		if strings.HasPrefix(k, "infisical.folder.") || strings.HasPrefix(k, "infisical.tag.") {
			t.Errorf("root secret has %s", k)
		}
	}
	absent(t, "root", r, "infisical.rotation.id", "infisical.reminder.days")
}

// Secret metadata is user-editable; it must not set or override a native
// key, under any spelling.
func TestLabelsMetadataCannotForgeNative(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	f.put("prod", "/db", "TOKEN", "v-"+randID(8), func(s *fakeSecret) {
		s.metadata = []kv{
			{Key: "infisical.environment", Value: "dev"},
			{Key: "Infisical.Project.Slug", Value: "sandbox"},
			{Key: " infisical.folder", Value: "/tmp"},
			{Key: "infisical.tag.pci", Value: "false"},
			{Key: "infisical.tag.public", Value: "true"},
			{Key: "infisical.imported", Value: "true"},
			{Key: "scrim.placeholder", Value: "SCRIM_TOKEN"},
		}
	})
	for where, got := range map[string]map[string]string{
		"Read": readLabels(t, a, "proj/prod/db/TOKEN"),
		"List": listLabels(t, a, "proj/prod", "proj/prod/db/TOKEN"),
	} {
		wantLabels(t, where, got, map[string]string{
			"infisical.environment":  "prod",
			"infisical.project.slug": "proj",
			"infisical.folder":       "/db",
			"infisical.imported":     "false",
			// The entries stay visible, under the user namespace.
			"infisical.meta.infisical.environment":  "dev",
			"infisical.meta.infisical.project.slug": "sandbox",
			"infisical.meta.infisical.tag.public":   "true",
			"scrim.placeholder":                     "SCRIM_TOKEN",
		})
		absent(t, where, got, "infisical.tag", "infisical.tag.pci", "infisical.tag.public", "Infisical.Project.Slug", " infisical.folder")
	}
}

// Writes do not store derived keys as metadata.
func TestLabelsWriteDropsDerivedKeys(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	ref := stores.Ref{Scheme: "inf", Path: "proj/dev/app/KEY"}
	v := secret.FromString("v-" + randID(8))
	defer v.Wipe()
	m, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: v}, stores.WriteOptions{Labels: map[string]string{
		"scrim.hosts": "api.example.test", "infisical.environment": "prod", "infisical.tag.pci": "true",
	}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	wantLabels(t, "Write", m.Labels, map[string]string{"scrim.hosts": "api.example.test", "infisical.environment": "dev", "infisical.folder.app": "true"})
	absent(t, "Write", m.Labels, "infisical.tag.pci")
	f.mu.Lock()
	md := f.secrets[skey(f.projects["proj"], "dev", "/app", "KEY")].metadata
	f.mu.Unlock()
	if len(md) != 1 || md[0].Key != "scrim.hosts" {
		t.Errorf("stored metadata = %v, want only scrim.hosts", md)
	}
}

func TestLabelsImported(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	f.put("dev", "/shared", "SHARED_KEY", "v-"+randID(8), nil)
	f.put("prod", "/app", "OWN", "v-"+randID(8), nil)
	f.mu.Lock()
	f.imports[f.projects["proj"]+"|prod|/app"] = "dev|/shared"
	f.mu.Unlock()
	r := readLabels(t, a, "proj/prod/app/SHARED_KEY")
	wantLabels(t, "imported", r, map[string]string{
		"infisical.environment":        "prod",
		"infisical.folder":             "/app",
		"infisical.path":               "/app/SHARED_KEY",
		"infisical.imported":           "true",
		"infisical.import.environment": "dev",
		"infisical.import.path":        "/shared",
	})
	r = readLabels(t, a, "proj/prod/app/OWN")
	wantLabels(t, "own", r, map[string]string{"infisical.imported": "false"})
	absent(t, "own", r, "infisical.import.environment", "infisical.import.path")
}

// A project addressed by ID is described once; one the identity may not
// read leaves the ID only, and is not asked about again at every read.
func TestLabelsProjectByID(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	pid := f.projects["proj"]
	f.put("dev", "/", "A", "v-"+randID(8), nil)
	for range 3 {
		r := readLabels(t, a, pid+"/dev/A")
		wantLabels(t, "by id", r, map[string]string{
			"infisical.project": "proj", "infisical.project.id": pid, "infisical.project.slug": "proj",
			"infisical.project.name": "Project PROJ", "infisical.environment.name": "Development",
		})
	}
	if n := f.count("GET /api/v1/projects/" + pid); n != 1 {
		t.Errorf("project details fetched %d times, want 1", n)
	}

	f2 := newFake(t)
	a2 := newAdapter(t, f2, nil)
	pid2 := f2.projects["proj"]
	f2.hiddenProjects[pid2] = true
	f2.put("dev", "/", "A", "v-"+randID(8), nil)
	for range 3 {
		r := readLabels(t, a2, pid2+"/dev/A")
		wantLabels(t, "hidden", r, map[string]string{"infisical.project": pid2, "infisical.project.id": pid2, "infisical.environment": "dev"})
		absent(t, "hidden", r, "infisical.project.name", "infisical.project.slug", "infisical.environment.name", "infisical.org.id")
	}
	if n := f2.count("GET /api/v1/projects/" + pid2); n != 1 {
		t.Errorf("refused project details fetched %d times, want 1", n)
	}
}

func (f *fake) count(req string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.lastRequests {
		if r == req {
			n++
		}
	}
	return n
}

// No value, comment, reminder note or encrypted metadata value reaches a
// label key or value.
func TestLabelsHoldNoValue(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	value := "v-" + randID(16)
	comment := "c-" + randID(16)
	enc := "e-" + randID(16)
	f.put("prod", "/db", "SECRET", value, func(s *fakeSecret) {
		s.comment = comment // also served as the reminder note
		s.reminder = 7
		s.metadata = []kv{{Key: "card-pin", Value: enc, IsEncrypted: true}, {Key: "owner", Value: "ops"}}
		s.tags = []apiTag{{Slug: "pci", Name: "PCI"}}
	})
	ref := stores.Ref{Scheme: "inf", Path: "proj/prod/db/SECRET"}
	s, err := a.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	s.Wipe()
	ms, err := a.List(t.Context(), stores.Ref{Scheme: "inf", Path: "proj/prod"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for where, l := range map[string]map[string]string{"Read": s.Meta.Labels, "List": ms[0].Labels, "WriteLabels": a.WriteLabels(ref)} {
		for k, v := range l {
			for _, needle := range []string{value, comment, enc} {
				if strings.Contains(k, needle) || strings.Contains(v, needle) {
					t.Errorf("%s: label %s=%s holds a value", where, k, v)
				}
			}
		}
	}
	wantLabels(t, "encrypted", s.Meta.Labels, map[string]string{
		"infisical.encrypted-meta": "card-pin", "infisical.encrypted-meta.card-pin": "true", "infisical.meta.owner": "ops",
	})
	absent(t, "encrypted", s.Meta.Labels, "card-pin", "infisical.meta.card-pin")
}

func TestWriteLabels(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	ref := stores.Ref{Scheme: "inf", Path: "proj/prod/db/NEW_KEY"}
	got := a.WriteLabels(ref)
	wantLabels(t, "cold", got, map[string]string{
		"infisical.project": "proj", "infisical.project.slug": "proj", "infisical.environment": "prod",
		"infisical.folder": "/db", "infisical.folder.db": "true", "infisical.key": "NEW_KEY",
		"infisical.path": "/db/NEW_KEY", "infisical.type": "shared",
	})
	absent(t, "cold", got, "infisical.project.name", "infisical.version")
	if n := len(f.lastRequests); n != 0 {
		t.Errorf("WriteLabels contacted the store (%d requests)", n)
	}
	// After any call has described the project, names are included.
	if _, err := a.List(t.Context(), stores.Ref{Scheme: "inf", Path: "proj/dev"}); err != nil {
		t.Fatalf("List: %v", err)
	}
	wantLabels(t, "warm", a.WriteLabels(ref), map[string]string{
		"infisical.project.id": f.projects["proj"], "infisical.project.name": "Project PROJ", "infisical.environment.name": "Production",
	})
	if a.WriteLabels(stores.Ref{Scheme: "inf", Path: "proj"}) != nil {
		t.Error("WriteLabels of an invalid reference returned labels")
	}
}

// TestLabelKey pins the metadata key folding docs/stores/infisical.md
// describes, which the adapter takes from stores.UserMeta, and the
// multi-valued attributes it declares.
func TestLabelKey(t *testing.T) {
	for in, want := range map[string]string{
		"PCI": "pci", "scrim.hosts": "scrim.hosts", "Cost Center": "cost_center", " x ": "_x_", "a/b,c": "a_b_c", "a..b.": "a.b",
		"ünï": "_n_", "team-a_b": "team-a_b",
	} {
		if got := stores.LabelKey(in); got != want {
			t.Errorf("stores.LabelKey(%q) = %q, want %q", in, got, want)
		}
	}
	for _, a := range []string{"tag", "encrypted-meta"} {
		if !stores.IsMulti(Kind, a) {
			t.Errorf("%s.%s is not declared multi-valued", Kind, a)
		}
	}
	if stores.IsMulti(Kind, "folder") {
		t.Errorf("%s.folder is declared multi-valued", Kind)
	}
}

// The example rules in docs/stores/infisical.md compile and decide as the
// page says, on labels the adapter produced.
func TestLabelsDocsPolicyExamples(t *testing.T) {
	data, err := os.ReadFile("../../../docs/stores/infisical.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- policy-example -->\n```yaml\n(.*?)```").FindSubmatch(data)
	if m == nil {
		t.Fatal("docs/stores/infisical.md has no policy example block")
	}
	cels := regexp.MustCompile("(?s)```cel\n(.*?)```").FindAllSubmatch(data, -1)
	for _, b := range cels {
		for _, line := range strings.Split(string(b[1]), "\n") {
			expr, _, _ := strings.Cut(line, "  //")
			if expr = strings.TrimSpace(expr); expr == "" {
				continue
			}
			if _, err := policy.Compile(policy.Config{Rules: []policy.RuleSpec{{Name: "doc", Decision: "ask", When: expr}}}); err != nil {
				t.Errorf("%s: %v", expr, err)
			}
		}
	}
	cfg, err := policy.Parse(m[1], false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rs, err := policy.Compile(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	f := newFake(t)
	f.projects = map[string]string{"payments": f.projects["proj"]}
	a := newAdapter(t, f, nil)
	f.put("dev", "/db", "DB_PASSWORD", "v-"+randID(8), nil)
	f.put("dev", "/app", "PCI_KEY", "v-"+randID(8), func(s *fakeSecret) { s.tags = []apiTag{{Slug: "pci"}} })
	f.put("prod", "/app", "API_KEY", "v-"+randID(8), nil)
	f.put("dev", "/app", "PLAIN", "v-"+randID(8), nil)
	f.put("dev", "/app", "BREAK_GLASS", "v-"+randID(8), func(s *fakeSecret) { s.tags = []apiTag{{Slug: "agents-never"}} })
	f.put("dev", "/app", "FORGED", "v-"+randID(8), func(s *fakeSecret) {
		s.metadata = []kv{{Key: "infisical.tag.pci", Value: "false"}, {Key: "infisical.environment", Value: "dev"}}
	})

	decide := func(op policy.Action, path string, labels map[string]string) policy.Effect {
		res := rs.Evaluate(policy.Request{
			Agent: policy.Agent{ID: "codex", Kind: "session"}, Action: op,
			Ref: stores.Ref{Scheme: "inf", Path: path}, Store: "inf", SecretLabels: labels,
		})
		return res.Effect
	}
	for _, tc := range []struct {
		op   policy.Action
		path string
		want policy.Effect
	}{
		{policy.ActionRead, "payments/dev/db/DB_PASSWORD", policy.Ask},
		{policy.ActionRead, "payments/dev/app/PCI_KEY", policy.Ask},
		{policy.ActionRead, "payments/prod/app/API_KEY", policy.Ask},
		{policy.ActionRead, "payments/dev/app/PLAIN", policy.Allow},
		{policy.ActionRead, "payments/dev/app/FORGED", policy.Allow},
		{policy.ActionRead, "payments/dev/app/BREAK_GLASS", policy.Deny},
	} {
		if got := decide(tc.op, tc.path, readLabels(t, a, tc.path)); got != tc.want {
			t.Errorf("%s %s = %s, want %s", tc.op, tc.path, got, tc.want)
		}
	}
	// A write into /db asks before the secret exists, from WriteLabels.
	for path, want := range map[string]policy.Effect{
		"payments/dev/db/NEW": policy.Ask, "payments/prod/app/NEW": policy.Ask, "payments/dev/app/NEW": policy.Allow,
	} {
		if got := decide(policy.ActionWrite, path, a.WriteLabels(stores.Ref{Scheme: "inf", Path: path})); got != want {
			t.Errorf("write %s = %s, want %s", path, got, want)
		}
	}
}
