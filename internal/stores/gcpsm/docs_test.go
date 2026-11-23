// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
)

// The example rules in docs/stores/gcp.md compile and decide as the page
// says, on labels the adapter produced.
func TestDocsPolicyExamples(t *testing.T) {
	data, err := os.ReadFile("../../../docs/stores/gcp.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- policy-example -->\n```yaml\n(.*?)```").FindSubmatch(data)
	if m == nil {
		t.Fatal("docs/stores/gcp.md has no policy example block")
	}
	for _, b := range regexp.MustCompile("(?s)```cel\n(.*?)```").FindAllSubmatch(data, -1) {
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
	a := adapterFor(t, f, nil)
	f.put("", "prod--db", []byte("v"))
	f.put("", "dev--db", []byte("v"))
	f.put("", "tagged", []byte("v"))
	f.edit("", "tagged", func(s *fakeSecret) { s.labels = map[string]string{"env": "prod"} })
	f.put("", "glass", []byte("v"))
	f.edit("", "glass", func(s *fakeSecret) { s.annotations = map[string]string{"agents-never": "yes"} })
	decide := func(op policy.Action, path string, labels map[string]string) policy.Effect {
		return rs.Evaluate(policy.Request{
			Agent: policy.Agent{ID: "codex", Kind: "session"}, Action: op,
			Ref: ref(path), Store: "gsm", SecretLabels: labels,
		}).Effect
	}
	for path, want := range map[string]policy.Effect{"prod/db": policy.Ask, "dev/db": policy.Allow, "tagged": policy.Ask, "glass": policy.Deny} {
		s, err := a.Read(t.Context(), ref(path))
		if err != nil {
			t.Fatal(err)
		}
		s.Wipe()
		if got := decide(policy.ActionRead, path, s.Meta.Labels); got != want {
			t.Errorf("read %s = %s, want %s", path, got, want)
		}
	}
	for path, want := range map[string]policy.Effect{"prod/new": policy.Ask, "dev/new": policy.Allow} {
		if got := decide(policy.ActionWrite, path, a.WriteLabels(stores.Ref{Scheme: "gsm", Path: path})); got != want {
			t.Errorf("write %s = %s, want %s", path, got, want)
		}
	}
}
