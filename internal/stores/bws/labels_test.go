// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
)

// The example rules in docs/stores/bws.md compile and decide as the page
// says, on labels the adapter produced.
func TestLabelsDocsPolicyExamples(t *testing.T) {
	data, err := os.ReadFile("../../../docs/stores/bws.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- policy-example -->\n```yaml\n(.*?)```").FindSubmatch(data)
	if m == nil {
		t.Fatal("docs/stores/bws.md has no policy example block")
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
	prod := f.addProject("prod", true)
	dev := f.addProject("dev", true)
	f.put(prod, "db/PASSWORD", secret.FromString("v_"+newUUID()))
	f.put(dev, "db/PASSWORD", secret.FromString("v_"+newUUID()))
	a := newAdapter(t, f, nil)
	decide := func(op policy.Action, path string, labels map[string]string) policy.Effect {
		return rs.Evaluate(policy.Request{
			Agent: policy.Agent{ID: "codex", Kind: "session"}, Action: op,
			Ref: ref(path), Store: "bws", SecretLabels: labels,
		}).Effect
	}
	for path, want := range map[string]policy.Effect{"prod/db/PASSWORD": policy.Ask, "dev/db/PASSWORD": policy.Allow} {
		md, err := a.ReadMetadata(t.Context(), ref(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := decide(policy.ActionRead, path, md.Labels); got != want {
			t.Errorf("read %s = %s, want %s", path, got, want)
		}
	}
	// A write into prod asks before the secret exists, from WriteLabels.
	for path, want := range map[string]policy.Effect{"prod/NEW": policy.Ask, "dev/NEW": policy.Allow} {
		if got := decide(policy.ActionWrite, path, a.WriteLabels(ref(path))); got != want {
			t.Errorf("write %s = %s, want %s", path, got, want)
		}
	}
}
