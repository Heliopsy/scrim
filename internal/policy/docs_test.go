// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDocsExamplesCompile keeps the rule examples in docs/policy.md valid:
// every YAML block is loaded and compiled, and every CEL block compiles as a
// rule condition.
func TestDocsExamplesCompile(t *testing.T) {
	data, err := os.ReadFile("../../docs/policy.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```(yaml|cel)\n(.*?)```").FindAllStringSubmatch(string(data), -1)
	if len(blocks) < 5 {
		t.Fatalf("found only %d example blocks", len(blocks))
	}
	for i, b := range blocks {
		lang, body := b[1], b[2]
		if lang == "cel" {
			for _, line := range strings.Split(body, "\n") {
				expr, _, _ := strings.Cut(line, "  //")
				if expr = strings.TrimSpace(expr); expr == "" {
					continue
				}
				if _, err := Compile(Config{Rules: []RuleSpec{{Name: "doc", Decision: "allow", When: expr}}}); err != nil {
					t.Errorf("block %d: %s: %v", i, expr, err)
				}
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(body), "- ") {
			body = "rules:\n" + body
		}
		c, err := Parse([]byte(body), false)
		if err != nil {
			t.Errorf("block %d: %v", i, err)
			continue
		}
		if _, err := Compile(c); err != nil {
			t.Errorf("block %d: %v", i, err)
		}
	}
}
