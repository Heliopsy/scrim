// SPDX-License-Identifier: AGPL-3.0-only

// Package scenario replays realistic agent sessions through a proxy against
// the fake provider: an agent reads a .env file, prints a config, reviews a
// diff with keys in it, tails a log with tokens, receives an MCP tool result.
// Fixtures in corpus/ are templates; secrets are filled in at run time from
// generated seeds.
//
// A built-in synthetic agent speaks each provider API directly and keeps the
// conversation history the way agent CLIs do: what it received (after the
// proxy restored placeholders) goes back in the next request. That makes the
// round trip part of the test: a restored value must be redacted again on the
// way out, byte for byte the same, or prompt caching breaks.
package scenario

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

//go:embed corpus/*.json
var corpus embed.FS

// Step is one model turn: optional text, then either a tool call whose output
// the agent returns, or nothing (the final answer).
type Step struct {
	Text string `json:"text,omitempty"`
	Tool string `json:"tool,omitempty"`
	// Input is the tool call input the fake model sends. Strings may use
	// {{placeholder}} for the first placeholder in the request.
	Input map[string]any `json:"input,omitempty"`
	// Output is the tool output template.
	Output string `json:"output,omitempty"`
}

// Scenario is one scripted session.
type Scenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Prompt      string `json:"prompt"`
	Steps       []Step `json:"steps"`
}

// Corpus returns the built-in scenarios, sorted by name.
func Corpus() ([]Scenario, error) {
	entries, err := fs.ReadDir(corpus, "corpus")
	if err != nil {
		return nil, err
	}
	var out []Scenario
	for _, e := range entries {
		b, err := corpus.ReadFile(path.Join("corpus", e.Name()))
		if err != nil {
			return nil, err
		}
		var s Scenario
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if s.Name == "" || len(s.Steps) == 0 {
			return nil, fmt.Errorf("%s: a scenario needs a name and steps", e.Name())
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var slot = regexp.MustCompile(`\{\{(secret|secret_b64|secret_url|secret_json|secret_indented):([a-z0-9-]+)\}\}`)

// Render fills secret slots in a template from seeds, by seed kind.
// Unknown kinds are an error so a typo cannot silently drop a secret.
func Render(tmpl string, seeds map[leak.Kind]leak.Seed) (string, error) {
	var err error
	out := slot.ReplaceAllStringFunc(tmpl, func(m string) string {
		p := slot.FindStringSubmatch(m)
		s, ok := seeds[leak.Kind(p[2])]
		if !ok {
			err = fmt.Errorf("template uses unknown seed kind %q", p[2])
			return m
		}
		v := s.Value()
		switch p[1] {
		case "secret_b64":
			return base64.StdEncoding.EncodeToString([]byte(v))
		case "secret_url":
			return url.QueryEscape(v)
		case "secret_json":
			b, _ := json.Marshal(v)
			return string(b[1 : len(b)-1])
		case "secret_indented":
			return "    \t    " + strings.ReplaceAll(v, "\n", "\n    \t    ")
		}
		return v
	})
	return out, err
}

// script turns the scenario into fake model replies, one per assistant turn.
func (s Scenario) script() []fp.ScriptStep {
	out := make([]fp.ScriptStep, 0, len(s.Steps))
	for _, st := range s.Steps {
		step := fp.ScriptStep{Text: st.Text}
		if st.Tool != "" {
			step.ToolCalls = []fp.ScriptToolCall{{Name: st.Tool, Input: st.Input}}
		}
		out = append(out, step)
	}
	return out
}

// seedsByKind indexes seeds by kind; the first seed of a kind wins.
func seedsByKind(seeds []leak.Seed) map[leak.Kind]leak.Seed {
	m := map[leak.Kind]leak.Seed{}
	for _, s := range seeds {
		if _, ok := m[s.Kind]; !ok {
			m[s.Kind] = s
		}
	}
	return m
}
