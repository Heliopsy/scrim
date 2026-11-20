// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ScriptStep is one scripted reply. Strings in Text and in tool inputs may use
// {{placeholder}} (the first placeholder in the request), {{placeholder:N}}
// (the N-th, from 0) and {{placeholders}} (all, space separated).
type ScriptStep struct {
	Text      string           `json:"text,omitempty"`
	ToolCalls []ScriptToolCall `json:"tool_calls,omitempty"`
	Status    int              `json:"status,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// ScriptToolCall is a scripted tool call.
type ScriptToolCall struct {
	Name  string         `json:"name"`
	Input map[string]any `json:"input"`
}

// Script answers the N-th assistant turn of a conversation with step N, and
// repeats the last step once the script runs out.
func Script(steps []ScriptStep) Responder {
	return func(t Turn) Reply {
		if len(steps) == 0 {
			return Echo(t)
		}
		st := steps[min(t.Assistant, len(steps)-1)]
		r := Reply{Text: expand(st.Text, t.Placeholders), Status: st.Status, Error: st.Error}
		for _, tc := range st.ToolCalls {
			r.ToolCalls = append(r.ToolCalls, ToolCall{Name: tc.Name, Input: expandAny(tc.Input, t.Placeholders).(map[string]any)})
		}
		return r
	}
}

// LoadScript reads a JSON array of steps.
func LoadScript(path string) ([]ScriptStep, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var steps []ScriptStep
	if err := json.Unmarshal(b, &steps); err != nil {
		return nil, fmt.Errorf("script %s: %w", path, err)
	}
	return steps, nil
}

func expand(s string, ph []string) string {
	if !strings.Contains(s, "{{placeholder") {
		return s
	}
	s = strings.ReplaceAll(s, "{{placeholders}}", strings.Join(ph, " "))
	for i := len(ph) - 1; i >= 0; i-- {
		s = strings.ReplaceAll(s, fmt.Sprintf("{{placeholder:%d}}", i), ph[i])
	}
	first := ""
	if len(ph) > 0 {
		first = ph[0]
	}
	return strings.ReplaceAll(s, "{{placeholder}}", first)
}

func expandAny(v any, ph []string) any {
	switch t := v.(type) {
	case nil:
		return map[string]any{}
	case string:
		return expand(t, ph)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = expandAny(e, ph)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = expandAny(e, ph)
		}
		return out
	}
	return v
}
