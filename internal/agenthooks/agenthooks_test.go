// SPDX-License-Identifier: AGPL-3.0-only

package agenthooks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/localapi"
)

const placeholder = "⟦scrim:acme:01abcdef⟧"

// fakeRedactor replaces value with placeholder, or fails.
type fakeRedactor struct {
	value string
	err   error
	calls int
}

func (f *fakeRedactor) Redact(_ context.Context, text []byte) (localapi.RedactOutput, error) {
	f.calls++
	if f.err != nil {
		return localapi.RedactOutput{}, f.err
	}
	n := strings.Count(string(text), f.value)
	return localapi.RedactOutput{Text: strings.ReplaceAll(string(text), f.value, placeholder), Replacements: n}, nil
}

func generated(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "sk-test-" + hex.EncodeToString(b)
}

func postInput(t *testing.T, resp any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"hook_event_name": EventPostToolUse, "tool_name": "Bash", "tool_response": resp})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func run(t *testing.T, agent, event string, in []byte, r Redactor) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Run(context.Background(), agent, event, bytes.NewReader(in), &out, r)
	return out.String(), err
}

func TestClaudePostToolUseReplacesTheResult(t *testing.T) {
	v := generated(t)
	in := postInput(t, map[string]any{"stdout": "KEY=" + v, "stderr": "", "interrupted": false, "isImage": false})
	got, err := run(t, AgentClaude, EventPostToolUse, in, &fakeRedactor{value: v})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, v) {
		t.Fatal("the hook answer holds the value")
	}
	var ans struct {
		HSO struct {
			Event  string `json:"hookEventName"`
			Output struct {
				Stdout      string `json:"stdout"`
				Interrupted *bool  `json:"interrupted"`
			} `json:"updatedToolOutput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(got), &ans); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if ans.HSO.Event != EventPostToolUse || ans.HSO.Output.Stdout != "KEY="+placeholder || ans.HSO.Output.Interrupted == nil {
		t.Fatalf("answer keeps neither the shape nor the placeholder: %s", got)
	}
}

func TestNothingFoundLeavesTheResult(t *testing.T) {
	for _, agent := range Agents {
		got, err := run(t, agent, EventPostToolUse, postInput(t, map[string]any{"stdout": "hello"}), &fakeRedactor{value: generated(t)})
		if err != nil || got != "" {
			t.Fatalf("%s: answered %q, %v; want nothing", agent, got, err)
		}
		in, _ := json.Marshal(map[string]any{"hook_event_name": EventUserPromptSubmit, "prompt": "hello"})
		if got, err := run(t, agent, EventUserPromptSubmit, in, &fakeRedactor{value: generated(t)}); err != nil || got != "" {
			t.Fatalf("%s prompt: answered %q, %v", agent, got, err)
		}
	}
}

func TestScrimDownWithholdsTheResult(t *testing.T) {
	v := generated(t)
	in := postInput(t, map[string]any{"stdout": "KEY=" + v, "lines": []any{v, 3}})
	got, err := run(t, AgentClaude, EventPostToolUse, in, &fakeRedactor{err: errors.New("cannot reach scrim")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, v) || strings.Count(got, Withheld) != 2 || !strings.Contains(got, `"updatedToolOutput"`) {
		t.Fatalf("not withheld with the shape kept: %s", got)
	}
	got, err = run(t, AgentCodex, EventPostToolUse, in, &fakeRedactor{err: errors.New("cannot reach scrim")})
	if err != nil || strings.Contains(got, v) || !strings.Contains(got, `"decision":"block"`) {
		t.Fatalf("codex: %s, %v", got, err)
	}
}

func TestCodexPostToolUseBlocksWithTheRedactedResult(t *testing.T) {
	v := generated(t)
	got, err := run(t, AgentCodex, EventPostToolUse, postInput(t, "KEY="+v), &fakeRedactor{value: v})
	if err != nil {
		t.Fatal(err)
	}
	var ans struct{ Decision, Reason string }
	if err := json.Unmarshal([]byte(got), &ans); err != nil {
		t.Fatal(err)
	}
	if ans.Decision != "block" || !strings.Contains(ans.Reason, placeholder) || strings.Contains(got, v) {
		t.Fatalf("answer = %s", got)
	}
}

func TestPromptWithAValueIsBlocked(t *testing.T) {
	v := generated(t)
	in, _ := json.Marshal(map[string]any{"hook_event_name": EventUserPromptSubmit, "prompt": "deploy with " + v})
	for _, agent := range Agents {
		got, err := run(t, agent, EventUserPromptSubmit, in, &fakeRedactor{value: v})
		if err != nil || strings.Contains(got, v) || !strings.Contains(got, `"decision":"block"`) || !strings.Contains(got, placeholder) {
			t.Fatalf("%s: %s, %v", agent, got, err)
		}
		got, err = run(t, agent, EventUserPromptSubmit, in, &fakeRedactor{err: errors.New("down")})
		if err != nil || strings.Contains(got, v) || !strings.Contains(got, `"decision":"block"`) {
			t.Fatalf("%s with scrim down: %s, %v", agent, got, err)
		}
	}
}

func TestRedactedResultThatIsNotJSONIsWithheld(t *testing.T) {
	v := generated(t)
	r := &fakeRedactor{value: `"` + v}
	got, err := run(t, AgentClaude, EventPostToolUse, postInput(t, map[string]any{"stdout": v}), r)
	if err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 {
		t.Fatalf("calls = %d", r.calls)
	}
	if strings.Contains(got, v) || !strings.Contains(got, Withheld) {
		t.Fatalf("answer = %s", got)
	}
}

func TestBadInput(t *testing.T) {
	r := &fakeRedactor{value: "x"}
	for _, in := range []string{"not json", `{"hook_event_name":"Stop"}`} {
		if _, err := run(t, AgentClaude, EventPostToolUse, []byte(in), r); !errors.Is(err, ErrBadInput) {
			t.Fatalf("%q: err = %v", in, err)
		}
	}
	if _, err := run(t, "other", EventPostToolUse, []byte(`{}`), r); err == nil {
		t.Fatal("unknown agent accepted")
	}
	if got, err := run(t, AgentClaude, EventPostToolUse, []byte(`{"hook_event_name":"PostToolUse"}`), r); err != nil || got != "" || r.calls != 0 {
		t.Fatalf("a call without a result answered %q, %v (%d calls)", got, err, r.calls)
	}
}
