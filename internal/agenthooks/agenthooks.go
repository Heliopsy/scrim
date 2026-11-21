// SPDX-License-Identifier: AGPL-3.0-only

// Package agenthooks is hooks-only interception (specs/interception
// "Hooks-only mode is reported as partial"): the command an agent runs as a
// hook after each tool call and before each prompt. It hands the tool
// result or the prompt to scrim's local API, which runs it through the data
// plane's redactor and guard, and answers in the agent's hook protocol.
//
// Claude Code's PostToolUse hook can replace the tool result
// (hookSpecificOutput.updatedToolOutput, which must keep the tool's output
// shape), so the agent sees the redacted result. Codex's PostToolUse hook
// cannot: it can only block, which replaces the result with the hook's
// reason, so the reason carries the redacted result. UserPromptSubmit can
// only block in both agents: a prompt holding a known value is refused, with
// the redacted prompt shown to the user.
//
// The hook fails closed where the agent lets it: when scrim cannot redact,
// a tool result is withheld and a prompt is blocked. Nothing here prints a
// value: what reaches standard output is the redactor's output or a fixed
// message.
package agenthooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

// Agents and events the hook handles.
const (
	AgentClaude = "claude"
	AgentCodex  = "codex"

	EventPostToolUse      = "PostToolUse"
	EventUserPromptSubmit = "UserPromptSubmit"
)

// Agents lists the agents with hooks, in a stable order.
var Agents = []string{AgentClaude, AgentCodex}

// Events lists the events the hook is installed for.
var Events = []string{EventPostToolUse, EventUserPromptSubmit}

// Withheld replaces every string in a tool result scrim could not check.
const Withheld = "[withheld by scrim: the tool result could not be checked for secret values]"

// maxReason bounds the redacted result a Codex block reason carries.
const maxReason = 256 << 10

// maxInput bounds the hook input read from standard input.
const maxInput = localapi.MaxRedactSize + 1<<20

// Redactor is scrim's local API; *localapi.Client implements it.
type Redactor interface {
	Redact(ctx context.Context, text []byte) (localapi.RedactOutput, error)
}

// ErrBadInput is returned for hook input that is not the agent's JSON. The
// caller exits 2, which the agents treat as a hook error.
var ErrBadInput = errors.New("hook input is not the agent's hook JSON")

// input is the part of the hook input both agents send that the hook reads.
type input struct {
	Event        string          `json:"hook_event_name"`
	ToolName     string          `json:"tool_name"`
	ToolResponse json.RawMessage `json:"tool_response"`
	Prompt       *string         `json:"prompt"`
}

// Run reads one hook invocation of agent for event from in and writes the
// answer, if any, to out. Writing nothing lets the agent go ahead
// unchanged. in may hold secret values; the buffers read are wiped.
func Run(ctx context.Context, agent, event string, in io.Reader, out io.Writer, r Redactor) error {
	if agent != AgentClaude && agent != AgentCodex {
		return fmt.Errorf("unknown agent %q (claude, codex)", agent)
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxInput))
	defer secret.WipeBytes(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadInput, err)
	}
	var hi input
	if err := json.Unmarshal(raw, &hi); err != nil {
		return ErrBadInput
	}
	if hi.Event != "" && hi.Event != event {
		return fmt.Errorf("%w: the agent sent %s to the %s hook", ErrBadInput, hi.Event, event)
	}
	defer secret.WipeBytes(hi.ToolResponse)
	switch event {
	case EventPostToolUse:
		return postToolUse(ctx, agent, hi, out, r)
	case EventUserPromptSubmit:
		if hi.Prompt == nil {
			return fmt.Errorf("%w: no prompt", ErrBadInput)
		}
		return userPromptSubmit(ctx, *hi.Prompt, out, r)
	}
	return fmt.Errorf("unknown hook event %q (%s)", event, strings.Join(Events, ", "))
}

func postToolUse(ctx context.Context, agent string, hi input, out io.Writer, r Redactor) error {
	resp := bytes.TrimSpace(hi.ToolResponse)
	if len(resp) == 0 || string(resp) == "null" {
		return nil
	}
	red, err := r.Redact(ctx, bytes.Clone(resp))
	var redacted json.RawMessage
	if err == nil && red.Replacements > 0 {
		redacted = json.RawMessage(red.Text)
		if !json.Valid(redacted) {
			// The result no longer parses; it cannot keep the tool's shape.
			err = errors.New("the redacted result is not valid JSON")
		}
	}
	if err == nil && red.Replacements == 0 {
		return nil
	}
	if agent == AgentCodex {
		reason := "scrim could not check this tool result for secret values, so it is withheld. The command or tool did run."
		if err == nil {
			reason = fmt.Sprintf("scrim replaced %d known secret values in this tool result with placeholders. Redacted result:\n%s",
				red.Replacements, truncate(string(redacted), maxReason))
		}
		return writeJSON(out, map[string]any{"decision": "block", "reason": reason})
	}
	ho := map[string]any{"hookEventName": EventPostToolUse}
	if err != nil {
		ho["updatedToolOutput"] = withhold(resp)
		ho["additionalContext"] = "scrim could not check the result of this " + toolName(hi) +
			" call for secret values, so its text was withheld. The tool did run."
	} else {
		ho["updatedToolOutput"] = redacted
	}
	return writeJSON(out, map[string]any{"hookSpecificOutput": ho})
}

func userPromptSubmit(ctx context.Context, prompt string, out io.Writer, r Redactor) error {
	red, err := r.Redact(ctx, []byte(prompt))
	switch {
	case err != nil:
		return writeJSON(out, map[string]any{"decision": "block", "suppressOriginalPrompt": true,
			"reason": "scrim could not check this prompt for secret values, so it was not sent. Check `scrim status`, then send it again."})
	case red.Replacements == 0:
		return nil
	}
	return writeJSON(out, map[string]any{"decision": "block", "suppressOriginalPrompt": true,
		"reason": fmt.Sprintf("This prompt holds %d known secret values, so scrim did not send it. "+
			"Send it again with the placeholders instead:\n%s", red.Replacements, truncate(red.Text, maxReason))})
}

func toolName(hi input) string {
	if hi.ToolName == "" {
		return "tool"
	}
	return hi.ToolName
}

// withhold keeps the JSON shape of v and replaces every string in it, so
// Claude Code accepts it as the tool's output and nothing of it is shown.
func withhold(v json.RawMessage) any {
	var x any
	if json.Unmarshal(v, &x) != nil {
		return Withheld
	}
	return withholdValue(x)
}

func withholdValue(x any) any {
	switch t := x.(type) {
	case string:
		return Withheld
	case []any:
		for i := range t {
			t[i] = withholdValue(t[i])
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = withholdValue(t[k])
		}
		return t
	}
	return x
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "\n[truncated by scrim]"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
