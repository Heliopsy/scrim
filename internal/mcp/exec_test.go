// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/heliopsy/scrim/internal/agenttools"
)

// execAPI is a fakeAPI that also offers the exec broker.
type execAPI struct {
	fakeAPI
	got agenttools.ExecInput
}

func (e *execAPI) Exec(_ context.Context, in agenttools.ExecInput) (agenttools.ExecOutput, error) {
	e.got = in
	if in.Command[0] == "base64" {
		return agenttools.ExecOutput{}, agenttools.Errorf(agenttools.CodeDenied, "base64 is never run by the exec broker")
	}
	return agenttools.ExecOutput{ExitCode: 2, Stdout: "token=⟦scrim:gh:01aa⟧\n", Refs: []string{"bao://kv/gh"}}, nil
}

// TestExecTool: an API with the exec broker gets secret_exec, whose schema
// takes no value and whose answers and errors pass through unchanged.
func TestExecTool(t *testing.T) {
	api := &execAPI{}
	s := connect(t, api)
	res, err := s.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *sdk.Tool
	for _, tl := range res.Tools {
		if tl.Name == agenttools.ToolSecretExec {
			tool = tl
		}
	}
	if tool == nil {
		t.Fatal("secret_exec is not offered")
	}
	raw, _ := json.Marshal(tool.InputSchema)
	var schema map[string]any
	_ = json.Unmarshal(raw, &schema)
	if schema["additionalProperties"] != false {
		t.Error("secret_exec accepts unlisted properties")
	}
	// Exactly these arguments. stdin, like env and command, carries
	// placeholders, which the broker swaps for values where the command's
	// allow-list entry permits; the agent has no value to put there.
	props, _ := schema["properties"].(map[string]any)
	want := map[string]bool{"command": true, "env": true, "stdin": true, "dir": true, "timeout_seconds": true}
	if len(props) != len(want) {
		t.Errorf("secret_exec arguments = %v", props)
	}
	for name := range props {
		if !want[name] {
			t.Errorf("secret_exec has unexpected argument %q", name)
		}
	}

	out, isErr := s.call(t, agenttools.ToolSecretExec, map[string]any{"command": []any{"git", "push"},
		"env": map[string]any{"GITHUB_TOKEN": "SCRIM_GITHUB_TOKEN"}})
	if isErr || out["exit_code"] != float64(2) || out["stdout"] != "token=⟦scrim:gh:01aa⟧\n" {
		t.Fatalf("result = %v", out)
	}
	if api.got.Env["GITHUB_TOKEN"] != "SCRIM_GITHUB_TOKEN" {
		t.Fatalf("input = %+v", api.got)
	}
	out, isErr = s.call(t, agenttools.ToolSecretExec, map[string]any{"command": []any{"base64"}})
	if !isErr || errCode(out) != "denied" {
		t.Fatalf("refusal = %v", out)
	}

	// Without the broker, no tool.
	plain := connect(t, &fakeAPI{})
	res, err = plain.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Name == agenttools.ToolSecretExec {
			t.Fatal("secret_exec offered without an exec broker")
		}
	}
}
