// SPDX-License-Identifier: AGPL-3.0-only

// Package mcp serves scrim's agent tools as an MCP server over stdio
// (`scrim mcp`). Each tool is one call to the control plane's local API, made
// with the transport identity of the process the agent started, so policy,
// grants and audit apply to that agent.
//
// No tool input carries a secret value and no result contains one. Where a
// value has to move, it moves around the model: secret_gen makes it inside
// scrim, secret_capture runs the command in this process and sends only the
// extracted value to scrim, and secret_ask_human sends a human to a local
// entry page.
package mcp

import (
	"context"
	"encoding/json"
	"io"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/heliopsy/scrim/internal/agenttools"
)

// API is what the tools call: the local API client, or the service directly
// in tests.
type API interface {
	List(ctx context.Context, in agenttools.ListInput) (agenttools.ListOutput, error)
	Request(ctx context.Context, in agenttools.RequestInput) (agenttools.RequestOutput, error)
	Generate(ctx context.Context, in agenttools.GenInput) (agenttools.WriteOutput, error)
	Capture(ctx context.Context, in agenttools.CaptureInput) (agenttools.CaptureOutput, error)
	Ask(ctx context.Context, in agenttools.AskInput) (agenttools.AskOutput, error)
	Status(ctx context.Context, in agenttools.StatusInput) (agenttools.StatusOutput, error)
	Grants(ctx context.Context) (agenttools.GrantsOutput, error)
}

// Instructions is what the server tells a client about itself.
const Instructions = "Tools for scrim, which keeps secret values away from the model while you keep working. " +
	"You never see a secret value: tools take and return references (such as bao://kv/agents/github) and " +
	"placeholders, which scrim swaps for the real value only where the value is used. " +
	"Use secrets_list to find secrets, secret_request for time-limited access (poll approval_status while pending), " +
	"secret_gen to create a password or key, secret_capture to store a token a command prints without seeing it, " +
	"and secret_ask_human when only a person has the value. Never paste a secret value into a tool argument."

// DefaultAskWait is how long secret_ask_human waits for the human when the
// call does not say.
const DefaultAskWait = 120

// AskInput is secret_ask_human as the MCP tool takes it: unlike the API, an
// absent wait_seconds waits DefaultAskWait seconds.
type AskInput struct {
	Ref            string `json:"ref" jsonschema:"reference to store the value at"`
	Store          string `json:"store,omitempty" jsonschema:"store to write to when the reference does not name one"`
	Prompt         string `json:"prompt" jsonschema:"what to ask the human for, for example: the Hetzner API token for project web"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"how long the human has to answer, default 900"`
	WaitSeconds    *int   `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the answer before returning pending, default 120, at most 600"`
	Overwrite      bool   `json:"overwrite,omitempty" jsonschema:"replace an existing secret at the reference"`
}

// GrantsInput is grants_list, which takes no arguments.
type GrantsInput struct{}

func boolp(b bool) *bool { return &b }

// NewServer returns an MCP server with every agent tool, each answered by
// api.
func NewServer(api API, version string) *sdk.Server {
	srv := sdk.NewServer(&sdk.Implementation{Name: "scrim", Version: version},
		&sdk.ServerOptions{Instructions: Instructions})
	read := &sdk.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}
	write := &sdk.ToolAnnotations{DestructiveHint: boolp(false)}

	sdk.AddTool(srv, &sdk.Tool{Name: agenttools.ToolSecretsList, Annotations: read,
		Description: "List the secrets you may use: reference, name, store, placeholder, bound hosts and metadata. Never values."},
		handle(func(ctx context.Context, in agenttools.ListInput) (agenttools.ListOutput, error) {
			return api.List(ctx, in)
		}))

	sdk.AddTool(srv, &sdk.Tool{Name: agenttools.ToolSecretRequest, Annotations: write,
		Description: "Ask for time-limited use of a secret. Returns granted, denied, or pending with an approval_id to poll " +
			"with approval_status. A grant lets scrim use the secret for you, for example inject it toward its bound host; " +
			"it never shows you the value."},
		handle(func(ctx context.Context, in agenttools.RequestInput) (agenttools.RequestOutput, error) {
			return api.Request(ctx, in)
		}))

	sdk.AddTool(srv, &sdk.Tool{Name: agenttools.ToolSecretGen, Annotations: write,
		Description: "Generate a random value inside scrim (characters, hex, base64, UUID or passphrase) and store it at a " +
			"reference. Returns the reference and placeholder only; use the placeholder wherever the value is needed."},
		handle(func(ctx context.Context, in agenttools.GenInput) (agenttools.WriteOutput, error) {
			return api.Generate(ctx, in)
		}))

	sdk.AddTool(srv, &sdk.Tool{Name: agenttools.ToolSecretCapture, Annotations: write,
		Description: "Run a command (no shell), take a value from its output (whole output, a JSON path or a regular " +
			"expression) and store it at a reference. Use it for commands that create tokens or keys. The command's output " +
			"is never returned to you, only the exit code, reference and placeholder."},
		handle(func(ctx context.Context, in agenttools.CaptureInput) (agenttools.CaptureOutput, error) {
			return api.Capture(ctx, in)
		}))

	sdk.AddTool(srv, &sdk.Tool{Name: agenttools.ToolSecretAskHuman, Annotations: write,
		Description: "Ask a human to enter a value you cannot get yourself, such as an API key from a web console. The human " +
			"gets a link to a local entry page; the value goes straight into the store. You receive only stored, declined, " +
			"timed_out, or pending with an id to poll with approval_status."},
		handle(func(ctx context.Context, in AskInput) (agenttools.AskOutput, error) {
			wait := DefaultAskWait
			if in.WaitSeconds != nil {
				wait = *in.WaitSeconds
			}
			return api.Ask(ctx, agenttools.AskInput{Ref: in.Ref, Store: in.Store, Prompt: in.Prompt,
				TimeoutSeconds: in.TimeoutSeconds, WaitSeconds: wait, Overwrite: in.Overwrite})
		}))

	sdk.AddTool(srv, &sdk.Tool{Name: agenttools.ToolApprovalStatus, Annotations: read,
		Description: "Check an approval from secret_request (pending, approved, denied, expired) or an ask from " +
			"secret_ask_human (pending, stored, declined, timed_out)."},
		handle(func(ctx context.Context, in agenttools.StatusInput) (agenttools.StatusOutput, error) {
			return api.Status(ctx, in)
		}))

	sdk.AddTool(srv, &sdk.Tool{Name: agenttools.ToolGrantsList, Annotations: read,
		Description: "List your active grants with reference, scope, expiry and remaining uses."},
		handle(func(ctx context.Context, _ GrantsInput) (agenttools.GrantsOutput, error) { return api.Grants(ctx) }))
	if d, ok := api.(DatabaseAPI); ok {
		addDatabaseTools(srv, d)
	}
	return srv
}

// toolError is a tool failure as the model reads it: the same code and
// message the local API and the CLI report.
type toolError struct{ e *agenttools.Error }

func (t toolError) Error() string {
	raw, _ := json.Marshal(map[string]any{"error": t.e})
	return string(raw)
}

func handle[In, Out any](f func(context.Context, In) (Out, error)) sdk.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, Out, error) {
		out, err := f(ctx, in)
		if err != nil {
			var zero Out
			return nil, zero, toolError{agenttools.Public(err)}
		}
		return nil, out, nil
	}
}

// Serve runs srv over newline-delimited JSON-RPC on in and out until the
// client closes the stream or ctx ends.
func Serve(ctx context.Context, srv *sdk.Server, in io.Reader, out io.Writer) error {
	return srv.Run(ctx, &sdk.IOTransport{Reader: io.NopCloser(in), Writer: nopCloser{out}})
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
