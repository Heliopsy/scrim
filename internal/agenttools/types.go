// SPDX-License-Identifier: AGPL-3.0-only

// Package agenttools is the service behind every agent tool: the MCP server,
// the agent-facing CLI and the local API all reach the same methods, so the
// inputs, outputs, policy and audit of a tool are the same on every path.
//
// No input type in this package carries a secret value, and no output type
// can hold one. The only ways a value enters are [Service.Put] (a value read
// from standard input or extracted from a captured command, passed as a
// [secret.Value]), [Service.Generate] (made here) and the human entry page
// ([Service.SubmitAsk]). Nothing returns one.
package agenttools

import (
	"time"
)

// Tool names, as the MCP server lists them and audit records them.
const (
	ToolSecretsList    = "secrets_list"
	ToolSecretRequest  = "secret_request"
	ToolSecretGen      = "secret_gen"
	ToolSecretCapture  = "secret_capture"
	ToolSecretAskHuman = "secret_ask_human"
	ToolApprovalStatus = "approval_status"
	ToolGrantsList     = "grants_list"
	// ToolSecretPut is the CLI's `scrim secret put --stdin`. It has no MCP
	// tool, because an MCP tool cannot take a value.
	ToolSecretPut = "secret_put"
)

// ListInput filters secrets_list.
type ListInput struct {
	Store   string `json:"store,omitempty" jsonschema:"only secrets in this store"`
	Prefix  string `json:"prefix,omitempty" jsonschema:"only references starting with this prefix, for example bao://kv/agents/"`
	Binding string `json:"binding,omitempty" jsonschema:"only secrets bound to this host"`
}

// SecretInfo describes one secret without its value.
type SecretInfo struct {
	Ref         string            `json:"ref"`
	Name        string            `json:"name,omitempty"`
	Store       string            `json:"store"`
	Placeholder string            `json:"placeholder,omitempty"`
	Bindings    []string          `json:"bindings,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitzero"`
}

// ListOutput is the result of secrets_list.
type ListOutput struct {
	Secrets []SecretInfo `json:"secrets"`
}

// RequestInput is secret_request.
type RequestInput struct {
	Ref string `json:"ref" jsonschema:"reference of the secret, for example bao://kv/agents/hetzner"`
	// Duration is a Go duration such as "30m". Empty takes the policy default.
	Duration string `json:"duration,omitempty" jsonschema:"how long the grant should last, for example 30m or 2h"`
	Reason   string `json:"reason" jsonschema:"why the secret is needed, shown to the approver"`
}

// Request statuses.
const (
	StatusGranted = "granted"
	StatusDenied  = "denied"
	StatusPending = "pending"
)

// RequestOutput is the result of secret_request.
type RequestOutput struct {
	Status     string    `json:"status" jsonschema:"granted, denied or pending"`
	Ref        string    `json:"ref"`
	ApprovalID string    `json:"approval_id,omitempty" jsonschema:"poll approval_status with this while pending"`
	GrantID    string    `json:"grant_id,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
	Duration   string    `json:"duration,omitempty" jsonschema:"duration of the grant, after any cap"`
	Capped     bool      `json:"capped,omitempty" jsonschema:"true when the requested duration was above the maximum and was capped"`
	Reason     string    `json:"reason,omitempty" jsonschema:"why the request was denied, when it was"`
}

// GenInput is secret_gen.
type GenInput struct {
	Ref   string `json:"ref" jsonschema:"reference to store the generated value at, for example bao://kv/agents/app-db#password"`
	Store string `json:"store,omitempty" jsonschema:"store to write to when the reference does not name one"`
	// Format is one of the Format* constants.
	Format string `json:"format,omitempty" jsonschema:"chars (default), hex, base64, base64url, uuid or passphrase"`
	// Length is the number of characters for chars, hex, base64 and
	// base64url. Ignored for uuid.
	Length int `json:"length,omitempty" jsonschema:"number of characters, default 32, between 8 and 4096"`
	// Charset applies to the chars format.
	Charset string `json:"charset,omitempty" jsonschema:"for chars: alnum (default), alnum-symbols, alpha, lower, digits"`
	// Words is the number of words for the passphrase format.
	Words int `json:"words,omitempty" jsonschema:"for passphrase: number of words, default 6"`
	// Separator joins passphrase words.
	Separator string `json:"separator,omitempty" jsonschema:"for passphrase: separator between words, default -"`
	Overwrite bool   `json:"overwrite,omitempty" jsonschema:"replace an existing secret at the reference"`
}

// WriteOutput is the result of every tool that stores a value.
type WriteOutput struct {
	Status      string `json:"status" jsonschema:"stored"`
	Ref         string `json:"ref"`
	Store       string `json:"store"`
	Placeholder string `json:"placeholder,omitempty" jsonschema:"what the value looks like to the model from now on"`
	// Length is the stored value's length in bytes, which is metadata.
	Length int `json:"length,omitempty"`
}

// StatusStored is the status of a successful write.
const StatusStored = "stored"

// CaptureInput is secret_capture. The command runs in the tool process (the
// agent's side), its output is never returned, and only the extracted value
// travels to the control plane.
type CaptureInput struct {
	Ref   string `json:"ref" jsonschema:"reference to store the captured value at"`
	Store string `json:"store,omitempty" jsonschema:"store to write to when the reference does not name one"`
	// Command is the program and its arguments, run without a shell.
	Command []string `json:"command" jsonschema:"program and arguments to run, without a shell, for example [\"gh\",\"api\",\"-X\",\"POST\",\"/user/tokens\"]"`
	Dir     string   `json:"dir,omitempty" jsonschema:"working directory for the command"`
	// JSONPath selects a value from JSON output, for example ".token" or
	// ".data[0].key". Mutually exclusive with Pattern.
	JSONPath string `json:"json_path,omitempty" jsonschema:"take the value at this path of the JSON output, for example .token"`
	// Pattern is a regular expression whose first capture group (or whole
	// match) is the value. Mutually exclusive with JSONPath.
	Pattern string `json:"pattern,omitempty" jsonschema:"take the first capture group of this regular expression"`
	// TimeoutSeconds bounds the command. Default 60, maximum 600.
	TimeoutSeconds int  `json:"timeout_seconds,omitempty" jsonschema:"command timeout in seconds, default 60"`
	Overwrite      bool `json:"overwrite,omitempty" jsonschema:"replace an existing secret at the reference"`
}

// CaptureOutput is the result of secret_capture.
type CaptureOutput struct {
	WriteOutput
	// ExitCode is the command's exit status. Its output is not returned.
	ExitCode int `json:"exit_code"`
}

// AskInput is secret_ask_human.
type AskInput struct {
	Ref    string `json:"ref" jsonschema:"reference to store the value at"`
	Store  string `json:"store,omitempty" jsonschema:"store to write to when the reference does not name one"`
	Prompt string `json:"prompt" jsonschema:"what to ask the human for, for example: the Hetzner API token for project web"`
	// TimeoutSeconds is how long the human has. Default 900, maximum 86400.
	TimeoutSeconds int `json:"timeout_seconds,omitempty" jsonschema:"how long the human has to answer, default 900"`
	// WaitSeconds is how long the call waits for the answer before returning
	// pending. Default 0 for the API, set by the MCP tool.
	WaitSeconds int  `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the answer before returning pending, default 120, at most 600"`
	Overwrite   bool `json:"overwrite,omitempty" jsonschema:"replace an existing secret at the reference"`
}

// Ask statuses.
const (
	AskPending  = "pending"
	AskStored   = "stored"
	AskDeclined = "declined"
	AskTimedOut = "timed_out"
)

// AskOutput is the result of secret_ask_human, and of approval_status for an
// ask identifier.
type AskOutput struct {
	ID          string    `json:"id" jsonschema:"poll approval_status with this while pending"`
	Status      string    `json:"status" jsonschema:"pending, stored, declined or timed_out"`
	Ref         string    `json:"ref"`
	Placeholder string    `json:"placeholder,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
}

// StatusInput is approval_status.
type StatusInput struct {
	ID string `json:"id" jsonschema:"approval identifier from secret_request, or ask identifier from secret_ask_human"`
}

// Approval statuses.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
)

// StatusOutput is the result of approval_status.
type StatusOutput struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind" jsonschema:"approval or ask"`
	Status    string    `json:"status" jsonschema:"for an approval: pending, approved, denied or expired; for an ask: pending, stored, declined or timed_out"`
	Ref       string    `json:"ref,omitempty"`
	GrantID   string    `json:"grant_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Grant is one active grant of the caller.
type Grant struct {
	ID            string    `json:"id"`
	Ref           string    `json:"ref"`
	Scope         []string  `json:"scope,omitempty" jsonschema:"destinations and tools the grant covers"`
	ExpiresAt     time.Time `json:"expires_at"`
	RemainingUses *int      `json:"remaining_uses,omitempty" jsonschema:"uses left, absent when unlimited"`
}

// GrantsOutput is the result of grants_list.
type GrantsOutput struct {
	Grants []Grant `json:"grants"`
}

// PutInput names where `scrim secret put` and secret_capture store a value.
// The value itself travels separately as a [secret.Value].
type PutInput struct {
	Ref       string `json:"ref"`
	Store     string `json:"store,omitempty"`
	Overwrite bool   `json:"overwrite,omitempty"`
	// Origin is ToolSecretPut or ToolSecretCapture, for audit.
	Origin string `json:"origin,omitempty"`
}

// CheckInput asks whether an operation would be allowed, so a capture can be
// refused before its command runs.
type CheckInput struct {
	Tool  string `json:"tool"`
	Ref   string `json:"ref"`
	Store string `json:"store,omitempty"`
}

// CheckOutput is the answer to CheckInput.
type CheckOutput struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}
