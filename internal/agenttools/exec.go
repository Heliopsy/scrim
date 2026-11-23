// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

// ToolSecretExec is the exec broker's tool (internal/execbroker): it runs an
// allow-listed command with the secrets its placeholders name, outside the
// agent, and returns redacted output.
const ToolSecretExec = "secret_exec"

// Exec request limits.
const (
	MaxExecArgs   = 256
	MaxExecArgLen = 32 << 10
	MaxExecEnv    = 64
	MaxExecStdin  = 1 << 20
)

// ExecInput is secret_exec. It never holds a value, only placeholders.
type ExecInput struct {
	Command []string          `json:"command" jsonschema:"program name and arguments, run without a shell, for example [\"git\",\"push\",\"origin\",\"main\"]"`
	Env     map[string]string `json:"env,omitempty" jsonschema:"environment variables to set; put the secret's placeholder where its value belongs, for example {\"PGPASSWORD\":\"<placeholder>\"}"`
	Stdin   string            `json:"stdin,omitempty" jsonschema:"standard input; placeholders are replaced only where the command allows it"`
	Dir     string            `json:"dir,omitempty" jsonschema:"absolute working directory, only where the command allows it; default a fresh empty directory"`
	// TimeoutSeconds bounds the run below exec.timeout.
	TimeoutSeconds int `json:"timeout_seconds,omitempty" jsonschema:"seconds the command may run, at most the configured exec.timeout"`
}

// ExecOutput is what came back from a brokered command, after redaction.
type ExecOutput struct {
	ExitCode int    `json:"exit_code" jsonschema:"the command's exit status, -1 when it was killed"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	// Withheld names streams that were not returned and why.
	Withheld map[string]string `json:"withheld,omitempty" jsonschema:"streams not returned (stdout, stderr) and why"`
	// Redactions counts values replaced by placeholders in the output.
	Redactions int  `json:"redactions,omitempty"`
	TimedOut   bool `json:"timed_out,omitempty"`
	// Refs are the secrets the command received.
	Refs []string `json:"refs"`
}
