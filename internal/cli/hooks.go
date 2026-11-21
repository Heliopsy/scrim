// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/agenthooks"
	"github.com/heliopsy/scrim/internal/localapi"
)

// hookWait bounds one hook's call to scrim, below the hook timeout the
// agents are given (install.HookTimeout).
const hookWait = 20 * time.Second

// Hooks is the command agents run as hooks (specs/interception "Hooks-only
// mode is reported as partial"). `scrim install --hooks` installs it.
func (Commands) Hooks(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hooks",
		Short: "Agent hooks that redact tool results and check prompts (installed by scrim install --hooks)",
		Long: "Hooks-only interception, the weakest method: scrim sees tool results and prompts, never the model traffic, " +
			"and nothing restores placeholders. Install with `scrim install --hooks`, remove with `scrim uninstall --hooks`; " +
			"docs/interception.md (method 6).",
	}
	var agent, event string
	run := &cobra.Command{
		Use:   "run --agent claude|codex --event PostToolUse|UserPromptSubmit",
		Short: "Handle one hook call: the agent's hook JSON on standard input, the answer on standard output",
		Long: "Sends the tool result (PostToolUse) or the prompt (UserPromptSubmit) to scrim's local API, which runs it " +
			"through the data plane's redactor and guard. Claude Code gets the redacted tool result in place of the " +
			"original; Codex gets the result blocked, with the redacted result as the reason. A prompt holding a known " +
			"value is blocked. When scrim cannot redact, the tool result is withheld and the prompt blocked. " +
			"Input that is not hook JSON exits 2.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var r agenthooks.Redactor = unavailableRedactor{}
			if c, err := agentClient(e); err == nil {
				defer c.Close()
				r = c
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), hookWait)
			defer cancel()
			err := agenthooks.Run(ctx, agent, event, cmd.InOrStdin(), cmd.OutOrStdout(), r)
			if errors.Is(err, agenthooks.ErrBadInput) {
				return &ExitCodeError{Code: 2, Err: err}
			}
			return err
		},
	}
	run.Flags().StringVar(&agent, "agent", "", "the agent running the hook: claude or codex")
	run.Flags().StringVar(&event, "event", "", "the hook event: PostToolUse or UserPromptSubmit")
	_ = run.MarkFlagRequired("agent")
	_ = run.MarkFlagRequired("event")
	cmd.AddCommand(run)
	return cmd
}

// unavailableRedactor stands in when the configuration cannot be loaded:
// the hook then withholds and blocks, as with scrim down.
type unavailableRedactor struct{}

func (unavailableRedactor) Redact(context.Context, []byte) (localapi.RedactOutput, error) {
	return localapi.RedactOutput{}, errors.New("scrim's configuration could not be loaded")
}
