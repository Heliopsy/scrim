// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/localapi"
)

// Exec runs a command through the exec broker (secret_exec).
func (Commands) Exec(e *Env) *cobra.Command {
	var (
		in        agenttools.ExecInput
		env       []string
		withStdin bool
	)
	cmd := &cobra.Command{
		Use:   "exec [--env NAME=PLACEHOLDER]... [--stdin] [--dir DIR] -- <command> [args...]",
		Short: "Run an allowed command with a secret you never hold (secret_exec)",
		Long: "Asks scrim's exec broker to run the command with the secrets its placeholders name. scrim runs it as " +
			"another user, outside this process, and prints its standard output and standard error with every secret " +
			"replaced by its placeholder. The command must be allowed by exec.commands or a policy rule; shells, " +
			"interpreters and commands that print or encode their input are refused.\n\n" +
			"Exit status: the command's own, or 1 for an error and 3 when scrim refused to run it. With --output json " +
			"the result is printed whole and exit_code holds the command's status.",
		Example: "  scrim exec --env PGPASSWORD=SCRIM_DB_PASSWORD -- psql -h db.internal -c 'select 1'\n" +
			"  scrim exec --dir \"$PWD\" -- git push https://x-access-token:SCRIM_GITHUB_TOKEN@github.com/org/repo HEAD",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o, _ := cmd.Flags().GetString("output")
			p := printer{cmd: cmd, json: o == "json"}
			if o != "json" && o != "text" && o != "" {
				return fmt.Errorf("--output must be text or json, not %q", o)
			}
			in.Command = args
			in.Env = map[string]string{}
			for _, kv := range env {
				k, v, ok := strings.Cut(kv, "=")
				if !ok || k == "" {
					return fmt.Errorf("--env takes NAME=VALUE, not %q", kv)
				}
				in.Env[k] = v
			}
			if withStdin {
				b, err := io.ReadAll(io.LimitReader(e.Stdin, agenttools.MaxExecStdin+1))
				if err != nil {
					return errors.New("reading standard input failed")
				}
				in.Stdin = string(b)
			}
			c, err := agentClient(e)
			if err != nil {
				return err
			}
			defer c.Close()
			return execRun(cmd.Context(), c, p, in)
		},
	}
	f := cmd.Flags()
	f.SetInterspersed(false)
	f.StringP("output", "o", "text", "output format: text or json")
	f.StringArrayVar(&env, "env", nil, "set NAME=VALUE in the command's environment; VALUE holds a placeholder (repeatable)")
	f.BoolVar(&withStdin, "stdin", false, "pass this command's standard input to the brokered command")
	f.StringVar(&in.Dir, "dir", "", "absolute working directory, where exec.commands allows it")
	f.IntVar(&in.TimeoutSeconds, "timeout", 0, "seconds the command may run (default and maximum exec.timeout)")
	return cmd
}

func execRun(ctx context.Context, c *localapi.Client, p printer, in agenttools.ExecInput) error {
	out, err := c.Exec(ctx, in)
	if err != nil {
		return p.fail(err)
	}
	if p.json {
		if err := p.emit(out, nil); err != nil {
			return err
		}
		return nil
	}
	_, _ = io.WriteString(p.cmd.OutOrStdout(), out.Stdout)
	w := p.cmd.ErrOrStderr()
	_, _ = io.WriteString(w, out.Stderr)
	for _, s := range []string{"stdout", "stderr"} {
		if why, ok := out.Withheld[s]; ok {
			_, _ = fmt.Fprintf(w, "scrim: %s withheld: %s\n", s, why)
		}
	}
	if out.TimedOut {
		_, _ = fmt.Fprintln(w, "scrim: the command ran out of time and was killed")
	}
	if out.ExitCode < 0 {
		return exitWith(ExitError)
	}
	return exitWith(out.ExitCode)
}
