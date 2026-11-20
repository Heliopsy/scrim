// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

// Secret lists, requests, generates, captures and stores secrets without
// showing values. Every subcommand is the CLI form of one agent tool, with
// the same inputs, outputs and policy.
func (Commands) Secret(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Work with secrets without seeing their values",
		Long: "Agent-facing secret commands. Each one is the CLI form of an MCP tool and talks to the local scrim API " +
			"on its Unix socket. No command takes a value as an argument or prints one.\n\n" +
			"Exit codes: 0 success, 1 error, 3 denied, 4 pending, 5 declined or expired.",
	}
	cmd.PersistentFlags().StringP("output", "o", "text", "output format: text or json")
	cmd.AddCommand(secretList(e), secretRequest(e), secretGen(e), secretCapture(e), secretAsk(e),
		secretPut(e), secretStatus(e), secretGrants(e))
	return cmd
}

// agentClient returns a local API client for the configured socket, with the
// session token from SCRIM_SESSION_TOKEN when the command runs inside
// `scrim run`.
func agentClient(e *Env) (*localapi.Client, error) {
	cfg, err := e.Config()
	if err != nil {
		return nil, err
	}
	path := agentapi.Socket.Get(cfg)
	if path == "" {
		path = localapi.DefaultSocketPath()
	}
	var tok secret.Value
	for _, kv := range e.Environ {
		if v, ok := strings.CutPrefix(kv, localapi.EnvToken+"="); ok && v != "" {
			tok = secret.FromString(v)
		}
	}
	return localapi.NewClient(path, tok), nil
}

type printer struct {
	cmd  *cobra.Command
	json bool
}

func newPrinter(cmd *cobra.Command) (printer, error) {
	o, _ := cmd.Flags().GetString("output")
	switch o {
	case "text", "":
		return printer{cmd: cmd}, nil
	case "json":
		return printer{cmd: cmd, json: true}, nil
	}
	return printer{}, fmt.Errorf("--output must be text or json, not %q", o)
}

// emit writes v as JSON, or calls text for the human form.
func (p printer) emit(v any, text func(w io.Writer)) error {
	w := p.cmd.OutOrStdout()
	if p.json {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	text(w)
	return nil
}

// fail reports a tool error: as the API's error envelope on stdout with
// --output json, as a message on stderr otherwise, with the exit code for
// its kind.
func (p printer) fail(err error) error {
	e := agenttools.Public(err)
	code := ExitError
	switch e.Code {
	case agenttools.CodeDenied, agenttools.CodeForbidden, agenttools.CodeNeedsApproval, agenttools.CodeUnauthenticated:
		code = ExitDenied
	}
	if p.json {
		_ = p.emit(localapi.ErrorBody{Error: *e}, nil)
		return &ExitCodeError{Code: code}
	}
	return &ExitCodeError{Code: code, Err: errors.New(e.Message)}
}

func exitWith(code int) error {
	if code == 0 {
		return nil
	}
	return &ExitCodeError{Code: code}
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// run is the common shape of a subcommand: build a client and printer, then
// call f.
func run(e *Env, f func(ctx context.Context, c *localapi.Client, p printer, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		p, err := newPrinter(cmd)
		if err != nil {
			return err
		}
		c, err := agentClient(e)
		if err != nil {
			return err
		}
		defer c.Close()
		return f(cmd.Context(), c, p, args)
	}
}

func secretList(e *Env) *cobra.Command {
	var in agenttools.ListInput
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List the secrets you may use (secrets_list)",
		Args:    cobra.NoArgs,
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, _ []string) error {
			out, err := c.List(ctx, in)
			if err != nil {
				return p.fail(err)
			}
			return p.emit(out, func(w io.Writer) {
				if len(out.Secrets) == 0 {
					_, _ = fmt.Fprintln(w, "no secrets")
					return
				}
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "REF\tSTORE\tBINDINGS\tPLACEHOLDER")
				for _, s := range out.Secrets {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Ref, s.Store, dash(strings.Join(s.Bindings, ",")), dash(s.Placeholder))
				}
				_ = tw.Flush()
			})
		}),
	}
	cmd.Flags().StringVar(&in.Store, "store", "", "only secrets in this store")
	cmd.Flags().StringVar(&in.Prefix, "prefix", "", "only references starting with this prefix")
	cmd.Flags().StringVar(&in.Binding, "binding", "", "only secrets bound to this host")
	return cmd
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func secretRequest(e *Env) *cobra.Command {
	var in agenttools.RequestInput
	cmd := &cobra.Command{
		Use:   "request <ref> --reason <why>",
		Short: "Ask for time-limited use of a secret (secret_request)",
		Args:  cobra.ExactArgs(1),
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, args []string) error {
			in.Ref = args[0]
			out, err := c.Request(ctx, in)
			if err != nil {
				return p.fail(err)
			}
			code := 0
			switch out.Status {
			case agenttools.StatusPending:
				code = ExitPending
			case agenttools.StatusDenied:
				code = ExitDenied
			}
			if perr := p.emit(out, func(w io.Writer) {
				switch out.Status {
				case agenttools.StatusGranted:
					_, _ = fmt.Fprintf(w, "granted %s for %s until %s (grant %s)\n", out.Ref, out.Duration, ts(out.ExpiresAt), out.GrantID)
				case agenttools.StatusPending:
					_, _ = fmt.Fprintf(w, "pending approval %s for %s; check with: scrim secret status %s\n", out.ApprovalID, out.Ref, out.ApprovalID)
				default:
					_, _ = fmt.Fprintf(w, "denied %s: %s\n", out.Ref, dash(out.Reason))
				}
				if out.Capped {
					_, _ = fmt.Fprintf(w, "note: the requested duration was above the maximum and was capped at %s\n", out.Duration)
				}
			}); perr != nil {
				return perr
			}
			return exitWith(code)
		}),
	}
	cmd.Flags().StringVar(&in.Duration, "duration", "", "how long the grant should last, for example 30m")
	cmd.Flags().StringVar(&in.Reason, "reason", "", "why the secret is needed, shown to the approver (required)")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func printWrite(p printer, out agenttools.WriteOutput, extra any) error {
	var v any = out
	if extra != nil {
		v = extra
	}
	return p.emit(v, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "stored %s in %s", out.Ref, out.Store)
		if out.Placeholder != "" {
			_, _ = fmt.Fprintf(w, " (placeholder %s)", out.Placeholder)
		}
		_, _ = fmt.Fprintln(w)
	})
}

func secretGen(e *Env) *cobra.Command {
	var in agenttools.GenInput
	cmd := &cobra.Command{
		Use:   "gen <ref>",
		Short: "Generate a random value inside scrim and store it (secret_gen)",
		Args:  cobra.ExactArgs(1),
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, args []string) error {
			in.Ref = args[0]
			out, err := c.Generate(ctx, in)
			if err != nil {
				return p.fail(err)
			}
			return printWrite(p, out, nil)
		}),
	}
	f := cmd.Flags()
	f.StringVar(&in.Store, "store", "", "store to write to when the reference does not name one")
	f.StringVar(&in.Format, "format", "", "chars (default), hex, base64, base64url, uuid or passphrase")
	f.IntVar(&in.Length, "length", 0, "number of characters (default 32)")
	f.StringVar(&in.Charset, "charset", "", "for chars: alnum (default), alnum-symbols, alpha, lower, digits")
	f.IntVar(&in.Words, "words", 0, "for passphrase: number of words (default 6)")
	f.StringVar(&in.Separator, "separator", "", "for passphrase: separator (default -)")
	f.BoolVar(&in.Overwrite, "overwrite", false, "replace an existing secret")
	return cmd
}

func secretCapture(e *Env) *cobra.Command {
	var (
		in        agenttools.CaptureInput
		fromStdin bool
	)
	cmd := &cobra.Command{
		Use:   "capture <ref> [--json-path P | --pattern RE] (--stdin | -- <command> [args...])",
		Short: "Store a value a command prints without showing it (secret_capture)",
		Long: "Runs the command (no shell) or reads standard input, takes the value from the output (whole output, " +
			"a JSON path or the first group of a regular expression) and stores it. The output is never printed.",
		Args: cobra.MinimumNArgs(1),
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, args []string) error {
			in.Ref = args[0]
			in.Command = args[1:]
			if fromStdin {
				if len(in.Command) > 0 {
					return errors.New("give either --stdin or a command, not both")
				}
				return captureStdin(ctx, e, c, p, in)
			}
			if len(in.Command) == 0 {
				return errors.New("give a command after --, or --stdin")
			}
			out, err := c.Capture(ctx, in)
			if err != nil {
				return p.fail(err)
			}
			return printWrite(p, out.WriteOutput, out)
		}),
	}
	f := cmd.Flags()
	f.StringVar(&in.Store, "store", "", "store to write to when the reference does not name one")
	f.StringVar(&in.JSONPath, "json-path", "", "take the value at this JSON path, for example .token")
	f.StringVar(&in.Pattern, "pattern", "", "take the first capture group of this regular expression")
	f.StringVar(&in.Dir, "dir", "", "working directory for the command")
	f.IntVar(&in.TimeoutSeconds, "timeout", 0, "command timeout in seconds (default 60)")
	f.BoolVar(&in.Overwrite, "overwrite", false, "replace an existing secret")
	f.BoolVar(&fromStdin, "stdin", false, "read the output from standard input instead of running a command")
	return cmd
}

func captureStdin(ctx context.Context, e *Env, c *localapi.Client, p printer, in agenttools.CaptureInput) error {
	ok, err := c.Check(ctx, agenttools.CheckInput{Tool: agenttools.ToolSecretCapture, Ref: in.Ref, Store: in.Store})
	if err != nil {
		return p.fail(err)
	}
	if !ok.Allowed {
		return p.fail(agenttools.Errorf(agenttools.CodeDenied, "%s", ok.Reason))
	}
	v, err := agenttools.CaptureReader(e.Stdin, agenttools.Extraction{JSONPath: in.JSONPath, Pattern: in.Pattern})
	if err != nil {
		return p.fail(err)
	}
	out, err := c.Put(ctx, agenttools.PutInput{Ref: in.Ref, Store: in.Store, Overwrite: in.Overwrite, Origin: agenttools.ToolSecretCapture}, v)
	if err != nil {
		return p.fail(err)
	}
	return printWrite(p, out, nil)
}

func secretPut(e *Env) *cobra.Command {
	var (
		in          agenttools.PutInput
		fromStdin   bool
		keepNewline bool
	)
	cmd := &cobra.Command{
		Use:   "put <ref> --stdin",
		Short: "Store a value read from standard input, never echoing it",
		Long: "Reads the value from standard input and stores it. On a terminal the value is read with echo off. " +
			"One trailing newline is removed unless --keep-newline is given. The value is never printed or logged; " +
			"the output is the reference and the result of the write.",
		Args: cobra.ExactArgs(1),
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, args []string) error {
			if !fromStdin {
				return errors.New("pass --stdin: values are read from standard input, never from arguments")
			}
			in.Ref, in.Origin = args[0], agenttools.ToolSecretPut
			v, err := readSecretInput(p.cmd, e.Stdin, in.Ref, keepNewline)
			if err != nil {
				return p.fail(err)
			}
			out, err := c.Put(ctx, in, v)
			if err != nil {
				return p.fail(err)
			}
			return printWrite(p, out, nil)
		}),
	}
	f := cmd.Flags()
	f.BoolVar(&fromStdin, "stdin", false, "read the value from standard input (required)")
	f.BoolVar(&keepNewline, "keep-newline", false, "keep a trailing newline as part of the value")
	f.StringVar(&in.Store, "store", "", "store to write to when the reference does not name one")
	f.BoolVar(&in.Overwrite, "overwrite", false, "replace an existing secret")
	return cmd
}

// readSecretInput reads a value from in. When in is a terminal it prompts on
// standard error and reads one line with echo off; otherwise it reads all of
// in.
func readSecretInput(cmd *cobra.Command, in io.Reader, ref string, keepNewline bool) (secret.Value, error) {
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) { // #nosec G115 -- a file descriptor fits in an int
		return agenttools.ReadValue(in, keepNewline)
	}
	errw := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(errw, "Value for %s (input is hidden): ", ref)
	b, err := term.ReadPassword(int(f.Fd())) // #nosec G115
	_, _ = fmt.Fprintln(errw)
	if err != nil {
		secret.WipeBytes(b)
		return secret.Value{}, agenttools.Errorf(agenttools.CodeInvalid, "reading the value from the terminal failed")
	}
	if len(b) == 0 {
		return secret.Value{}, agenttools.Errorf(agenttools.CodeInvalid, "no value was given")
	}
	return secret.Adopt(b), nil
}

func secretAsk(e *Env) *cobra.Command {
	var in agenttools.AskInput
	cmd := &cobra.Command{
		Use:   "ask <ref> --prompt <text>",
		Short: "Ask a human to enter a value on the local entry page (secret_ask_human)",
		Args:  cobra.ExactArgs(1),
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, args []string) error {
			in.Ref = args[0]
			out, err := c.Ask(ctx, in)
			if err != nil {
				return p.fail(err)
			}
			if perr := p.emit(out, func(w io.Writer) {
				switch out.Status {
				case agenttools.AskStored:
					_, _ = fmt.Fprintf(w, "stored %s\n", out.Ref)
				case agenttools.AskPending:
					_, _ = fmt.Fprintf(w, "pending ask %s for %s; check with: scrim secret status %s\n", out.ID, out.Ref, out.ID)
				case agenttools.AskDeclined:
					_, _ = fmt.Fprintf(w, "declined %s; nothing was stored\n", out.Ref)
				default:
					_, _ = fmt.Fprintf(w, "timed out %s; nothing was stored\n", out.Ref)
				}
			}); perr != nil {
				return perr
			}
			return exitWith(askExit(out.Status))
		}),
	}
	f := cmd.Flags()
	f.StringVar(&in.Prompt, "prompt", "", "what to ask the human for (required)")
	f.StringVar(&in.Store, "store", "", "store to write to when the reference does not name one")
	f.IntVar(&in.TimeoutSeconds, "timeout", 0, "seconds the human has to answer (default 900)")
	f.IntVar(&in.WaitSeconds, "wait", 120, "seconds to wait for the answer before returning pending (at most 600)")
	f.BoolVar(&in.Overwrite, "overwrite", false, "replace an existing secret")
	_ = cmd.MarkFlagRequired("prompt")
	return cmd
}

func askExit(s string) int {
	switch s {
	case agenttools.AskStored:
		return 0
	case agenttools.AskPending:
		return ExitPending
	default:
		return ExitDeclined
	}
}

func secretStatus(e *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "status <approval-or-ask-id>",
		Short: "Check an approval or an ask (approval_status)",
		Args:  cobra.ExactArgs(1),
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, args []string) error {
			out, err := c.Status(ctx, agenttools.StatusInput{ID: args[0]})
			if err != nil {
				return p.fail(err)
			}
			if perr := p.emit(out, func(w io.Writer) {
				_, _ = fmt.Fprintf(w, "%s %s: %s", out.Kind, out.ID, out.Status)
				if out.Ref != "" {
					_, _ = fmt.Fprintf(w, " for %s", out.Ref)
				}
				if out.GrantID != "" {
					_, _ = fmt.Fprintf(w, " (grant %s)", out.GrantID)
				}
				_, _ = fmt.Fprintln(w)
			}); perr != nil {
				return perr
			}
			switch out.Status {
			case agenttools.ApprovalApproved, agenttools.AskStored:
				return nil
			case agenttools.ApprovalPending:
				return exitWith(ExitPending)
			case agenttools.ApprovalDenied:
				return exitWith(ExitDenied)
			default:
				return exitWith(ExitDeclined)
			}
		}),
	}
}

func secretGrants(e *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "grants",
		Short: "List your active grants (grants_list)",
		Args:  cobra.NoArgs,
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, _ []string) error {
			out, err := c.Grants(ctx)
			if err != nil {
				return p.fail(err)
			}
			return p.emit(out, func(w io.Writer) {
				if len(out.Grants) == 0 {
					_, _ = fmt.Fprintln(w, "no active grants")
					return
				}
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "ID\tREF\tEXPIRES\tUSES LEFT\tSCOPE")
				for _, g := range out.Grants {
					uses := "unlimited"
					if g.RemainingUses != nil {
						uses = fmt.Sprint(*g.RemainingUses)
					}
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", g.ID, g.Ref, ts(g.ExpiresAt), uses, dash(strings.Join(g.Scope, ",")))
				}
				_ = tw.Flush()
			})
		}),
	}
}
