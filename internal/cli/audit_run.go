// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/leak/audit"
	"github.com/heliopsy/scrim/internal/leak/matrix"
)

// newAuditRunCmd is `scrim audit run`: the leak suite (bypass matrix and
// scenario corpus) against a proxy, with the fake provider as upstream.
func newAuditRunCmd(e *Env) *cobra.Command {
	var (
		o           audit.Options
		proxyCmd    string
		apis        []string
		routes      []string
		headers     []string
		placeholder string
		reportPath  string
		listMatrix  bool
		quiet       bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the leak suite against a proxy and report every seeded value that reached the fake provider",
		Long: `Run the bypass matrix and the scenario corpus through a proxy to a local fake
model provider, seeded with generated fake secrets, and report every leak,
every row whose outcome differs from its expectation, and the prompt-cache
hit rate. Exits non-zero when the gate fails.

The proxy must know the seeds: write them with --seeds-out and load that file
into the store the proxy uses, or let --proxy-cmd start the proxy with
SCRIM_LEAK_SEEDS, SCRIM_LEAK_UPSTREAM and SCRIM_LEAK_LISTEN set. Point the
proxy's provider routes at the fake provider (--upstream-listen).

--proxy builtin:passthrough and builtin:naive run the suite against stand-ins
that forward everything or redact only verbatim values; use them to check the
suite itself.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if listMatrix {
				_, err := fmt.Fprint(e.Stdout, matrix.Markdown())
				return err
			}
			if proxyCmd != "" {
				o.ProxyCmd = strings.Fields(proxyCmd)
			}
			for _, a := range apis {
				api, err := audit.ParseAPI(a)
				if err != nil {
					return err
				}
				o.APIs = append(o.APIs, api)
			}
			var err error
			if o.Prefix, err = audit.ParseRoutes(routes); err != nil {
				return err
			}
			o.Header = http.Header{}
			for _, h := range headers {
				k, v, ok := strings.Cut(h, ":")
				if !ok {
					return fmt.Errorf("header %q: want 'Name: value'", h)
				}
				o.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
			}
			if placeholder != "" {
				if o.Placeholder, err = regexp.Compile(placeholder); err != nil {
					return fmt.Errorf("--placeholder: %w", err)
				}
			}
			if !quiet {
				o.Progress = e.Stderr
			}
			rep, err := audit.Run(cmd.Context(), o)
			if rep != nil {
				if reportPath != "" {
					if werr := rep.WriteJSON(reportPath, e.Stdout); werr != nil {
						return werr
					}
				}
				if reportPath != "-" {
					rep.WriteText(e.Stdout)
				}
			}
			if errors.Is(err, audit.ErrGate) {
				return fmt.Errorf("%w: %d gated leaks, %d unexpected outcomes, %d scenario failures, %d errors",
					err, rep.Summary.GatedLeaks, rep.Summary.UnexpectedRows, rep.Summary.ScenarioFailures, rep.Summary.Errors)
			}
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.Proxy, "proxy", "", "base URL of the proxy under test, or builtin:passthrough / builtin:naive")
	f.StringVar(&proxyCmd, "proxy-cmd", "", "command that starts the proxy (split on spaces); it must listen on --proxy")
	f.DurationVar(&o.ProxyStartTimeout, "proxy-start-timeout", 0, "how long to wait for --proxy-cmd to listen (default 30s)")
	f.StringVar(&o.UpstreamListen, "upstream-listen", "127.0.0.1:0", "address of the fake provider")
	f.StringVar(&o.SeedsIn, "seeds", "", "read seeds (fake values) from this file instead of generating them")
	f.StringVar(&o.SeedsOut, "seeds-out", "", "write the seeds (fake values) to this file, mode 0600")
	f.StringSliceVar(&o.Suites, "suite", nil, "suites to run: matrix, scenarios (default both)")
	f.StringSliceVar(&apis, "api", nil, "APIs to run: anthropic, openai-chat, openai-responses, gemini, openai-realtime, openai-responses-ws (default all; the scenarios run on the HTTP ones)")
	f.StringSliceVar(&o.Rows, "rows", nil, "run only matrix rows whose ID starts with one of these prefixes")
	f.StringSliceVar(&routes, "route", nil, "route prefix of an API on the proxy, as api=prefix (for example anthropic=/anthropic); the WebSocket APIs default to the openai-responses prefix")
	f.StringArrayVar(&headers, "header", nil, "header sent with every request, as 'Name: value' (the agent's provider auth; never a seed)")
	f.StringVar(&placeholder, "placeholder", "", "regular expression matching the proxy's placeholders (default the ⟦scrim:...⟧ format)")
	f.IntVar(&o.MinPartial, "min-partial", 0, "shortest fragment of a seed that counts as a leak (default 8)")
	f.Float64Var(&o.PartialFraction, "partial-fraction", 0, "fraction of a seed's length a fragment must reach (default 0.5)")
	f.IntVar(&o.MaxPartial, "max-partial", 0, "fragment length that always counts, for long seeds (default 24)")
	f.StringVar(&o.Driver, "driver", "synthetic", "agent for the scenarios: synthetic (every API) or claude (Claude Code, empty HOME)")
	f.StringVar(&o.AgentBin, "agent-bin", "", "agent CLI binary for --driver claude (default from PATH)")
	f.StringVar(&reportPath, "report", "", "write the JSON report to this file (mode 0600), or - for stdout")
	f.BoolVar(&listMatrix, "list-matrix", false, "print the bypass matrix catalogue as Markdown and exit")
	f.BoolVarP(&quiet, "quiet", "q", false, "do not print failures as they happen")
	return cmd
}
