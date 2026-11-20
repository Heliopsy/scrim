// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// Upstream is the fake provider as the runner sees it.
type Upstream interface {
	Reset(ctx context.Context) error
	Exchanges(ctx context.Context) ([]fp.Exchange, error)
}

// Target is the proxy under test.
type Target struct {
	// BaseURL is the proxy's base URL, for example http://127.0.0.1:8484.
	BaseURL string
	// Prefix maps an API to the route prefix the proxy serves it under, for
	// example "/anthropic". Empty means the provider's own path.
	Prefix map[fp.API]string
	// Header is added to every request, typically the agent's own provider
	// authentication. It must not be a seed.
	Header http.Header
	// Client sends requests. Default: a client with a 30 s timeout.
	Client *http.Client
}

// defaultClient has its own connection pool, separate from
// http.DefaultTransport, which in-process stand-in proxies may also use.
var defaultClient = &http.Client{Timeout: 60 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()}

// Send sends one request through the proxy and returns status and body.
func (t Target) Send(ctx context.Context, r Request) (int, []byte, error) {
	u := strings.TrimRight(t.BaseURL, "/") + t.Prefix[r.API] + r.Path
	if len(r.Query) > 0 {
		u += "?" + r.Query.Encode()
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(r.Body))
	if err != nil {
		return 0, nil, err
	}
	for k, vs := range t.Header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	for k, vs := range r.Header {
		hr.Header[k] = vs
	}
	if hr.Header.Get("Authorization") == "" && hr.Header.Get("X-Api-Key") == "" {
		switch r.API {
		case fp.Anthropic:
			hr.Header.Set("X-Api-Key", "fake-provider-key-not-a-seed")
		default:
			hr.Header.Set("Authorization", "Bearer fake-provider-key-not-a-seed")
		}
	}
	c := t.Client
	if c == nil {
		c = defaultClient
	}
	resp, err := c.Do(hr)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, body, err
}

// Result is the outcome of one row for one seed.
type Result struct {
	Row       string         `json:"row"`
	API       fp.API         `json:"api"`
	Placement string         `json:"placement"`
	Transform string         `json:"transform"`
	Seed      leak.SeedRef   `json:"seed"`
	Expect    Expect         `json:"expect"`
	Outcome   Outcome        `json:"outcome"`
	Pass      bool           `json:"pass"`
	Statuses  []int          `json:"statuses"`
	Forwarded int            `json:"forwarded"`
	Findings  []leak.Finding `json:"findings,omitempty"`
	Error     string         `json:"error,omitempty"`
	Note      string         `json:"note,omitempty"`
}

// Runner runs rows against a target.
type Runner struct {
	Target   Target
	Upstream Upstream
	Checker  *leak.Checker
	// Placeholder matches the proxy's placeholders. Default
	// [fp.DefaultPlaceholderPattern].
	Placeholder *regexp.Regexp
	// Progress, when set, is called after each result.
	Progress func(Result)
}

// ContentFor returns the tool output a transform renders for a value.
func ContentFor(t Transform, value string) Content {
	return Content{
		Command: t.Command,
		Before:  "$ " + t.Command + "\n# billing service\nSERVICE_NAME=billing\nAPI_TOKEN=",
		Value:   t.Apply(value),
		After:   "\nLOG_LEVEL=debug\n",
	}
}

// RunRow runs one row for one seed.
func (r *Runner) RunRow(ctx context.Context, row Row, seed leak.Seed) Result {
	res := Result{Row: row.ID, API: row.API, Placement: row.Placement.ID, Transform: row.Transform.ID, Seed: seed.Ref(), Expect: row.Expect, Note: row.Note}
	ph := r.Placeholder
	if ph == nil {
		ph = fp.DefaultPlaceholderPattern
	}
	if err := r.Upstream.Reset(ctx); err != nil {
		res.Outcome, res.Error = OutcomeError, "reset upstream: "+err.Error()
		return res
	}
	reqs := row.Placement.Build(row.API, ContentFor(row.Transform, seed.Value()), row.Transform.Body)
	allFailed := true
	for _, q := range reqs {
		status, _, err := r.Target.Send(ctx, q)
		if err != nil {
			res.Outcome, res.Error = OutcomeError, "send: "+err.Error()
			return res
		}
		res.Statuses = append(res.Statuses, status)
		if status >= 200 && status < 300 {
			allFailed = false
		}
	}
	ex, err := r.Upstream.Exchanges(ctx)
	if err != nil {
		res.Outcome, res.Error = OutcomeError, "read upstream: "+err.Error()
		return res
	}
	res.Forwarded = len(ex)
	base := r.Checker
	if base == nil {
		base = leak.NewChecker(nil)
	}
	checker := base.WithSeeds([]leak.Seed{seed})
	placeholder := false
	for _, e := range ex {
		res.Findings = append(res.Findings, checker.Check(e.Capture)...)
		if ph.Match(e.Body) || ph.MatchString(e.RawQuery) || headerMatch(ph, e.Header) {
			placeholder = true
		}
	}
	// A value split across requests (server-side conversation state) is
	// only visible with the requests side by side.
	if len(res.Findings) == 0 && len(ex) > 1 {
		res.Findings = append(res.Findings, checker.Check(merged(ex))...)
	}
	switch {
	case len(res.Findings) > 0:
		res.Outcome = OutcomeLeaked
	case len(ex) == 0 && allFailed:
		res.Outcome = OutcomeWithheld
	case len(ex) == 0:
		res.Outcome = OutcomeWithheld
		res.Error = "proxy answered 2xx without forwarding anything"
	case placeholder:
		res.Outcome = OutcomeRedacted
	default:
		res.Outcome = OutcomeRepaired
	}
	res.Pass = row.Expect.Accepts(res.Outcome)
	return res
}

// merged joins the bodies of several exchanges into one JSON array.
func merged(ex []fp.Exchange) leak.Capture {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, e := range ex {
		if i > 0 {
			b.WriteByte(',')
		}
		if json.Valid(e.Body) {
			b.Write(e.Body)
		} else {
			q, _ := json.Marshal(string(e.Body))
			b.Write(q)
		}
	}
	b.WriteByte(']')
	return leak.Capture{Seq: 0, Body: b.Bytes()}
}

func headerMatch(re *regexp.Regexp, h http.Header) bool {
	for _, vs := range h {
		for _, v := range vs {
			if re.MatchString(v) {
				return true
			}
		}
	}
	return false
}

// Run runs every row for every seed, in order.
func (r *Runner) Run(ctx context.Context, rows []Row, seeds []leak.Seed) ([]Result, error) {
	var out []Result
	for _, row := range rows {
		for _, s := range seeds {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			res := r.RunRow(ctx, row, s)
			out = append(out, res)
			if r.Progress != nil {
				r.Progress(res)
			}
		}
	}
	return out, nil
}

// Totals summarises results.
type Totals struct {
	Rows        int `json:"rows"`
	Cases       int `json:"cases"`
	Passed      int `json:"passed"`
	Failed      int `json:"failed"`
	Leaked      int `json:"leaked"`
	GatedLeaks  int `json:"gated_leaks"`
	Limitations int `json:"limitation_leaks"`
	Errors      int `json:"errors"`
	// ByOutcome counts results per observed outcome.
	ByOutcome map[Outcome]int `json:"by_outcome"`
}

// Tally summarises results.
func Tally(results []Result) Totals {
	t := Totals{ByOutcome: map[Outcome]int{}}
	rows := map[string]bool{}
	for _, r := range results {
		rows[r.Row] = true
		t.Cases++
		t.ByOutcome[r.Outcome]++
		if r.Pass {
			t.Passed++
		} else {
			t.Failed++
		}
		if r.Outcome == OutcomeLeaked {
			t.Leaked++
			if r.Expect == Limitation {
				t.Limitations++
			} else {
				t.GatedLeaks++
			}
		}
		if r.Outcome == OutcomeError {
			t.Errors++
		}
	}
	t.Rows = len(rows)
	return t
}

// Describe renders a failing result for a log line, without any value.
func (r Result) Describe() string {
	s := fmt.Sprintf("%s seed=%s expect=%s got=%s statuses=%v forwarded=%d", r.Row, r.Seed.Name+"#"+r.Seed.SHA256, r.Expect, r.Outcome, r.Statuses, r.Forwarded)
	if r.Error != "" {
		s += " error=" + r.Error
	}
	for _, f := range r.Findings {
		enc := ""
		if len(f.Encodings) > 0 {
			enc = f.Encodings[0]
		}
		s += fmt.Sprintf("\n    found in request %d at %s via %s (%s, %d/%d bytes)", f.Request, f.Location, enc, f.Match, f.Matched, f.Of)
	}
	return s
}
