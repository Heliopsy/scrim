// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// Upstream is the fake provider as the runner sees it.
type Upstream interface {
	Reset(ctx context.Context) error
	Exchanges(ctx context.Context) ([]fp.Exchange, error)
	// FilesURL is where the fake serves the files it holds (ending in
	// fp.FilesPath), empty when unknown.
	FilesURL() string
	// Attach holds a file at the fake provider until the next Reset.
	Attach(ctx context.Context, f fp.File) error
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

// Send sends one request through the proxy and returns status and body. A
// WebSocket request is sent as described at [Target.sendWS].
func (t Target) Send(ctx context.Context, r Request) (int, []byte, error) {
	if r.WS {
		return t.sendWS(ctx, r)
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url(r), bytes.NewReader(r.Body))
	if err != nil {
		return 0, nil, err
	}
	hr.Header = t.header(r)
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

func (t Target) url(r Request) string {
	u := strings.TrimRight(t.BaseURL, "/") + t.Prefix[r.API] + r.Path
	if len(r.Query) > 0 {
		u += "?" + r.Query.Encode()
	}
	return u
}

// header is the target's headers, then the request's, then the provider
// authentication the agent would send when neither has any.
func (t Target) header(r Request) http.Header {
	h := http.Header{}
	for k, vs := range t.Header {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	for k, vs := range r.Header {
		h[k] = vs
	}
	if h.Get("Authorization") == "" && h.Get("X-Api-Key") == "" && h.Get("X-Goog-Api-Key") == "" {
		switch r.API {
		case fp.Anthropic:
			h.Set("X-Api-Key", "fake-provider-key-not-a-seed")
		case fp.Gemini:
			h.Set("X-Goog-Api-Key", "fake-provider-key-not-a-seed")
		default:
			h.Set("Authorization", "Bearer fake-provider-key-not-a-seed")
		}
	}
	return h
}

// WebSocket timing: a whole conversation, and how long to wait for the
// proxy to close the socket after an error event.
const (
	wsTimeout    = 5 * time.Second
	wsErrorGrace = time.Second
)

// wsClient dials WebSocket handshakes; its own pool, no timeout (the
// conversation's context bounds it).
var wsClient = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}

// Statuses sendWS reports for a conversation that did not complete.
const (
	// StatusWSPolicyClose: the proxy closed the socket with 1008 (policy
	// violation), its refusal.
	StatusWSPolicyClose = http.StatusUnprocessableEntity
	// StatusWSTooBigClose: the proxy closed the socket with 1009 (message
	// too big).
	StatusWSTooBigClose = http.StatusRequestEntityTooLarge
	// StatusWSClosed: the socket closed with any other code before the
	// conversation completed.
	StatusWSClosed = http.StatusBadGateway
	// StatusWSTimeout: nothing completed or closed within the timeout.
	StatusWSTimeout = http.StatusGatewayTimeout
)

// sendWS plays a WebSocket conversation: it dials BaseURL + prefix + Path
// (+ Query) with the same headers an HTTP request gets, sends each message
// in order, and reads server events until every response.create has its
// response.done or response.completed, the socket closes, or the
// conversation times out (a few seconds). The status is 200 when the
// conversation completed, the HTTP status when the handshake was refused,
// [StatusWSPolicyClose] or [StatusWSTooBigClose] when the proxy closed the
// socket with 1008 or 1009, the error event's status when an error event
// was not followed by a close (422 for a scrim_error), [StatusWSClosed] for
// any other close and [StatusWSTimeout] on timeout. The body is the server
// events received, one per line.
func (t Target) sendWS(ctx context.Context, r Request) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, wsTimeout)
	defer cancel()
	opts := &websocket.DialOptions{HTTPHeader: t.header(r), HTTPClient: wsClient}
	c, resp, err := websocket.Dial(ctx, t.url(r), opts)
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			var body []byte
			if resp.Body != nil {
				body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			}
			return resp.StatusCode, body, nil
		}
		return 0, nil, err
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(64 << 20)
	want := 0
	for _, m := range r.Messages {
		if eventType(m.Data) == "response.create" {
			want++
		}
	}
	for _, m := range r.Messages {
		typ := websocket.MessageText
		if m.Binary {
			typ = websocket.MessageBinary
		}
		// A failed write means the proxy closed the socket; what it sent
		// before closing is read below.
		if c.Write(ctx, typ, m.Data) != nil {
			break
		}
	}
	var events [][]byte
	done, errStatus := 0, 0
	status := 0
	for status == 0 {
		rctx, rcancel := ctx, context.CancelFunc(func() {})
		if errStatus != 0 || want == 0 {
			rctx, rcancel = context.WithTimeout(ctx, wsErrorGrace)
		}
		_, b, err := c.Read(rctx)
		rcancel()
		if err != nil {
			switch code := websocket.CloseStatus(err); {
			case code == websocket.StatusPolicyViolation:
				status = StatusWSPolicyClose
			case code == websocket.StatusMessageTooBig:
				status = StatusWSTooBigClose
			case want == 0 && errStatus == 0 && ctx.Err() == nil:
				status = http.StatusOK
			case errStatus != 0 && (code == -1 || code == websocket.StatusNormalClosure):
				status = errStatus
			case code != -1:
				status = StatusWSClosed
			default:
				status = StatusWSTimeout
			}
			break
		}
		events = append(events, b)
		switch eventType(b) {
		case "response.done", "response.completed", "response.failed", "response.incomplete":
			if done++; done >= want {
				status = http.StatusOK
				_ = c.Close(websocket.StatusNormalClosure, "")
			}
		case "error":
			errStatus = errorEventStatus(b)
		}
	}
	return status, bytes.Join(events, []byte("\n")), nil
}

func eventType(b []byte) string {
	var ev struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(b, &ev)
	return ev.Type
}

// errorEventStatus is the status an error event stands for: 422 for scrim's
// own refusal, the event's status when it has one, else 400.
func errorEventStatus(b []byte) int {
	var ev struct {
		Status int `json:"status"`
		Error  struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &ev)
	switch {
	case ev.Error.Type == "scrim_error":
		return StatusWSPolicyClose
	case ev.Status >= 400:
		return ev.Status
	}
	return http.StatusBadRequest
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

// RunRow runs one row for one seed. An unknown-secret row ignores the seed
// and runs with a value it generates.
func (r *Runner) RunRow(ctx context.Context, row Row, seed leak.Seed) Result {
	content := ContentFor(row.Transform, seed.Value())
	if row.Unknown != nil {
		seed, content = unknownSeed(row.Unknown)
	}
	return r.run(ctx, row, seed, content)
}

func (r *Runner) run(ctx context.Context, row Row, seed leak.Seed, content Content) Result {
	res := Result{Row: row.ID, API: row.API, Placement: row.Placement.ID, Transform: row.Transform.ID, Seed: seed.Ref(), Expect: row.Expect, Note: row.Note}
	ph := r.Placeholder
	if ph == nil {
		ph = fp.DefaultPlaceholderPattern
	}
	if err := r.Upstream.Reset(ctx); err != nil {
		res.Outcome, res.Error = OutcomeError, "reset upstream: "+err.Error()
		return res
	}
	content.FilesURL = r.Upstream.FilesURL()
	reqs := row.Placement.Build(row.API, content, row.Transform.Body)
	allFailed, settle := true, false
	for _, q := range reqs {
		for _, f := range q.Files {
			if content.FilesURL == "" {
				res.Outcome, res.Error = OutcomeError, "the row references files and the fake provider's URL is unknown"
				return res
			}
			if err := r.Upstream.Attach(ctx, f); err != nil {
				res.Outcome, res.Error = OutcomeError, "attach: "+err.Error()
				return res
			}
		}
	}
	for _, q := range reqs {
		status, _, err := r.Target.Send(ctx, q)
		if err != nil {
			res.Outcome, res.Error = OutcomeError, "send: "+err.Error()
			return res
		}
		res.Statuses = append(res.Statuses, status)
		if status >= 200 && status < 300 {
			allFailed = false
		} else if q.WS {
			settle = true
		}
	}
	ex, err := r.exchanges(ctx, settle)
	if err != nil {
		res.Outcome, res.Error = OutcomeError, "read upstream: "+err.Error()
		return res
	}
	// A WebSocket handshake is checked like any request, but it forwards
	// no message: a proxy that opened the upstream socket and then refused
	// the first message has withheld the conversation.
	for _, e := range ex {
		if e.WS != "handshake" {
			res.Forwarded++
		}
	}
	base := r.Checker
	if base == nil {
		base = leak.NewChecker(nil)
	}
	checker := base.WithSeeds([]leak.Seed{seed})
	placeholder := false
	for _, e := range ex {
		res.Findings = append(res.Findings, checker.Check(e.Capture)...)
		if ph.Match(e.Body) || base64Match(ph, e.Body) || ph.MatchString(e.RawQuery) || headerMatch(ph, e.Header) {
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
	case res.Forwarded == 0 && allFailed:
		res.Outcome = OutcomeWithheld
	case res.Forwarded == 0:
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

// exchanges reads what the fake provider received. After a WebSocket
// conversation that did not complete, the proxy may still be relaying a
// message it accepted before it closed the client socket, so the read is
// repeated until the count has held for 100 ms (up to a second).
func (r *Runner) exchanges(ctx context.Context, settle bool) ([]fp.Exchange, error) {
	ex, err := r.Upstream.Exchanges(ctx)
	for i, stable := 0, 0; settle && err == nil && i < 20 && stable < 2; i++ {
		time.Sleep(50 * time.Millisecond)
		var again []fp.Exchange
		if again, err = r.Upstream.Exchanges(ctx); err == nil {
			if len(again) == len(ex) {
				stable++
			} else {
				stable = 0
			}
			ex = again
		}
	}
	return ex, err
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

// base64Runs finds base64 text long enough to hold a placeholder: a file
// attachment's data, bare or in a `data:` URL.
var base64Runs = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

// base64Match reports whether a placeholder sits inside base64 text of body,
// as it does in a text document the proxy redacted and encoded again.
func base64Match(re *regexp.Regexp, body []byte) bool {
	for _, run := range base64Runs.FindAll(body, -1) {
		if d, err := base64.StdEncoding.DecodeString(string(run)); err == nil && re.Match(d) {
			return true
		}
	}
	return false
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
		if row.Unknown != nil {
			// One run: the value is generated, not taken from the seeds.
			seeds := seeds[:min(1, len(seeds))]
			if len(seeds) == 0 {
				seeds = []leak.Seed{{}}
			}
			for _, s := range seeds {
				res := r.RunRow(ctx, row, s)
				out = append(out, res)
				if r.Progress != nil {
					r.Progress(res)
				}
			}
			continue
		}
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
