// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/run"
	"github.com/heliopsy/scrim/internal/secret"
)

// placeholderRE is the generated placeholder grammar (design D3).
var placeholderRE = regexp.MustCompile(`⟦scrim:[^⟧\s]{1,200}⟧`)

// markerRE finds the seeded values the agent put into a request: a marker
// naming the set and index, then whatever the provider received in place of
// the value.
var markerRE = regexp.MustCompile(`\[\[([bnc])(\d+)\]\] (\S+)`)

// session is one minted `scrim run` session.
type session struct {
	id    string
	token string
	tools []*http.Client // forward proxy client per replica
}

// driver is the load generator: agents, fake provider and fake tool API.
type driver struct {
	plan  Plan
	p     RunParams
	bulk  [][]byte
	notes [][]byte
	creds [][]byte
	appr  [][]byte
	scan  *scanner

	sessions []*session
	llm      []*http.Client
	admin    *http.Client
	caPEM    []byte

	pending sync.Map // catalog name -> chan string (approval id)
	timing  sync.Map // request id -> *upstreamTiming

	measuring   atomic.Bool
	activeLLM   atomic.Int64
	streamGauge recorder

	m metrics
}

type upstreamTiming struct {
	recv, firstWrite, end time.Time
}

// metrics are the counters and latencies the driver reports.
type metrics struct {
	llmOK, llmErr, toolOK, toolErr, apprOK, apprErr atomic.Int64
	chunks, reqBytes                                atomic.Int64
	leaksProvider, leaksTool, leaksAgent            atomic.Int64
	unredactedMarkers                               atomic.Int64
	restoreOK, restoreFail                          atomic.Int64
	injectOK, injectFail                            atomic.Int64
	held, released, approvedN, deniedN, notHeld     atomic.Int64
	apprTimeout, apprLate, revoked, revokeFail      atomic.Int64
	crossReplica                                    atomic.Int64

	requestAdded, ttfbAdded, totalAdded, clientTotal recorder
	toolLatency, releaseLag                          recorder

	mu      sync.Mutex
	samples map[string][]string // first few failure descriptions per kind
}

func (m *metrics) note(kind, format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.samples == nil {
		m.samples = map[string][]string{}
	}
	if len(m.samples[kind]) < 5 {
		m.samples[kind] = append(m.samples[kind], fmt.Sprintf(format, args...))
	}
}

func driveMain(args []string) error {
	fs := flag.NewFlagSet("drive", flag.ContinueOnError)
	planPath := fs.String("plan", "", "plan.json written by scrim-load run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := os.ReadFile(*planPath)
	if err != nil {
		return err
	}
	var plan Plan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	d := &driver{plan: plan, p: plan.Run}
	if path := os.Getenv("SCRIM_LOAD_CPUPROFILE"); path != "" {
		f, err := os.Create(path) //nolint:gosec // a path the operator names
		if err != nil {
			return err
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}
	return d.run()
}

func readSet(dir, prefix string, n int) ([][]byte, error) {
	out := make([][]byte, n)
	for i := range n {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%s%d", prefix, i))) //nolint:gosec // the run's own seed files
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func (d *driver) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error
	sd := d.plan.SeedsDir
	if d.bulk, err = readSet(filepath.Join(sd, "bulk"), "b", d.p.BulkSecrets); err != nil {
		return err
	}
	if d.notes, err = readSet(filepath.Join(sd, "notes"), "n", d.p.Notes); err != nil {
		return err
	}
	if d.creds, err = readSet(filepath.Join(sd, "creds"), "c", d.p.Creds); err != nil {
		return err
	}
	if d.appr, err = readSet(filepath.Join(sd, "approve"), "a", d.p.ApprovalWorkers); err != nil {
		return err
	}

	if err := d.startFakes(); err != nil {
		return err
	}
	d.admin = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 32}}
	if d.caPEM, err = d.fetchCA(ctx); err != nil {
		return err
	}
	for range d.plan.Replicas {
		d.llm = append(d.llm, &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
			MaxIdleConnsPerHost: d.p.Streams + 16, MaxConnsPerHost: 0, IdleConnTimeout: time.Minute,
			DisableCompression: true,
		}})
	}
	if err := d.mintSessions(ctx); err != nil {
		return err
	}
	all := [][]byte{}
	all = append(all, d.bulk...)
	all = append(all, d.notes...)
	all = append(all, d.creds...)
	all = append(all, d.appr...)
	seeded := len(all)
	for _, s := range d.sessions {
		all = append(all, []byte(s.token))
	}
	all = append(all, []byte(d.plan.AdminToken))
	d.scan = newScanner(all, seeded)
	logf("drive: %d replicas, %d streams, %d sessions, %d approval workers, %d+%d+%d+%d seeded values",
		len(d.plan.Replicas), d.p.Streams, len(d.sessions), d.p.ApprovalWorkers, len(d.bulk), len(d.notes), len(d.creds), len(d.appr))

	// Every replica must deliver what another committed before the clock starts.
	before, err := d.scrapeAll(ctx)
	if err != nil {
		return err
	}
	_ = before

	start := time.Now()
	windowStart := start.Add(d.p.Warmup.D())
	windowEnd := windowStart.Add(d.p.Duration.D())
	runCtx, stop := context.WithDeadline(ctx, windowEnd)
	defer stop()

	var wg sync.WaitGroup
	for w := range d.p.Streams {
		wg.Go(func() {
			// Stagger the start over the warm-up so the first wave does
			// not arrive as one burst.
			if d.p.Warmup.D() > 0 {
				delay := time.Duration(int64(d.p.Warmup.D()) * int64(w) / int64(d.p.Streams) / 2)
				select {
				case <-time.After(delay):
				case <-runCtx.Done():
					return
				}
			}
			d.agent(runCtx, w)
		})
	}
	for w := range d.p.ApprovalWorkers {
		wg.Go(func() { d.approvals(runCtx, w) })
	}
	wg.Go(func() { d.pollApprovals(runCtx) })
	wg.Go(func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
				if d.measuring.Load() {
					d.streamGauge.add(time.Duration(d.activeLLM.Load()) * time.Millisecond)
				}
			}
		}
	})

	time.Sleep(time.Until(windowStart))
	scrapeStart, err := d.scrapeAll(ctx)
	if err != nil {
		return err
	}
	d.measuring.Store(true)
	measuredFrom := time.Now()
	<-runCtx.Done()
	d.measuring.Store(false)
	measuredFor := time.Since(measuredFrom)
	scrapeEnd, err := d.scrapeAll(ctx)
	if err != nil {
		return err
	}
	wg.Wait()

	// Agreement: once traffic stops every replica has delivered the same
	// outbox. Give the last hints a moment to arrive.
	var lastIDs []float64
	agree := false
	for range 50 {
		lastIDs = lastIDs[:0]
		sc, err := d.scrapeAll(ctx)
		if err == nil {
			for _, s := range sc {
				v, _ := gaugeOf(s, "scrim_events_last_id", nil)
				lastIDs = append(lastIDs, v)
			}
			agree = len(lastIDs) > 0
			for _, v := range lastIDs {
				agree = agree && v == lastIDs[0] && v > 0
			}
			if agree {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	res := d.result(measuredFor, scrapeStart, scrapeEnd, lastIDs, agree, measuredFrom)
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.plan.ResultFile, append(b, '\n'), 0o600)
}

func (d *driver) fetchCA(ctx context.Context) ([]byte, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.plan.Replicas[0].Admin+"/v1/ca", nil)
		resp, err := d.admin.Do(req)
		if err == nil {
			b, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if rerr == nil && resp.StatusCode == http.StatusOK {
				return b, nil
			}
			err = fmt.Errorf("GET /v1/ca: %d", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// mintSessions mints the sessions the way `scrim run` does, spread over the
// replicas: every replica must accept sessions minted through another.
func (d *driver) mintSessions(ctx context.Context) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(d.caPEM) {
		return errors.New("no CA certificate from the admin API")
	}
	for i := range d.p.Sessions {
		rep := d.plan.Replicas[i%len(d.plan.Replicas)]
		c := localapi.NewClient(rep.APISocket, secret.Value{})
		m, err := c.Mint(ctx, localapi.MintInput{Name: fmt.Sprintf("load-%d", i), TTLSeconds: 4 * 3600})
		c.Close()
		if err != nil {
			return fmt.Errorf("minting session %d through %s: %w", i, rep.Name, err)
		}
		s := &session{id: m.Session.ID}
		_ = m.Token.Expose(func(b []byte) error { s.token = string(b); return nil })
		m.Token.Wipe()
		for _, r := range d.plan.Replicas {
			pu := &url.URL{Scheme: "http", User: url.UserPassword(s.id, s.token), Host: r.Forward}
			s.tools = append(s.tools, &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{
				Proxy:               http.ProxyURL(pu),
				TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
				MaxIdleConnsPerHost: 64, IdleConnTimeout: time.Minute,
			}})
		}
		d.sessions = append(d.sessions, s)
	}
	return nil
}

// ---------------------------------------------------------------- agents

var filler = strings.Fields(`func handler request response context error return value config secret
store policy grant approval stream chunk token placeholder provider tool proxy replica event outbox
index buffer bytes reader writer server client upstream retry timeout deadline cancel select channel`)

// buildBody writes an Anthropic Messages request of about kb kilobytes in
// which the given seeded values appear behind their markers.
func buildBody(rng *rand.Rand, kb int, inserts []string) []byte {
	var text strings.Builder
	target := kb * 1024
	slot := target / (len(inserts) + 1)
	next := slot
	k := 0
	for text.Len() < target {
		if k < len(inserts) && text.Len() >= next {
			text.WriteString("\n")
			text.WriteString(inserts[k])
			text.WriteString("\n")
			k++
			next += slot
		}
		text.WriteString(filler[rng.IntN(len(filler))])
		if rng.IntN(12) == 0 {
			text.WriteString("\n")
		} else {
			text.WriteByte(' ')
		}
	}
	for ; k < len(inserts); k++ {
		text.WriteString("\n" + inserts[k] + "\n")
	}
	body := map[string]any{
		"model": "claude-sonnet-4-5", "max_tokens": 4096, "stream": true,
		"system": "You are a coding agent working in a repository. Use the tools.",
		"tools": []any{map[string]any{
			"name": "Bash", "description": "Run a shell command",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}, "required": []string{"command"}},
		}},
		"messages": []any{
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": text.String()}}},
		},
	}
	b, _ := json.Marshal(body)
	return b
}

// newRand is the generator that shapes the load (which values a request
// carries, request ids); it has nothing to do with the seeded values.
func newRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, uint64(time.Now().UnixNano()))) //nolint:gosec // load shape, not security
}

// agent is one simulated agent: a streamed provider turn, then the tool
// call the model asked for, again and again, each request through the next
// replica as a round-robin load balancer would send it.
func (d *driver) agent(ctx context.Context, w int) {
	rng := newRand(uint64(w))
	s := d.sessions[w%len(d.sessions)]
	cred := w % len(d.creds)
	rr := w
	for ctx.Err() == nil {
		rr++
		ph, ok := d.llmTurn(ctx, rng, s, rr%len(d.plan.Replicas), w, cred)
		if ctx.Err() != nil {
			return
		}
		if ok && ph != "" {
			rr++
			d.toolCall(ctx, s, rr%len(d.plan.Replicas), w, cred, ph)
		}
		if d.p.ThinkTime.D() > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(d.p.ThinkTime.D()):
			}
		}
	}
}

// llmTurn sends one streamed provider request and checks the reply. It
// returns the credential placeholder the model's tool call carries.
func (d *driver) llmTurn(ctx context.Context, rng *rand.Rand, s *session, replica, w, cred int) (string, bool) {
	var inserts []string
	var bulk []int
	for range d.p.SecretsPerRequest {
		i := rng.IntN(len(d.bulk))
		bulk = append(bulk, i)
		inserts = append(inserts, fmt.Sprintf("[[b%d]] %s", i, d.bulk[i]))
	}
	// An encoded copy of one value: the redactor matches encoded variants.
	enc := bulk[0]
	inserts = append(inserts, fmt.Sprintf("export TOKEN_B64=%s", base64.StdEncoding.EncodeToString(d.bulk[enc])))
	note := rng.IntN(len(d.notes))
	inserts = append(inserts, fmt.Sprintf("[[n%d]] %s", note, d.notes[note]))
	inserts = append(inserts, fmt.Sprintf("[[c%d]] %s", cred, d.creds[cred]))
	body := buildBody(rng, d.p.BodyKB, inserts)

	id := fmt.Sprintf("w%d-%d", w, rng.Uint64())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.plan.Replicas[replica].LLM+"/anthropic/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "agent-own-provider-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set(run.SessionHeader, s.token)
	req.Header.Set("x-load-id", id)

	d.activeLLM.Add(1)
	defer d.activeLLM.Add(-1)
	t0 := time.Now()
	resp, err := d.llm[replica].Do(req)
	if err != nil {
		if ctx.Err() == nil {
			d.countLLM(false)
			d.m.note("llm", "%s: %v", d.plan.Replicas[replica].Name, err)
		}
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		d.countLLM(false)
		d.m.note("llm", "%s: status %d %s %s", d.plan.Replicas[replica].Name, resp.StatusCode, resp.Header.Get("x-scrim-error"), b)
		return "", false
	}
	var text, args strings.Builder
	var firstByte time.Time
	chunks := 0
	br := bufio.NewReaderSize(resp.Body, 16*1024)
	for {
		line, err := br.ReadString('\n')
		if firstByte.IsZero() && len(line) > 0 {
			firstByte = time.Now()
		}
		if data, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "data: "); ok {
			chunks++
			if !strings.Contains(data, `"content_block_delta"`) {
				continue
			}
			var ev struct {
				Type  string `json:"type"`
				Delta struct {
					Type        string `json:"type"`
					Text        string `json:"text"`
					PartialJSON string `json:"partial_json"`
				} `json:"delta"`
			}
			if json.Unmarshal([]byte(data), &ev) == nil && ev.Type == "content_block_delta" {
				text.WriteString(ev.Delta.Text)
				args.WriteString(ev.Delta.PartialJSON)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				if ctx.Err() == nil {
					d.countLLM(false)
					d.m.note("llm", "%s: reading the stream: %v", d.plan.Replicas[replica].Name, err)
				}
				return "", false
			}
			break
		}
	}
	end := time.Now()
	ut := d.takeTiming(id)

	measuring := d.measuring.Load()
	if measuring {
		d.m.chunks.Add(int64(chunks))
		d.m.reqBytes.Add(int64(len(body)))
		d.m.clientTotal.add(end.Sub(t0))
		if ut != nil {
			d.m.requestAdded.add(ut.recv.Sub(t0))
			if !firstByte.IsZero() {
				d.m.ttfbAdded.add(firstByte.Sub(ut.firstWrite))
			}
			d.m.totalAdded.add(end.Sub(t0) - ut.end.Sub(ut.recv))
		}
	}

	// Restore: display values come back as values, credentials stay
	// placeholders, in text and in the tool call alike.
	got := text.String()
	ok := true
	check := func(cond bool, format string, a ...any) {
		if cond {
			d.m.restoreOK.Add(1)
			return
		}
		ok = false
		d.m.restoreFail.Add(1)
		d.m.note("restore", format, a...)
	}
	check(strings.Contains(got, fmt.Sprintf("[[n%d]] %s", note, d.notes[note])), "display value n%d not restored in assistant text", note)
	for _, i := range bulk[:min(3, len(bulk))] {
		marker := fmt.Sprintf("[[b%d]] ", i)
		check(strings.Contains(got, marker+"⟦scrim:") && !bytes.Contains([]byte(got), d.bulk[i]), "credential b%d not left as a placeholder in assistant text", i)
	}
	var input struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal([]byte(args.String()), &input)
	ph := placeholderRE.FindString(input.Command)
	check(ph != "" && !strings.Contains(input.Command, string(d.creds[cred])), "credential c%d restored into a shell command or missing", cred)
	if hits := d.scan.find([]byte(got + args.String())); len(hits) > 0 {
		for _, h := range hits {
			if h >= len(d.bulk) && h < len(d.bulk)+len(d.notes) {
				continue // display values are meant to come back
			}
			d.m.leaksAgent.Add(1)
			d.m.note("leak", "a credential reached the agent in a provider reply")
		}
	}
	d.countLLM(true)
	return ph, ok
}

func (d *driver) countLLM(ok bool) {
	if !d.measuring.Load() {
		return
	}
	if ok {
		d.m.llmOK.Add(1)
	} else {
		d.m.llmErr.Add(1)
	}
}

func (d *driver) takeTiming(id string) *upstreamTiming {
	v, ok := d.timing.LoadAndDelete(id)
	if !ok {
		return nil
	}
	return v.(*upstreamTiming)
}

// toolCall runs the model's tool call: an HTTPS request through the forward
// proxy carrying the credential's placeholder, which scrim must replace with
// the value toward the bound host and put back in the echoed response.
func (d *driver) toolCall(ctx context.Context, s *session, replica, w, cred int, ph string) {
	u := fmt.Sprintf("https://%s/v1/items/%d", d.plan.ToolAddr, w)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+ph)
	req.Header.Set("x-load-cred", fmt.Sprintf("c%d", cred))
	t0 := time.Now()
	resp, err := s.tools[replica].Do(req)
	if err != nil {
		if ctx.Err() == nil {
			d.countTool(false)
			d.m.note("tool", "%s: %v", d.plan.Replicas[replica].Name, err)
		}
		return
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		d.countTool(false)
		d.m.note("tool", "%s: status %d %s %s", d.plan.Replicas[replica].Name, resp.StatusCode, resp.Header.Get("x-scrim-error"), b)
		return
	}
	if d.measuring.Load() {
		d.m.toolLatency.add(time.Since(t0))
	}
	// The API echoed what it received: the agent must see its placeholder.
	if !bytes.Contains(b, []byte(ph)) || bytes.Contains(b, d.creds[cred]) {
		d.m.leaksAgent.Add(1)
		d.m.note("leak", "tool response not redacted back to the placeholder (%d bytes)", len(b))
	}
	d.countTool(true)
}

func (d *driver) countTool(ok bool) {
	if !d.measuring.Load() {
		return
	}
	if ok {
		d.m.toolOK.Add(1)
	} else {
		d.m.toolErr.Add(1)
	}
}

// ---------------------------------------------------------------- approvals

type approvalView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// pollApprovals lists pending approvals through the replicas in turn and
// hands each to the worker waiting for its credential (catalog name).
func (d *driver) pollApprovals(ctx context.Context) {
	t := time.NewTicker(25 * time.Millisecond)
	defer t.Stop()
	seen := map[string]bool{}
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var list []approvalView
		if err := d.adminJSON(ctx, i%len(d.plan.Replicas), http.MethodGet, "/v1/approvals?status=pending", &list); err != nil {
			continue
		}
		for _, a := range list {
			if seen[a.ID] {
				continue
			}
			if ch, ok := d.pending.Load(a.Name); ok {
				seen[a.ID] = true
				select {
				case ch.(chan string) <- a.ID:
				default:
				}
			}
		}
	}
}

func (d *driver) adminJSON(ctx context.Context, replica int, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, d.plan.Replicas[replica].Admin+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.plan.AdminToken)
	resp, err := d.admin.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s on %s: %d %s", method, path, d.plan.Replicas[replica].Name, resp.StatusCode, b)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// approvals is one approval worker. Each round its request is held on one
// replica, decided through a second and, when approved, the grant it left
// is revoked through a third; the next round must be held again, so a
// revoked grant honoured anywhere shows up as a request that was not held.
func (d *driver) approvals(ctx context.Context, w int) {
	name := fmt.Sprintf("approve/A%d", w)
	ch := make(chan string, 4)
	d.pending.Store(name, ch)
	defer d.pending.Delete(name)
	s := d.sessions[w%len(d.sessions)]
	n := len(d.plan.Replicas)
	for round := 0; ctx.Err() == nil; round++ {
		if round > 0 && d.p.ApprovalInterval.D() > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(d.p.ApprovalInterval.D()):
			}
		}
		k := w + round
		hold, decide, revoke := k%n, (k+1)%n, (k+2)%n
		approve := round%4 != 3
		type outcome struct {
			status int
			code   string
			at     time.Time
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/v1/approve/%d", d.plan.ToolAddr, w), nil)
			req.Header.Set("Authorization", "Bearer "+approvePlaceholder(w))
			req.Header.Set("x-load-cred", fmt.Sprintf("a%d", w))
			resp, err := s.tools[hold].Do(req)
			if err != nil {
				done <- outcome{err: err, at: time.Now()}
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			done <- outcome{status: resp.StatusCode, code: resp.Header.Get("x-scrim-error"), at: time.Now()}
		}()
		var id string
		select {
		case <-ctx.Done():
			<-done
			return
		case o := <-done:
			if ctx.Err() != nil {
				return
			}
			d.m.notHeld.Add(1)
			d.m.note("approval", "round %d of worker %d answered %d %s before any approval was pending (a revoked grant was honoured?) %v", round, w, o.status, o.code, o.err)
			continue
		case id = <-ch:
		}
		d.m.held.Add(1)
		var dec struct {
			GrantID string `json:"grant_id"`
		}
		action := "approve"
		if !approve {
			action = "deny"
		}
		if err := d.adminJSON(ctx, decide, http.MethodPost, "/v1/approvals/"+id+"/"+action, &dec); err != nil {
			if ctx.Err() == nil {
				d.m.apprErr.Add(1)
				d.m.note("approval", "deciding through %s: %v", d.plan.Replicas[decide].Name, err)
			}
			<-done
			continue
		}
		decided := time.Now()
		var o outcome
		select {
		case o = <-done:
		case <-time.After(45 * time.Second):
			d.m.apprTimeout.Add(1)
			d.m.note("approval", "request held on %s not released 45s after the decision on %s", d.plan.Replicas[hold].Name, d.plan.Replicas[decide].Name)
			<-done
			continue
		}
		if ctx.Err() != nil {
			return
		}
		lag := o.at.Sub(decided)
		switch {
		case o.err == nil && lag > releaseBound:
			// Released, but not by the decision: the ask timed out (a deny
			// looks the same) or a poll found it.
			d.m.apprLate.Add(1)
			d.m.note("approval", "held on %s, %sd on %s: released only after %s (%d %s)", d.plan.Replicas[hold].Name, action, d.plan.Replicas[decide].Name, lag.Round(time.Millisecond), o.status, o.code)
		case o.err != nil:
			d.m.apprErr.Add(1)
			d.m.note("approval", "held request on %s: %v", d.plan.Replicas[hold].Name, o.err)
		case approve && o.status == http.StatusOK, !approve && o.status == http.StatusForbidden && o.code == "policy_denied":
			d.m.released.Add(1)
			d.m.crossReplica.Add(1)
			if d.measuring.Load() {
				d.m.releaseLag.add(lag)
				d.m.apprOK.Add(1)
			}
			if approve {
				d.m.approvedN.Add(1)
			} else {
				d.m.deniedN.Add(1)
			}
		default:
			d.m.apprErr.Add(1)
			d.m.note("approval", "held on %s, %sd on %s: got %d %s after %s", d.plan.Replicas[hold].Name, action, d.plan.Replicas[decide].Name, o.status, o.code, lag)
		}
		if approve && dec.GrantID != "" {
			if err := d.adminJSON(ctx, revoke, http.MethodPost, "/v1/grants/"+dec.GrantID+"/revoke", nil); err != nil {
				if ctx.Err() == nil {
					d.m.revokeFail.Add(1)
					d.m.note("approval", "revoking through %s: %v", d.plan.Replicas[revoke].Name, err)
				}
				continue
			}
			d.m.revoked.Add(1)
		}
	}
}

// releaseBound is how soon after its decision a held request must come
// back. Events deliver in milliseconds; the polls that could also release
// it run every 50 s and the ask itself times out after 40 s.
const releaseBound = 10 * time.Second

// approvePlaceholder is the declared placeholder of approval credential w
// (catalog entry approve, template SCRIM_LOADAPPROVE_{NAME}).
func approvePlaceholder(w int) string { return fmt.Sprintf("SCRIM_LOADAPPROVE_A%d", w) }

// ---------------------------------------------------------------- fakes

func (d *driver) startFakes() error {
	pln, err := net.Listen("tcp", d.plan.ProviderAddr)
	if err != nil {
		return fmt.Errorf("fake provider: %w", err)
	}
	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(d.provider), ReadHeaderTimeout: 10 * time.Second}
		_ = srv.Serve(pln)
	}()
	cert, err := tls.LoadX509KeyPair(d.plan.ToolCertFile, d.plan.ToolKeyFile)
	if err != nil {
		return err
	}
	tln, err := net.Listen("tcp", d.plan.ToolAddr)
	if err != nil {
		return fmt.Errorf("fake tool API: %w", err)
	}
	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(d.tool), ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		_ = srv.ServeTLS(tln, "", "")
	}()
	return nil
}

// provider is the fake Anthropic Messages endpoint. It checks every byte it
// received for seeded values, learns the placeholders that replaced them
// and streams a reply that uses them, paced like a model.
func (d *driver) provider(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	recv := time.Now()
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	var hdr bytes.Buffer
	hdr.WriteString(r.URL.String())
	_ = r.Header.Write(&hdr)
	if hits := append(d.scan.find(body), d.scan.find(hdr.Bytes())...); len(hits) > 0 {
		d.m.leaksProvider.Add(int64(len(hits)))
		d.m.note("leak", "the provider received %d seeded value(s), first #%d", len(hits), hits[0])
	}
	// Learn the placeholders; a marker followed by anything else means
	// the value went through unredacted (the scanner counts it as a leak).
	ph := map[string]string{}
	for _, m := range markerRE.FindAllSubmatch(body, -1) {
		v := string(m[3])
		if p := placeholderRE.FindString(v); p != "" && strings.HasPrefix(v, p) {
			ph[string(m[1])+string(m[2])] = p
		} else {
			d.m.unredactedMarkers.Add(1)
		}
	}
	var text strings.Builder
	text.WriteString("I looked at the workspace. ")
	var cmd string
	for _, m := range markerRE.FindAllSubmatch(body, -1) {
		key := string(m[1]) + string(m[2])
		p, ok := ph[key]
		if !ok {
			continue
		}
		switch m[1][0] {
		case 'n':
			fmt.Fprintf(&text, "The note [[%s]] %s is current. ", key, p)
		case 'b':
			if strings.Count(text.String(), "[[b") < 3 {
				fmt.Fprintf(&text, "Rotate [[%s]] %s soon. ", key, p)
			}
		case 'c':
			cmd = fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' https://%s/v1/items", p, d.plan.ToolAddr)
		}
	}
	for i := 0; text.Len() < d.p.ReplyRunes; i++ {
		text.WriteString(filler[i%len(filler)])
		text.WriteByte(' ')
	}
	text.WriteString("Next I will call the API with the stored credential to list the items.")
	input, _ := json.Marshal(map[string]string{"command": cmd})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	ut := &upstreamTiming{recv: recv}
	event := func(name string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b); err != nil {
			return false
		}
		if fl != nil {
			fl.Flush()
		}
		return true
	}
	// One ticker per stream paces the deltas like a model's output.
	var tick <-chan time.Time
	if d.p.ChunkInterval.D() > 0 {
		t := time.NewTicker(d.p.ChunkInterval.D())
		defer t.Stop()
		tick = t.C
	}
	pace := func() bool {
		if tick == nil {
			return true
		}
		select {
		case <-r.Context().Done():
			return false
		case <-tick:
			return true
		}
	}
	// Deltas are written from templates: they are most of what the fake
	// sends, and marshalling a map per event would make the load
	// generator, not scrim, the bottleneck.
	buf := make([]byte, 0, 256)
	delta := func(index int, kind, field, piece string) bool {
		q, _ := json.Marshal(piece)
		buf = append(buf[:0], `event: content_block_delta
data: {"type":"content_block_delta","index":`...)
		buf = strconv.AppendInt(buf, int64(index), 10)
		buf = append(buf, `,"delta":{"type":"`...)
		buf = append(buf, kind...)
		buf = append(buf, `","`...)
		buf = append(buf, field...)
		buf = append(buf, `":`...)
		buf = append(buf, q...)
		buf = append(buf, "}}\n\n"...)
		if _, err := w.Write(buf); err != nil {
			return false
		}
		if fl != nil {
			fl.Flush()
		}
		return true
	}
	defer func() {
		ut.end = time.Now()
		if id := r.Header.Get("x-load-id"); id != "" {
			d.timing.Store(id, ut)
		}
	}()
	if !event("message_start", map[string]any{"type": "message_start", "message": map[string]any{
		"id": "msg_load", "type": "message", "role": "assistant", "model": "claude-sonnet-4-5", "content": []any{},
		"stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": len(body) / 4, "output_tokens": 1},
	}}) {
		return
	}
	ut.firstWrite = time.Now()
	event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
	for _, p := range pieces(text.String(), d.p.ChunkRunes) {
		if !pace() || !delta(0, "text_delta", "text", p) {
			return
		}
	}
	event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	event("content_block_start", map[string]any{"type": "content_block_start", "index": 1, "content_block": map[string]any{"type": "tool_use", "id": "toolu_load", "name": "Bash", "input": map[string]any{}}})
	for _, p := range pieces(string(input), d.p.ChunkRunes) {
		if !pace() || !delta(1, "input_json_delta", "partial_json", p) {
			return
		}
	}
	event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 1})
	event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "tool_use", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": text.Len() / 4}})
	event("message_stop", map[string]any{"type": "message_stop"})
}

func pieces(s string, n int) []string {
	r := []rune(s)
	var out []string
	for i := 0; i < len(r); i += n {
		out = append(out, string(r[i:min(i+n, len(r))]))
	}
	return out
}

// tool is the fake HTTPS tool API: it checks that the credential it was
// meant to get arrived, and echoes the Authorization header back the way
// some APIs do in their errors.
func (d *driver) tool(w http.ResponseWriter, r *http.Request) {
	var hdr bytes.Buffer
	_ = r.Header.Write(&hdr)
	// The session token and the admin token are seeded too; the tool API
	// must see neither. Its own credential is the only value allowed.
	want := d.expected(r.Header.Get("x-load-cred"))
	for _, h := range d.scan.find(hdr.Bytes()) {
		if want == nil || !bytes.Equal(d.valueAt(h), want) {
			d.m.leaksTool.Add(1)
			d.m.note("leak", "the tool API received a seeded value it is not bound to (#%d)", h)
		}
	}
	auth := r.Header.Get("Authorization")
	if want == nil || auth != "Bearer "+string(want) {
		d.m.injectFail.Add(1)
		shown := auth
		if placeholderRE.MatchString(auth) || strings.Contains(auth, "SCRIM_") {
			shown = "a placeholder"
		} else if auth != "" {
			shown = "another value"
		}
		d.m.note("inject", "%s %s for %s received %s", r.Method, r.URL.Path, r.Header.Get("x-load-cred"), shown)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"bad credential"}`)
		return
	}
	d.m.injectOK.Add(1)
	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(map[string]string{"ok": "true", "echo": auth})
	_, _ = w.Write(resp)
}

func (d *driver) expected(tag string) []byte {
	if len(tag) < 2 {
		return nil
	}
	i, err := strconv.Atoi(tag[1:])
	if err != nil || i < 0 {
		return nil
	}
	switch tag[0] {
	case 'c':
		if i < len(d.creds) {
			return d.creds[i]
		}
	case 'a':
		if i < len(d.appr) {
			return d.appr[i]
		}
	}
	return nil
}

func (d *driver) valueAt(i int) []byte {
	for _, set := range [][][]byte{d.bulk, d.notes, d.creds, d.appr} {
		if i < len(set) {
			return set[i]
		}
		i -= len(set)
	}
	return nil
}

// ---------------------------------------------------------------- metrics

func (d *driver) scrapeAll(ctx context.Context) ([][]promSample, error) {
	out := make([][]promSample, len(d.plan.Replicas))
	for i, r := range d.plan.Replicas {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Metrics+"/metrics", nil)
		if err != nil {
			return nil, err
		}
		resp, err := d.admin.Do(req)
		if err != nil {
			return nil, fmt.Errorf("scraping %s: %w", r.Name, err)
		}
		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("scraping %s: %w", r.Name, err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("scraping %s: status %d", r.Name, resp.StatusCode)
		}
		out[i] = parseProm(string(b))
	}
	return out, nil
}
