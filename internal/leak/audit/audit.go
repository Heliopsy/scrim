// SPDX-License-Identifier: AGPL-3.0-only

// Package audit runs the leak suite end to end, as `scrim audit run` does:
// it starts the fake provider, seeds generated secrets, starts or reaches the
// proxy under test, runs the bypass matrix and the scenario corpus through
// it, and writes a JSON report. A run passes only with zero gated leaks,
// every matrix row at its expected outcome, and stable prompt caching.
package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	"github.com/heliopsy/scrim/internal/leak/scenario"
	"github.com/heliopsy/scrim/internal/leak/stub"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// Built-in stand-in proxies for validating the suite itself.
const (
	BuiltinPassThrough = "builtin:passthrough"
	BuiltinNaive       = "builtin:naive"
)

// Suites.
const (
	SuiteMatrix    = "matrix"
	SuiteScenarios = "scenarios"
)

// Options configure a run.
type Options struct {
	// Proxy is the base URL of the proxy under test, or a builtin stand-in.
	Proxy string
	// ProxyCmd, when set, is started before the run and stopped after. It
	// gets SCRIM_LEAK_UPSTREAM (the fake provider URL), SCRIM_LEAK_SEEDS
	// (the seed file) and SCRIM_LEAK_LISTEN (host:port of Proxy) in its
	// environment, and must listen on Proxy's address.
	ProxyCmd []string
	// ProxyStartTimeout bounds waiting for ProxyCmd to listen.
	ProxyStartTimeout time.Duration
	// UpstreamListen is where the fake provider listens, so an externally
	// configured proxy can point at it. Default 127.0.0.1:0.
	UpstreamListen string
	// UpstreamListener, when set, is where the fake provider serves, in
	// place of UpstreamListen. A caller that must name the address before
	// the run binds it first and passes it here, so no other process can
	// take the port in between. The run closes it.
	UpstreamListener net.Listener
	// SeedsIn reads seeds from a file instead of generating them.
	SeedsIn string
	// SeedsOut writes the generated seeds (fake values) to a file, mode
	// 0600, for loading into the store of the proxy under test.
	SeedsOut string
	// Suites to run; default both.
	Suites []string
	// APIs to run; default all, the WebSocket ones included
	// ([fp.AllAPIs]). The scenario corpus runs on the HTTP ones only.
	APIs []fp.API
	// Rows keeps matrix rows whose ID starts with any of these prefixes.
	Rows []string
	// Prefix maps an API to the proxy's route prefix for it. A WebSocket
	// API without an entry of its own takes the openai-responses entry: both
	// are OpenAI routes.
	Prefix map[fp.API]string
	// Header is sent with every request (the agent's provider auth).
	Header http.Header
	// Placeholder matches the proxy's placeholders.
	Placeholder *regexp.Regexp
	// Checker thresholds; zero keeps defaults.
	MinPartial      int
	PartialFraction float64
	MaxPartial      int
	// Driver selects the agent for the scenarios: "synthetic" (default), a
	// built-in agent for every API, or a real agent CLI run with an empty
	// HOME against the proxy: "claude" (Claude Code, Anthropic Messages),
	// "codex" (Codex, Responses API over WebSocket) or "opencode" (OpenCode,
	// Anthropic Messages). The matrix always sends its requests directly.
	Driver string
	// AgentBin overrides the agent CLI binary.
	AgentBin string
	// Progress, when set, receives one line per finished case.
	Progress io.Writer
	// WrapUpstream, when set, wraps the fake provider before it is served,
	// for example in a cloud provider front end (fakeprovider.NewCloud)
	// that checks authentication and translates the wire format. Results
	// are still read from the fake itself.
	WrapUpstream func(*fp.Server) http.Handler
}

// ErrGate is returned when the run completed and the gate failed.
var ErrGate = errors.New("leak gate failed")

// Run executes the suite and returns the report. It returns ErrGate (with the
// report) when leaks or unexpected outcomes were found, and another error
// when the run could not complete.
func Run(ctx context.Context, o Options) (*Report, error) {
	if o.Driver != "" && o.Driver != "synthetic" && !slices.Contains(scenario.Agents, o.Driver) {
		return nil, fmt.Errorf("unknown driver %q (synthetic, %s)", o.Driver, strings.Join(scenario.Agents, ", "))
	}
	if o.Driver == "" {
		o.Driver = "synthetic"
	}
	if len(o.Suites) == 0 {
		o.Suites = []string{SuiteMatrix, SuiteScenarios}
	}
	for _, s := range o.Suites {
		if s != SuiteMatrix && s != SuiteScenarios {
			return nil, fmt.Errorf("unknown suite %q", s)
		}
	}
	if len(o.APIs) == 0 {
		o.APIs = fp.AllAPIs
	}
	if p, ok := o.Prefix[fp.OpenAIResponses]; ok {
		for _, api := range fp.WSAPIs {
			if _, set := o.Prefix[api]; !set {
				o.Prefix[api] = p
			}
		}
	}
	if o.Proxy == "" {
		return nil, errors.New("no proxy: pass --proxy URL (or builtin:passthrough / builtin:naive to test the suite itself)")
	}

	seeds, err := loadSeeds(o)
	if err != nil {
		return nil, err
	}

	fake := fp.New(fp.Options{PlaceholderPattern: o.Placeholder})
	ln := o.UpstreamListener
	if ln == nil {
		upAddr := o.UpstreamListen
		if upAddr == "" {
			upAddr = "127.0.0.1:0"
		}
		if ln, err = net.Listen("tcp", upAddr); err != nil {
			return nil, fmt.Errorf("fake provider: %w", err)
		}
	}
	var handler http.Handler = fake
	if o.WrapUpstream != nil {
		handler = o.WrapUpstream(fake)
	}
	up := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = up.Serve(ln) }()
	defer func() { _ = up.Close() }()
	upURL := "http://" + ln.Addr().String()

	proxyURL := o.Proxy
	switch o.Proxy {
	case BuiltinPassThrough, BuiltinNaive:
		u, _ := url.Parse(upURL)
		h := stub.PassThrough(u)
		if o.Proxy == BuiltinNaive {
			h = stub.Naive(u, seeds)
		}
		px := httptest.NewServer(h)
		defer px.Close()
		proxyURL = px.URL
	default:
		if len(o.ProxyCmd) > 0 {
			stop, err := startProxy(ctx, o, upURL, seeds)
			if err != nil {
				return nil, err
			}
			defer stop()
		}
	}

	checker := leak.NewChecker(seeds)
	if o.MinPartial > 0 {
		checker.MinPartial = o.MinPartial
	}
	if o.PartialFraction > 0 {
		checker.PartialFraction = o.PartialFraction
	}
	if o.MaxPartial > 0 {
		checker.MaxPartial = o.MaxPartial
	}
	target := matrix.Target{BaseURL: proxyURL, Prefix: o.Prefix, Header: o.Header}

	rep := &Report{
		Version:  1,
		Started:  time.Now().UTC(),
		Proxy:    o.Proxy,
		Upstream: upURL,
		Driver:   o.Driver,
		Checker:  CheckerSettings{MinPartial: checker.MinPartial, PartialFraction: checker.PartialFraction, MaxPartial: checker.MaxPartial},
	}
	for _, s := range seeds {
		rep.Seeds = append(rep.Seeds, s.Ref())
	}
	progress := func(format string, a ...any) {
		if o.Progress != nil {
			_, _ = fmt.Fprintf(o.Progress, format+"\n", a...)
		}
	}

	for _, suite := range o.Suites {
		switch suite {
		case SuiteMatrix:
			var rows []matrix.Row
			for _, r := range matrix.Filter(matrix.Rows(), o.Rows...) {
				for _, api := range o.APIs {
					if r.API == api {
						rows = append(rows, r)
					}
				}
			}
			mr := &matrix.Runner{Target: target, Upstream: matrix.LocalUpstream{Server: fake}, Checker: checker, Placeholder: o.Placeholder,
				Progress: func(r matrix.Result) {
					if !r.Pass {
						progress("FAIL %s", r.Describe())
					}
				}}
			results, err := mr.Run(ctx, rows, seeds)
			if err != nil {
				return nil, err
			}
			rep.Matrix = &MatrixReport{Totals: matrix.Tally(results), Results: results}
		case SuiteScenarios:
			report := func(r scenario.Result) {
				if !r.Pass {
					progress("FAIL scenario %s/%s stream=%v leaks=%d cache=%d/%d deterministic=%v %s", r.Scenario, r.API, r.Stream, len(r.Findings), r.CacheHits, r.CacheTurns, r.Deterministic, r.Error)
				}
			}
			var results []scenario.Result
			if o.Driver != "synthetic" {
				d := scenario.AgentDriver{Agent: o.Driver, Bin: o.AgentBin}
				for _, s := range scenario.AgentSessions {
					r := d.Run(ctx, target, fake, checker, s, seeds)
					report(r)
					results = append(results, r)
				}
			} else {
				scs, err := scenario.Corpus()
				if err != nil {
					return nil, err
				}
				sr := &scenario.Runner{Target: target, Fake: fake, Checker: checker}
				results = sr.RunAll(ctx, scs, o.APIs, seeds, report)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			c := scenario.Cache(results)
			rep.Scenarios = &ScenarioReport{Results: results, Cache: c}
		}
	}
	rep.Finished = time.Now().UTC()
	rep.finish()
	if !rep.Pass {
		return rep, ErrGate
	}
	return rep, nil
}

func loadSeeds(o Options) ([]leak.Seed, error) {
	var seeds []leak.Seed
	if o.SeedsIn != "" {
		s, err := leak.ReadSeedFile(o.SeedsIn)
		if err != nil {
			return nil, err
		}
		seeds = s
	} else {
		seeds = leak.GenerateSet()
	}
	if o.SeedsOut != "" {
		if err := leak.WriteSeedFile(o.SeedsOut, seeds); err != nil {
			return nil, fmt.Errorf("write seeds: %w", err)
		}
	}
	return seeds, nil
}

// startProxy runs ProxyCmd and waits until Proxy's address accepts
// connections.
func startProxy(ctx context.Context, o Options, upstream string, seeds []leak.Seed) (func(), error) {
	u, err := url.Parse(o.Proxy)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("--proxy must be a URL when --proxy-cmd is set: %q", o.Proxy)
	}
	seedPath := o.SeedsOut
	cleanup := func() {}
	if seedPath == "" {
		dir, err := os.MkdirTemp("", "scrim-leak-")
		if err != nil {
			return nil, err
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
		seedPath = dir + "/seeds.json"
		if err := leak.WriteSeedFile(seedPath, seeds); err != nil {
			cleanup()
			return nil, err
		}
	}
	cmd := exec.CommandContext(ctx, o.ProxyCmd[0], o.ProxyCmd[1:]...)
	cmd.Env = append(os.Environ(), "SCRIM_LEAK_UPSTREAM="+upstream, "SCRIM_LEAK_SEEDS="+seedPath, "SCRIM_LEAK_LISTEN="+u.Host)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	stop := func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		cleanup()
	}
	timeout := o.ProxyStartTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", u.Host, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return stop, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			stop()
			return nil, fmt.Errorf("proxy did not listen on %s within %s", u.Host, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ParseRoutes parses "api=prefix" pairs.
func ParseRoutes(pairs []string) (map[fp.API]string, error) {
	m := map[fp.API]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("route %q: want api=prefix", p)
		}
		api, err := ParseAPI(k)
		if err != nil {
			return nil, err
		}
		m[api] = "/" + strings.Trim(v, "/")
	}
	return m, nil
}

// ParseAPI accepts an API name or a short alias.
func ParseAPI(s string) (fp.API, error) {
	switch strings.ToLower(s) {
	case "anthropic", "anthropic-messages", "messages":
		return fp.Anthropic, nil
	case "openai-chat", "chat":
		return fp.OpenAIChat, nil
	case "openai-responses", "responses":
		return fp.OpenAIResponses, nil
	case "gemini", "google", "google-gemini":
		return fp.Gemini, nil
	case "openai-realtime", "realtime":
		return fp.OpenAIRealtime, nil
	case "openai-responses-ws", "responses-ws":
		return fp.OpenAIResponsesWS, nil
	}
	return "", fmt.Errorf("unknown api %q (anthropic, openai-chat, openai-responses, gemini, openai-realtime, openai-responses-ws)", s)
}
