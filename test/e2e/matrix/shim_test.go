// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package matrix

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMatrixShim is the agent of a traffic cell, started by the inner test
// as a child process (under `scrim run` for the run-* modes, bare for the
// transparent mode). The leak suite's runner sends each request to it as
// /<route>/<provider path>; it sends the request on the way an agent in its
// mode does, with the environment it was started with, and streams the reply
// back:
//
//   - run-base-url: to the base URL scrim run set for the route
//     (ANTHROPIC_BASE_URL, OPENAI_BASE_URL, GOOGLE_GEMINI_BASE_URL; a cloud
//     route sits next to /anthropic), honouring NO_PROXY;
//   - run-forward-proxy: to https://<provider host> through HTTPS_PROXY,
//     trusting SSL_CERT_FILE, both from scrim run;
//   - transparent: to https://<provider host> directly, trusting
//     SSL_CERT_FILE (scrim's CA, as an install puts it in the system store).
//
// For a cloud route it rewrites the Anthropic request into that provider's
// wire format first (cloudRequest). It skips unless started that way.
func TestMatrixShim(t *testing.T) {
	listen := os.Getenv("SCRIM_MATRIX_SHIM_LISTEN")
	if listen == "" {
		t.Skip("started by the matrix only")
	}
	mode, provider := Mode(os.Getenv("SCRIM_MATRIX_SHIM_MODE")), Provider(os.Getenv("SCRIM_MATRIX_PROVIDER"))
	tr := &http.Transport{DisableCompression: true, ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 4,
		ResponseHeaderTimeout: 60 * time.Second}
	switch mode {
	case ModeForwardProxy:
		if os.Getenv("HTTPS_PROXY") == "" || os.Getenv("SSL_CERT_FILE") == "" {
			t.Fatal("scrim run set no HTTPS_PROXY or SSL_CERT_FILE")
		}
		tr.Proxy = http.ProxyFromEnvironment
	case ModeBaseURL:
		tr.Proxy = http.ProxyFromEnvironment
	case ModeTransparent:
		if os.Getenv("HTTPS_PROXY") != "" || os.Getenv("ANTHROPIC_BASE_URL") != "" {
			t.Fatal("the transparent agent has proxy settings; it must have none")
		}
	}
	client := &http.Client{Transport: tr, Timeout: 90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	mux := http.NewServeMux()
	mux.HandleFunc("/_shim/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/_shim/exit", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "bye")
		stop()
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		route, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		rest = "/" + rest
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "shim: read body", http.StatusBadRequest)
			return
		}
		header := r.Header.Clone()
		if provider.Cloud() {
			rest, body = cloudRequest(provider, rest, body)
			if provider == ProviderAnthropicAWS {
				header.Set("anthropic-workspace-id", workspaceID)
			}
		}
		target, ok := shimTarget(mode, provider, route, rest)
		if !ok {
			http.Error(w, "shim: no base URL for route "+route, http.StatusBadGateway)
			return
		}
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		out, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "shim: "+err.Error(), http.StatusBadGateway)
			return
		}
		for k, vs := range header {
			switch http.CanonicalHeaderKey(k) {
			case "Content-Length", "Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Host":
				continue
			}
			out.Header[k] = vs
		}
		resp, err := client.Do(out)
		if err != nil {
			http.Error(w, "shim: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			if http.CanonicalHeaderKey(k) == "Content-Length" {
				continue
			}
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		f, _ := w.(http.Flusher)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if f != nil {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
}

// shimTarget is the URL a request for route and path goes to in mode.
func shimTarget(mode Mode, p Provider, route, path string) (string, bool) {
	if mode != ModeBaseURL {
		return "https://" + p.Host() + path, true
	}
	anthropic := os.Getenv("ANTHROPIC_BASE_URL")
	switch route {
	case "anthropic":
		return anthropic + path, anthropic != ""
	case "openai":
		base := strings.TrimSuffix(os.Getenv("OPENAI_BASE_URL"), "/v1")
		return base + path, base != ""
	case "gemini":
		base := os.Getenv("GOOGLE_GEMINI_BASE_URL")
		return base + path, base != ""
	}
	base, ok := strings.CutSuffix(anthropic, "/anthropic")
	return base + "/" + route + path, ok
}
