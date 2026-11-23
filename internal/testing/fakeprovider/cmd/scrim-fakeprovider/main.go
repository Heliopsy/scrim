// SPDX-License-Identifier: AGPL-3.0-only

// Command scrim-fakeprovider runs the leak suite's fake model provider on its
// own, for testing a proxy from another language or by hand.
//
//	scrim-fakeprovider -listen 127.0.0.1:18089 -capture-dir ./captures
//
// It answers Anthropic Messages (/v1/messages), OpenAI Chat Completions
// (/v1/chat/completions) and Responses (/v1/responses), and Gemini
// (/v1beta/models/{model}:generateContent, :streamGenerateContent and
// :countTokens) under any path prefix, and serves /_fake/health, /_fake/exchanges (GET, every recorded exchange as
// JSON) and /_fake/reset (POST).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "scrim-fakeprovider:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:18089", "address to listen on")
	captureDir := flag.String("capture-dir", "", "write every exchange as NNNN.json into this directory (created 0700)")
	chunk := flag.Int("chunk", 5, "runes per streamed delta")
	script := flag.String("script", "", "JSON file with scripted replies, one per assistant turn")
	requireAuth := flag.Bool("require-auth", false, "refuse requests without provider authentication")
	flag.Parse()

	opts := fakeprovider.Options{ChunkSize: *chunk, RequireAuth: *requireAuth}
	if *script != "" {
		steps, err := fakeprovider.LoadScript(*script)
		if err != nil {
			return err
		}
		opts.Responder = fakeprovider.Script(steps)
	}
	fp := fakeprovider.New(opts)
	var h http.Handler = fp
	if *captureDir != "" {
		if err := os.MkdirAll(*captureDir, 0o700); err != nil {
			return err
		}
		h = &dumper{fp: fp, dir: *captureDir}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "listening on http://%s\n", ln.Addr())
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// dumper writes each new exchange to disk after it is served.
type dumper struct {
	fp      *fakeprovider.Server
	dir     string
	mu      sync.Mutex
	written int
}

func (d *dumper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.fp.ServeHTTP(w, r)
	d.mu.Lock()
	defer d.mu.Unlock()
	ex := d.fp.Exchanges()
	if len(ex) < d.written {
		d.written = 0 // reset happened
	}
	for _, e := range ex[d.written:] {
		b, err := json.MarshalIndent(e, "", "  ")
		if err == nil {
			_ = os.WriteFile(filepath.Join(d.dir, fmt.Sprintf("%04d-%d.json", e.Seq, e.Time.UnixNano())), b, 0o600)
		}
	}
	d.written = len(ex)
}
