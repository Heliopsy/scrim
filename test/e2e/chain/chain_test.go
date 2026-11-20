// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Package chain runs scrim with caveman, a context compression proxy, as its
// chained upstream (tasks.md 3.5): agent, then scrim, then caveman, then a
// fake provider. Run it with `just e2e-chain`; it is skipped when
// caveman-proxy is not installed.
package chain

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite" // caveman's stores are SQLite

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// cavemanBinary finds caveman-proxy: SCRIM_E2E_CAVEMAN, PATH, or the
// default install location. It is only executed, never modified.
func cavemanBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SCRIM_E2E_CAVEMAN"); p != "" {
		return p
	}
	if p, err := exec.LookPath("caveman-proxy"); err == nil {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".caveman", "bin", "caveman-proxy")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("caveman-proxy is not installed (set SCRIM_E2E_CAVEMAN)")
	return ""
}

// startCaveman runs caveman-proxy on its own port with its own HOME and data
// directory, compressing, with the fake provider as its Anthropic upstream.
// It returns the base URL and the data directory.
func startCaveman(t *testing.T, bin, upstream string) (string, string) {
	t.Helper()
	// Short: caveman binds a Unix socket under its home.
	dir, err := os.MkdirTemp("", "cv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	home := filepath.Join(dir, "cm")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	listen := harness.FreePort(t)
	cfg := filepath.Join(dir, "caveman.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("listen: %s\nmode: compress\nproviders:\n  anthropic:\n    base_url: %s\n", listen, upstream)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "serve") //nolint:gosec // caveman under test
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_DATA_HOME=" + dir,
		"XDG_STATE_HOME=" + dir, "XDG_CACHE_HOME=" + dir,
		"CAVEMAN_HOME=" + home, "CAVEMAN_CONFIG=" + cfg, "CAVEMAN_LISTEN=" + listen,
		"CAVEMAN_MODE=compress", "CAVEMAN_RECOVERY=mcp",
		// caveman refuses loopback upstreams unless allowed.
		"CAVE_SSRF_ALLOWLIST=127.0.0.1",
		"DO_NOT_TRACK=1", "CAVEMAN_TELEMETRY=0", "CAVEMAN_OFFLINE=1",
	}
	var log harness.SyncBuffer
	cmd.Stdout, cmd.Stderr = &log, &log
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	stop := func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			t.Logf("caveman log:\n%s", log.String())
		}
	})
	base := "http://" + listen
	for i := 0; ; i++ {
		resp, err := http.Get(base + "/health/live")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if i > 100 {
			t.Fatalf("caveman did not start: %v\n%s", err, log.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return base, home
}

// toolLog is a long, repetitive command output, the kind caveman elides,
// with seeded values in a line it keeps (an error) and in lines it elides.
func toolLog(credential, display string) string {
	var b strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&b, "2026-11-20T10:%02d:00Z INFO worker-%d processed batch id=%d status=ok duration_ms=%d bytes=%d\n",
			i%60, i%7, i, 100+i%37, i*13)
		if i == 1500 {
			fmt.Fprintf(&b, "2026-11-20T10:30:00Z DEBUG worker-2 retry with api_key=%s password=%s\n", credential, display)
		}
	}
	fmt.Fprintf(&b, "2026-11-20T11:00:00Z ERROR worker-3 failed batch id=99999 auth=%s db_password=%s", credential, display)
	return b.String()
}

func messages(log string, stream bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"model": "claude-sonnet-4-5", "max_tokens": 256, "stream": stream,
		"tools": []any{map[string]any{"name": "bash", "description": "run a command",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{"cmd": map[string]any{"type": "string"}}}}},
		"messages": []any{
			map[string]any{"role": "user", "content": "Check the worker logs."},
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "toolu_1", "name": "bash",
				"input": map[string]any{"cmd": "cat worker.log"}}}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "toolu_1", "content": log},
				map[string]any{"type": "text", "text": "Which credentials does the failing batch use?"}}},
		},
	})
	return b
}

// replyText is the assistant text of a Messages response, streamed or not.
func replyText(t *testing.T, body []byte, stream bool) string {
	t.Helper()
	var out strings.Builder
	if !stream {
		var m struct {
			Content []struct {
				Type, Text string
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("response: %v: %.300s", err, body)
		}
		for _, c := range m.Content {
			out.WriteString(c.Text)
		}
		return out.String()
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Type, Text string
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(data), &ev) == nil && ev.Type == "content_block_delta" {
			out.WriteString(ev.Delta.Text)
		}
	}
	return out.String()
}

func TestCavemanChain(t *testing.T) {
	bin := harness.Require(t)
	caveman := cavemanBinary(t)

	credential, display := leak.Generate(leak.KindAPIKey), leak.Generate(leak.KindDBPassword)
	seeds := []leak.Seed{credential, display}
	fake := fp.New(fp.Options{})
	provider := httptest.NewServer(fake)
	defer provider.Close()
	caveURL, caveHome := startCaveman(t, caveman, provider.URL)

	d := harness.Start(t, bin, harness.Options{
		Secrets:  map[string]string{"api-key": credential.Value(), "db-password": display.Value()},
		Upstream: provider.URL, // never used directly: every request goes through the chain
		Chain:    caveURL,
		Capture:  true,
		Catalog: `    api-key:
      ref: e2e://tools/api-key
      hosts: [api.acme.test]
    db-password:
      ref: e2e://tools/db-password
      class: display
`,
	})
	info, err := d.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	log := toolLog(credential.Value(), display.Value())
	var sent int
	for _, stream := range []bool{false, true} {
		req, _ := http.NewRequest(http.MethodPost, info.Addrs.BaseURL+"/anthropic/v1/messages", bytes.NewReader(messages(log, stream)))
		req.Header.Set("content-type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("x-api-key", "fake-provider-key-not-a-seed")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		sent++
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream=%v: %s: %.500s", stream, resp.Status, body)
		}
		text := replyText(t, body, stream)
		// The fake provider names every placeholder it saw. Back at the
		// agent, the display value is restored and the credential stays a
		// placeholder: both survived compression intact.
		if !strings.Contains(text, display.Value()) {
			t.Errorf("stream=%v: the display value was not restored in the reply: %.300s", stream, text)
		}
		if strings.Contains(text, credential.Value()) {
			t.Errorf("stream=%v: the credential was restored into the reply", stream)
		}
		if !fp.DefaultPlaceholderPattern.MatchString(text) {
			t.Errorf("stream=%v: the credential placeholder did not come back: %.300s", stream, text)
		}
	}

	// Every request reached the fake provider through caveman, compressed,
	// with placeholders only.
	ex := fake.Exchanges()
	if len(ex) != sent {
		t.Fatalf("the fake provider received %d requests, want %d", len(ex), sent)
	}
	checker := leak.NewChecker(seeds)
	for _, e := range ex {
		if f := checker.Check(e.Capture); len(f) > 0 {
			raw, _ := json.Marshal(f)
			t.Errorf("leak in request %d to the provider: %s", e.Seq, raw)
		}
		if !strings.Contains(e.Header.Get("User-Agent"), "caveman") {
			t.Errorf("request %d did not come through caveman (User-Agent %q)", e.Seq, e.Header.Get("User-Agent"))
		}
		if !bytes.Contains(e.Body, []byte("elided")) || len(e.Body) > len(log)/4 {
			t.Errorf("request %d was not compressed (%d bytes)", e.Seq, len(e.Body))
		}
		if len(e.Placeholders) < 2 {
			t.Errorf("request %d carries %d placeholders, want the credential's and the display value's", e.Seq, len(e.Placeholders))
		}
	}

	// scrim's own capture of what left it.
	scanDir(t, checker, d.CaptureDir(), "scrim capture")

	// caveman's stores: every file it wrote (databases with their WAL,
	// logs), then the recovery store's originals through SQLite, since a
	// long value spans database pages.
	time.Sleep(500 * time.Millisecond)
	scanDir(t, checker, caveHome, "caveman data")
	db, err := sql.Open("sqlite", "file:"+filepath.Join(caveHome, "ccr.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT handle, original FROM recoveries`)
	if err != nil {
		t.Fatalf("caveman's recovery store: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var n int
	for rows.Next() {
		var handle string
		var original []byte
		if err := rows.Scan(&handle, &original); err != nil {
			t.Fatal(err)
		}
		n++
		if f := checker.Check(leak.Capture{Body: original}); len(f) > 0 {
			raw, _ := json.Marshal(f)
			t.Errorf("caveman stored a seeded value under %s: %s", handle, raw)
		}
		if got := len(fp.DefaultPlaceholderPattern.FindAll(original, -1)); got < 4 {
			t.Errorf("recovery %s holds %d placeholders, want the 4 of the log", handle, got)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("caveman stored no recovery: nothing was compressed")
	}
	t.Logf("%d provider requests, %d caveman recoveries, all placeholders", len(ex), n)
}

// scanDir fails when any file under dir holds a seeded value.
func scanDir(t *testing.T, checker *leak.Checker, dir, what string) {
	t.Helper()
	var files int
	err := filepath.WalkDir(dir, func(p string, de fs.DirEntry, err error) error {
		if err != nil || !de.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // test output
		if err != nil {
			return err
		}
		files++
		if f := checker.Check(leak.Capture{Body: b}); len(f) > 0 {
			raw, _ := json.Marshal(f)
			t.Errorf("%s: %s holds a seeded value: %s", what, p, raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Errorf("%s: no files under %s", what, dir)
	}
}
