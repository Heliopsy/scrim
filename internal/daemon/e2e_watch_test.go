// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// TestWatchedSecretIsRedactedEndToEnd: on the real data plane, a secret
// written under a prefix redact target after start, and a new value of a
// single-secret target, are redacted from provider requests within a few
// watch intervals. The full refresh runs once an hour, so only the watch can
// bring them in. Before, the watch loaded them into the store's set but
// never pushed the set to the data plane, and the provider received them in
// the clear until the next full refresh (found with OpenBao in the
// Kubernetes e2e cell).
func TestWatchedSecretIsRedactedEndToEnd(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()

	before, single, added, rotated := leak.Generate(leak.KindAPIKey), leak.Generate(leak.KindAPIKey),
		leak.Generate(leak.KindAPIKey), leak.Generate(leak.KindAPIKey)
	h := newHarness(t, seed(t, "tok-"))
	root := filepath.Join(h.dir, "files")
	if err := os.MkdirAll(filepath.Join(root, "agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, v string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("agents/before", before.Value())
	write("deploy", single.Value())
	h.editConfig(t, harnessRedact, harnessRedact+`  files:
    kind: file
    root: `+root+`
    watch: {interval: 200ms}
    refresh: {interval: 1h}
    redact: ["files://agents/*", "files://deploy"]
`)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up.URL)

	// redacted sends s to the provider and reports whether the forwarded
	// request was free of it.
	redacted := func(s leak.Seed) bool {
		t.Helper()
		n := len(fake.Exchanges())
		body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"deploy with ` + s.Value() + ` now"}]}`
		if code := sendMessages(t, ctx, d, body); code != http.StatusOK {
			t.Fatalf("provider request answered %d", code)
		}
		ex := fake.Exchanges()
		if len(ex) != n+1 {
			t.Fatalf("the provider saw %d new requests", len(ex)-n)
		}
		return len(leak.NewChecker([]leak.Seed{s}).Check(leak.Capture{Seq: 1, Header: ex[n].Header, Body: ex[n].Body})) == 0
	}
	if !redacted(before) || !redacted(single) {
		t.Fatal("a value loaded at start is not redacted")
	}

	write("agents/added", added.Value())
	write("deploy", rotated.Value())
	// eventually allows 15s: 75 watch intervals, and far less than the
	// hour until the next full refresh.
	eventually(t, "the secret added under the prefix redacted", func() bool { return redacted(added) })
	eventually(t, "the rotated single secret redacted", func() bool { return redacted(rotated) })
	if !redacted(single) {
		t.Fatal("the previous value of the rotated secret is no longer redacted")
	}
	logs := h.logs.String()
	for _, s := range []leak.Seed{before, single, added, rotated} {
		if strings.Contains(logs, s.Value()) {
			t.Fatal("a secret reached the log")
		}
	}
}
