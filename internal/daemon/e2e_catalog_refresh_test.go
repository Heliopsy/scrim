// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// TestCatalogSecretSurvivesRefresh: a catalog-bound secret that no redact
// target covers is loaded with its store and kept by the store's refresher,
// on the real data plane:
//
//   - at start, it is redacted from provider requests and injected toward
//     its host. Before, nothing loaded it until the catalog changed, and the
//     provider received it in the clear;
//   - after several refreshes and a full retention period it is still both.
//     Before, a value loaded on a catalog change was retired by the next
//     refresh (no target listed it): no longer injected, and in the clear
//     once the retention ran out;
//   - a secret a catalog reload adds is redacted too, and stays so.
//
// The file store refreshes every 300ms and retains rotated values for 1s.
func TestCatalogSecretSurvivesRefresh(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()
	pki := newTestPKI(t)
	api := newToolAPI(t, pki)

	first, added := leak.Generate(leak.KindAPIKey), leak.Generate(leak.KindAPIKey)
	credential := first.Value()
	h := newHarness(t, seed(t, "tok-"))
	root := filepath.Join(h.dir, "files")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"cat-token": credential, "cat-added": added.Value()} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.editConfig(t, harnessRedact, harnessRedact+`  files:
    kind: file
    root: `+root+`
    refresh:
      interval: 300ms
      retention: 1s
`)
	h.editConfig(t, "      placeholder: SCRIM_ACME_KEY\n", `      placeholder: SCRIM_ACME_OLD
    cat:
      ref: files://cat-token
      hosts: [`+api.host()+`]
      placeholder: SCRIM_ACME_KEY
`)
	if err := os.WriteFile(filepath.Join(h.dir, "rules.yaml"), []byte(`default: deny
rules:
  - name: inject-catalog
    decision: allow
    when: op == "inject"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(h.dir, "tool-api-ca.pem")
	if err := os.WriteFile(caFile, pki.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_UPSTREAM_CA_FILE="+caFile)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up.URL)
	client := proxyClient(t, &url.URL{Scheme: "http", Host: d.Addrs().ForwardProxy}, d.TrustBundlePEM())
	checker := leak.NewChecker([]leak.Seed{first, added})

	injected := func() bool {
		before := len(api.requests())
		code, _ := toolGet(t, ctx, client, "https://"+api.host()+"/v1/thing")
		got := api.requests()
		return code == http.StatusOK && len(got) == before+1 && got[len(got)-1].Get("Authorization") == "Bearer "+credential
	}
	// redacted sends vals to the provider and checks that the request was
	// forwarded with none of them in it.
	redacted := func(when string, vals ...string) {
		t.Helper()
		n := len(fake.Exchanges())
		body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"deploy with ` +
			strings.Join(vals, " and ") + ` now"}]}`
		if code := sendMessages(t, ctx, d, body); code != http.StatusOK {
			t.Fatalf("%s: provider request answered %d", when, code)
		}
		ex := fake.Exchanges()
		if len(ex) != n+1 {
			t.Fatalf("%s: the provider saw %d new requests", when, len(ex)-n)
		}
		if fs := checker.Check(leak.Capture{Seq: 1, Header: ex[n].Header, Body: ex[n].Body}); len(fs) > 0 {
			t.Fatalf("%s: the provider received a catalog secret (%d findings)", when, len(fs))
		}
	}
	r, err := d.refresherFor(mustRef(t, "files://cat-token"))
	if err != nil {
		t.Fatal(err)
	}
	// refreshes waits for several refreshes and more than the retention
	// period, then for the snapshot to reach the data plane.
	refreshes := func() {
		t.Helper()
		began, last := time.Now(), r.Status().LastSuccess
		deadline := began.Add(30 * time.Second)
		for n := 0; n < 3 || time.Since(began) < 2*time.Second; {
			if time.Now().After(deadline) {
				t.Fatalf("the files store did not refresh: %+v", r.Status())
			}
			if s := r.Status().LastSuccess; s.After(last) {
				n++
				last = s
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond)
	}

	redacted("at start", credential)
	if !injected() {
		t.Fatalf("the catalog secret is not injected at start\n%s", h.logs.String())
	}
	refreshes()
	redacted("after refreshes", credential)
	if !injected() {
		t.Fatalf("the catalog secret is no longer injected after the store refreshed\n%s", h.logs.String())
	}

	h.editConfig(t, "      placeholder: SCRIM_ACME_KEY\n", `      placeholder: SCRIM_ACME_KEY
    added:
      ref: files://cat-added
      hosts: [api.added.test]
`)
	if res := d.app.Config.Reload(ctx, "test"); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	eventually(t, "the added catalog secret loaded", func() bool {
		held := false
		r.EachValue(func(s refresh.Source, _ secret.Value) { held = held || s.Ref.Path == "cat-added" && !s.Retained })
		return held
	})
	time.Sleep(500 * time.Millisecond)
	redacted("after the catalog reload", credential, added.Value())
	refreshes()
	redacted("after the reload and refreshes", credential, added.Value())
	if !injected() {
		t.Fatalf("the catalog secret is not injected after the reload\n%s", h.logs.String())
	}
	logs := h.logs.String()
	if fs := checker.CheckText(1, logs); len(fs) > 0 || strings.Contains(logs, credential) || strings.Contains(logs, added.Value()) {
		t.Fatal("a catalog secret reached the log")
	}
}
