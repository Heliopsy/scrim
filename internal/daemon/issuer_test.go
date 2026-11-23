// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/issuer"
	"github.com/heliopsy/scrim/internal/secret"
)

// TestIssuerServesDiscoveryAndRedactsTokens: with identity.issuer.url set,
// the daemon serves the discovery document and JWKS on
// identity.issuer.listen, every token it signs is in the next snapshot's
// redaction set (store scrim-issuer, no store reference or bound host:
// redaction only), an
// ended session's token is not handed out again, and no token or key
// material reaches the log.
func TestIssuerServesDiscoveryAndRedactsTokens(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	h.editConfig(t, "dataplane:\n", `identity:
  issuer:
    url: http://127.0.0.1:1/scrim
    listen: 127.0.0.1:0
    key-dir: `+filepath.Join(h.dir, "issuer")+`
dataplane:
`)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	if err := d.WaitReady(ctx); err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}
	addr := d.Addrs().Issuer
	if addr == "" {
		t.Fatal("no issuer listener")
	}
	get := func(path string) map[string]any {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var m map[string]any
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&m) != nil {
			t.Fatalf("GET %s: %d", path, resp.StatusCode)
		}
		return m
	}
	doc := get("/scrim" + issuer.DiscoveryPath)
	if doc["issuer"] != "http://127.0.0.1:1/scrim" || doc["jwks_uri"] != "http://127.0.0.1:1/scrim"+issuer.JWKSPath {
		t.Fatalf("discovery %v", doc)
	}
	if keys, _ := get("/scrim" + issuer.JWKSPath)["keys"].([]any); len(keys) != 2 {
		t.Fatalf("jwks has %d keys", len(keys))
	}
	resp, err := http.Get("http://" + addr + "/v1/approvals")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("issuer listener serves other paths: %d", resp.StatusCode)
	}

	id := identity.Identity{Agent: "claude-laptop", Source: identity.SourceSession, SessionID: "sess-1",
		ExpiresAt: time.Now().Add(time.Hour), Scopes: identity.AgentScopes}
	v, _, err := d.issuer.Mint(id, "openbao")
	if err != nil {
		t.Fatal(err)
	}
	var tok string
	_ = v.Expose(func(b []byte) error { tok = string(b); return nil })
	v.Wipe()
	held := func(s *pb.Snapshot) bool {
		for _, e := range s.GetValues() {
			if string(e.GetValue()) == tok {
				if e.GetStore() != "scrim-issuer" || strings.Contains(e.GetRef(), "://") || len(e.GetBoundHosts()) != 0 {
					t.Fatalf("issued token entry %s %q %v", e.GetStore(), e.GetRef(), e.GetBoundHosts())
				}
				return true
			}
		}
		return false
	}
	eventually(t, "the issued token in the redaction set", func() bool { return held(h.snapshot(t)) })

	d.sessionEnded("sess-1")
	w, _, err := d.issuer.Mint(id, "openbao")
	if err != nil {
		t.Fatal(err)
	}
	if w.Equal(secret.FromString(tok)) {
		t.Fatal("an ended session's token was handed out again")
	}
	w.Wipe()

	if strings.Contains(h.logs.String(), tok[len(tok)-40:]) || strings.Contains(h.logs.String(), "PRIVATE KEY") {
		t.Fatal("a token or key reached the log")
	}
	if !strings.Contains(h.logs.String(), "identity issuer serving discovery and JWKS") {
		t.Fatalf("issuer start not logged:\n%s", h.logs.String())
	}
}

// TestIssuerNeedsListen: a URL without a listener, or the reverse, is a
// start-up error naming both settings.
func TestIssuerNeedsListen(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	h.editConfig(t, "dataplane:\n", "identity:\n  issuer:\n    url: https://scrim.example.test\ndataplane:\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err == nil {
		_ = d.Shutdown(context.Background())
		t.Fatal("started without identity.issuer.listen")
	}
	if !strings.Contains(err.Error(), "identity.issuer.listen") {
		t.Fatalf("error does not name the setting: %v", err)
	}
}
