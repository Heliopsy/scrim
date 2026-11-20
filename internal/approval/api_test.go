// SPDX-License-Identifier: AGPL-3.0-only

package approval

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/state"
)

func TestDecisionEndpoint(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	n := f.sent(t, 1)[0]
	srv := httptest.NewServer(f.svc.DecisionHandler())
	defer srv.Close()
	path := func(link string) string {
		u, _ := url.Parse(link)
		return srv.URL + u.RequestURI()
	}
	// GET shows the request and changes nothing.
	resp, err := http.Get(path(n.ApproveURL))
	if err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	buf := make([]byte, 8192)
	for {
		k, err := resp.Body.Read(buf)
		body.Write(buf[:k])
		if err != nil {
			break
		}
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(body.String(), "claude-laptop") || !strings.Contains(body.String(), "<form method=\"post\">") {
		t.Fatalf("GET %d %s", resp.StatusCode, body.String())
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("no CSP on decision page")
	}
	if got, _ := f.svc.Get(f.ctx, a.ID, ""); got.Status != state.ApprovalPending {
		t.Fatal("GET decided the approval")
	}
	// A forged token is refused.
	u, _ := url.Parse(path(n.ApproveURL))
	q := u.Query()
	q.Set("t", q.Get("t")+"x")
	u.RawQuery = q.Encode()
	if r, _ := http.Post(u.String(), "", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("forged: %d", r.StatusCode)
	}
	// The ntfy-style POST decides.
	r, err := http.Post(path(n.ApproveURL), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var res DecisionResult
	_ = json.NewDecoder(r.Body).Decode(&res)
	_ = r.Body.Close()
	if r.StatusCode != 200 || res.Approval.Status != "approved" || res.GrantID == "" {
		t.Fatalf("POST %d %+v", r.StatusCode, res)
	}
	// Second tap, on either button.
	for _, link := range []string{n.ApproveURL, n.DenyURL} {
		if r, _ := http.Post(path(link), "", nil); r.StatusCode != http.StatusConflict {
			t.Fatalf("replay: %d", r.StatusCode)
		}
	}
	// A form post with the token in the body works the same way.
	b := f.create(t)
	nb := f.sent(t, 2)[1]
	_, tok, _ := TokenFromLink(nb.DenyURL)
	r, _ = http.PostForm(srv.URL+DecidePath(b.ID), url.Values{"t": {tok}})
	if r.StatusCode != 200 {
		t.Fatalf("form post: %d", r.StatusCode)
	}
	// Expired.
	c := f.create(t)
	nc := f.sent(t, 3)[2]
	f.clk.Add(2 * time.Minute)
	if r, _ := http.Post(path(nc.ApproveURL), "", nil); r.StatusCode != http.StatusGone {
		t.Fatalf("expired: %d", r.StatusCode)
	}
	_ = c
}

func TestAdminRequiresOperator(t *testing.T) {
	f := newFixture(t)
	h := AdminHandler(f.svc, grant.NewService(f.st, f.bg), f.bg, func(*http.Request) (string, bool) { return "", false })
	srv := httptest.NewServer(h)
	defer srv.Close()
	for _, p := range []string{"/v1/approvals", "/v1/grants", "/v1/deny-all"} {
		r, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: %d", p, r.StatusCode)
		}
	}
	h = AdminHandler(f.svc, nil, nil, nil)
	srv2 := httptest.NewServer(h)
	defer srv2.Close()
	if r, _ := http.Post(srv2.URL+"/v1/deny-all", "application/json", strings.NewReader(`{"active":true}`)); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nil operator func: %d", r.StatusCode)
	}
}
