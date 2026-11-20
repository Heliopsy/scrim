// SPDX-License-Identifier: AGPL-3.0-only

package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

// testdata/nono-approval-status-v1.json is nono's own fixture
// (nolabs-ai/nono, tests/fixtures/approval-status-v1.json, Apache-2.0): the
// response shapes of the approval webhook protocol and the decision each
// must produce.
func TestParseMatchesNonoFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/nono-approval-status-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Signed []struct {
			Name     string          `json:"name"`
			Status   int             `json:"http_status"`
			Body     json.RawMessage `json:"body"`
			Expected string          `json:"expected"`
		} `json:"signed"`
		Unsigned []struct {
			Name     string          `json:"name"`
			Body     json.RawMessage `json:"body"`
			Expected string          `json:"expected"`
		} `json:"unsigned"`
	}
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	// nono denies on every error; scrim settles nothing and leaves the
	// approval to expire, which ends in the same denial.
	want := map[string][]Verdict{
		"pending": {Pending}, "granted": {Granted}, "denied": {Denied, Invalid}, "timeout": {TimedOut},
	}
	check := func(name string, status int, body []byte, expected string) {
		got := Parse(status, body)
		for _, w := range want[expected] {
			if got == w {
				return
			}
		}
		t.Errorf("%s: got %d, want one of %v", name, got, want[expected])
	}
	for _, c := range fx.Signed {
		check(c.Name, c.Status, c.Body, c.Expected)
	}
	for _, c := range fx.Unsigned {
		check(c.Name, 200, c.Body, c.Expected)
	}
	if Parse(200, []byte(`{"decision":"maybe"}`)) != Invalid || Parse(200, []byte(`nope`)) != Invalid || Parse(302, nil) != Invalid {
		t.Error("unrecognised answers must be invalid")
	}
}

type rig struct {
	svc  *approval.Service
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []recorded
	// answer decides each response.
	answer func(r *http.Request, n int) (int, string)
	secret []byte
}

type recorded struct {
	method, path string
	body         []byte
	header       http.Header
}

func newRig(t *testing.T, answer func(*http.Request, int) (int, string)) *rig {
	t.Helper()
	svc, err := approval.New(approval.Options{State: memstate.New(), Signer: approval.RandomSigner(),
		PublicURL: "https://scrim.example", Timeout: 5 * time.Second, PollInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{svc: svc, answer: answer, secret: []byte(strings.Repeat("s", 32))}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, recorded{req.Method, req.URL.Path, body, req.Header.Clone()})
		n := len(r.reqs)
		r.mu.Unlock()
		if err := Verify(r.secret, req, body, time.Minute, time.Now()); err != nil {
			t.Errorf("signature: %v", err)
		}
		status, out := r.answer(req, n)
		if status == http.StatusFound {
			w.Header().Set("Location", "https://elsewhere.example/")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) first() recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reqs[0]
}

func (r *rig) notifier(t *testing.T) *Notifier {
	t.Helper()
	n, err := New(Options{URL: r.srv.URL + "/api/v1/approvals", Secret: secret.New(r.secret), Settler: r.svc,
		TokenFromLink: approval.TokenFromLink, PollInterval: 5 * time.Millisecond, Hold: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// pending creates an approval and the notify request the service would
// send, links included.
func (r *rig) pending(t *testing.T) (*state.Approval, notify.Request) {
	t.Helper()
	ctx := context.Background()
	a, err := r.svc.Create(ctx, approval.Request{
		Policy: policy.Request{Agent: policy.Agent{ID: "claude-laptop", Kind: policy.IdentitySession, Session: "sess-1"},
			Action: policy.ActionInject, Ref: stores.MustParseRef("bao://kv/agents/github"), Host: "api.github.com",
			Method: "POST", Path: "/repos/a/b/issues?token=⟦scrim:github:00ff⟧"},
		Decision: policy.Decision{Effect: policy.Ask, Rule: "github-write", Reason: "writes need a human"},
	})
	if err != nil {
		t.Fatal(err)
	}
	approve, _ := r.svc.Link(a.ID, approval.ActionApprove, a.ExpiresAt, "webhook")
	deny, _ := r.svc.Link(a.ID, approval.ActionDeny, a.ExpiresAt, "webhook")
	return a, notify.Request{ApprovalID: a.ID, Agent: a.Request.Agent, Summary: a.Request, Rule: a.Rule,
		Reason: a.Reason, ExpiresAt: a.ExpiresAt, ApproveURL: approve, DenyURL: deny}
}

func (r *rig) status(t *testing.T, id string) state.ApprovalStatus {
	t.Helper()
	a, err := r.svc.Get(context.Background(), id, "")
	if err != nil {
		t.Fatal(err)
	}
	return a.Status
}

func (r *rig) waitStatus(t *testing.T, id string, want state.ApprovalStatus) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.status(t, id) == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("approval is %s, want %s", r.status(t, id), want)
}

func TestImmediateGrant(t *testing.T) {
	r := newRig(t, func(*http.Request, int) (int, string) { return 200, `{"decision":"granted"}` })
	a, req := r.pending(t)
	if err := r.notifier(t).Notify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := r.status(t, a.ID); got != state.ApprovalApproved {
		t.Fatalf("status %s", got)
	}
	got, _ := r.svc.Get(context.Background(), a.ID, "")
	if got.DecidedBy != "link:webhook" {
		t.Fatalf("decided by %q", got.DecidedBy)
	}
	// The body follows nono's endpoint shape plus the scrim extension.
	var env Envelope
	if err := json.Unmarshal(r.first().body, &env); err != nil {
		t.Fatal(err)
	}
	b := env.Request
	if env.Backend != "webhook" || b.CapabilityType != "endpoint" || b.RequestID != a.ID || b.SessionID != "sess-1" ||
		b.Upstream != "api.github.com" || b.Method != "POST" || b.Path != "/repos/a/b/issues" || b.RouteID != "github-write" ||
		b.CredentialRoute == nil || *b.CredentialRoute != "bao://kv/agents/github" || b.Scrim.Agent != "claude-laptop" ||
		!strings.HasPrefix(b.Scrim.ApproveURL, "https://scrim.example/v1/approvals/") {
		t.Fatalf("body %+v", env)
	}
	if strings.Contains(string(r.first().body), "token=") {
		t.Fatal("query string sent to the webhook")
	}
	if r.first().header.Get("X-Nono-Timeout-Secs") == "" || r.first().header.Get("X-Scrim-Signature") == "" {
		t.Fatalf("headers %v", r.first().header)
	}
}

func TestSubmitThenPollDecidesLater(t *testing.T) {
	r := newRig(t, func(req *http.Request, n int) (int, string) {
		switch {
		case req.Method == http.MethodPost:
			return 202, `{"request_id":"x","state":"pending"}`
		case n < 4:
			return 202, `{"state":"pending"}`
		}
		return 200, `{"state":"denied","decision":"denied","reason":"not today"}`
	})
	a, req := r.pending(t)
	if err := r.notifier(t).Notify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	r.waitStatus(t, a.ID, state.ApprovalDenied)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) != 4 || r.reqs[1].method != http.MethodGet || r.reqs[1].path != "/api/v1/approvals/"+a.ID {
		t.Fatalf("requests %+v", r.reqs)
	}
}

func TestErrorsAndRedirectsSettleNothing(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
	}{{401, `{"error":"Unauthorized"}`}, {404, `{}`}, {302, ``}, {500, ``}, {200, `{"decision":"perhaps"}`}} {
		r := newRig(t, func(*http.Request, int) (int, string) { return c.status, c.body })
		a, req := r.pending(t)
		if err := r.notifier(t).Notify(context.Background(), req); err == nil {
			t.Errorf("%d: no error", c.status)
		}
		if got := r.status(t, a.ID); got != state.ApprovalPending {
			t.Errorf("%d %s: status %s", c.status, c.body, got)
		}
	}
}

func TestPollGivesUpAtExpiry(t *testing.T) {
	var polls atomic.Int32
	r := newRig(t, func(*http.Request, int) (int, string) { polls.Add(1); return 202, `{"state":"pending"}` })
	a, req := r.pending(t)
	req.ExpiresAt = time.Now().Add(100 * time.Millisecond)
	if err := r.notifier(t).Notify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	n := polls.Load()
	time.Sleep(100 * time.Millisecond)
	if polls.Load() != n {
		t.Fatal("still polling after expiry")
	}
	if r.status(t, a.ID) != state.ApprovalPending {
		t.Fatal("timeout settled the approval")
	}
}

func TestCallbackThroughDecisionLink(t *testing.T) {
	// The receiver acknowledges, then posts the decision link a while later.
	r := newRig(t, func(*http.Request, int) (int, string) { return 202, `{"state":"pending"}` })
	n, err := New(Options{URL: r.srv.URL, Secret: secret.New(r.secret), Settler: r.svc, TokenFromLink: approval.TokenFromLink,
		Hold: time.Second, PollInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	a, req := r.pending(t)
	if err := n.Notify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var env Envelope
	_ = json.Unmarshal(r.first().body, &env)
	dp := httptest.NewServer(r.svc.DecisionHandler())
	defer dp.Close()
	link := strings.Replace(env.Request.Scrim.ApproveURL, "https://scrim.example", dp.URL, 1)
	resp, err := http.Post(link, "", nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("callback: %v %v", resp, err)
	}
	if r.status(t, a.ID) != state.ApprovalApproved {
		t.Fatal("callback did not settle")
	}
}

func TestOptionsValidation(t *testing.T) {
	ok := Options{Settler: SettlerFunc(func(context.Context, string, string) error { return nil }), TokenFromLink: approval.TokenFromLink}
	for _, u := range []string{"http://example.org/hook", "ftp://x", "not a url", ""} {
		o := ok
		o.URL = u
		if _, err := New(o); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	for _, u := range []string{"https://approvals.example/hook", "http://127.0.0.1:9/x", "http://localhost/x", "http://[::1]/x"} {
		o := ok
		o.URL = u
		if _, err := New(o); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	o := ok
	o.URL, o.Secret = "https://a.example", secret.New([]byte("short"))
	if _, err := New(o); err == nil {
		t.Error("short secret accepted")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	n, _ := New(Options{URL: "https://a.example/hook", Secret: secret.New(key), Settler: SettlerFunc(nil), TokenFromLink: approval.TokenFromLink})
	body := []byte(`{"a":1}`)
	req, _ := http.NewRequest(http.MethodPost, "https://a.example/hook", nil)
	if err := n.sign(req, body); err != nil {
		t.Fatal(err)
	}
	if err := Verify(key, req, body, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	if Verify(key, req, []byte(`{"a":2}`), time.Minute, time.Now()) == nil {
		t.Error("modified body accepted")
	}
	if Verify([]byte(strings.Repeat("x", 32)), req, body, time.Minute, time.Now()) == nil {
		t.Error("wrong key accepted")
	}
	if Verify(key, req, body, time.Minute, time.Now().Add(time.Hour)) == nil {
		t.Error("stale timestamp accepted")
	}
}
