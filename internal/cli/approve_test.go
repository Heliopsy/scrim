// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

type adminRig struct {
	svc  *approval.Service
	bg   *breakglass.Switch
	gs   *grant.Service
	addr string
}

func newAdminRig(t *testing.T) *adminRig {
	t.Helper()
	ctx := context.Background()
	st := memstate.New()
	bg, err := breakglass.New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approval.New(approval.Options{State: st, Signer: approval.RandomSigner(), BreakGlass: bg,
		Notifiers: []notify.Notifier{&notify.Recorder{}}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	gs := grant.NewService(st, bg)
	h := approval.AdminHandler(svc, gs, bg, func(*http.Request) (string, bool) { return "alice", true })
	// Serve on a Unix socket, the default transport.
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := netListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: h, ReadHeaderTimeout: time.Second}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &adminRig{svc: svc, bg: bg, gs: gs, addr: "unix:" + sock}
}

func (r *adminRig) pending(t *testing.T, agent string) *state.Approval {
	t.Helper()
	a, err := r.svc.Create(context.Background(), approval.Request{
		Policy: policy.Request{Agent: policy.Agent{ID: agent, Kind: policy.IdentitySession}, Action: policy.ActionInject,
			Ref: stores.MustParseRef("bao://kv/agents/hetzner"), Host: "api.hetzner.cloud", Method: "DELETE"},
		Decision: policy.Decision{Effect: policy.Ask, Rule: "hetzner-writes", GrantTTL: 10 * time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func runAdmin(t *testing.T, addr string, args ...string) (int, string, string) {
	t.Helper()
	e, out, errb := newEnv("SCRIM_ADMIN_URL=" + addr)
	code := Run(context.Background(), e, args)
	return code, out.String(), errb.String()
}

func TestTerminalApproveAndDeny(t *testing.T) {
	r := newAdminRig(t)
	a := r.pending(t, "claude-laptop")
	b := r.pending(t, "codex")

	code, out, errs := runAdmin(t, r.addr, "approvals", "list")
	if code != 0 || !strings.Contains(out, a.ID) || !strings.Contains(out, "DELETE api.hetzner.cloud") || !strings.Contains(out, b.ID) {
		t.Fatalf("list: %d %q %q", code, out, errs)
	}
	code, out, _ = runAdmin(t, r.addr, "approvals", "list", "--agent", "codex", "--json")
	if code != 0 || strings.Contains(out, a.ID) || !strings.Contains(out, `"agent": "codex"`) {
		t.Fatalf("filtered list: %q", out)
	}
	code, out, errs = runAdmin(t, r.addr, "approve", a.ID, "--ttl", "2h", "--reason", "deploy window")
	if code != 0 || !strings.Contains(out, "approved") || !strings.Contains(out, "grant ") {
		t.Fatalf("approve: %d %q %q", code, out, errs)
	}
	if got, _ := r.svc.Get(context.Background(), a.ID, ""); got.Status != state.ApprovalApproved || got.DecidedBy != "alice" {
		t.Fatalf("approval %+v", got)
	}
	if code, _, errs := runAdmin(t, r.addr, "approve", a.ID); code != 1 || !strings.Contains(errs, "already decided") {
		t.Fatalf("second approve: %d %q", code, errs)
	}
	if code, out, _ := runAdmin(t, r.addr, "deny", b.ID, "--reason", "not now"); code != 0 || !strings.Contains(out, "denied") {
		t.Fatalf("deny: %d %q", code, out)
	}
	code, out, _ = runAdmin(t, r.addr, "grants", "list")
	if code != 0 || !strings.Contains(out, "claude-laptop") || !strings.Contains(out, "bao://kv/agents/hetzner") {
		t.Fatalf("grants: %q", out)
	}
	gs, _ := r.gs.List(context.Background(), "", true)
	if len(gs) != 1 {
		t.Fatalf("%d grants", len(gs))
	}
	if code, out, _ := runAdmin(t, r.addr, "grants", "revoke", gs[0].ID); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %q", out)
	}
	if code, out, _ := runAdmin(t, r.addr, "grants", "list"); code != 0 || !strings.Contains(out, "no grants") {
		t.Fatalf("after revoke: %q", out)
	}
}

func TestDenyAllCommand(t *testing.T) {
	r := newAdminRig(t)
	a := r.pending(t, "claude-laptop")
	if code, out, _ := runAdmin(t, r.addr, "deny-all", "on", "--reason", "drill"); code != 0 || !strings.Contains(out, "ON") {
		t.Fatalf("on: %q", out)
	}
	if got, _ := r.svc.Get(context.Background(), a.ID, ""); got.Status != state.ApprovalDenied {
		t.Fatalf("pending approval is %s", got.Status)
	}
	b := r.pendingAfterRelease(t)
	_ = b
}

func (r *adminRig) pendingAfterRelease(t *testing.T) *state.Approval {
	t.Helper()
	if code, out, errs := runAdmin(t, r.addr, "deny-all", "status"); code != 0 || !strings.Contains(out, "alice") || !strings.Contains(out, "drill") {
		t.Fatalf("status: %q %q", out, errs)
	}
	if code, out, _ := runAdmin(t, r.addr, "deny-all", "off"); code != 0 || !strings.Contains(out, "off") {
		t.Fatalf("off: %q", out)
	}
	return r.pending(t, "claude-laptop")
}

func TestAdminUnreachable(t *testing.T) {
	code, _, errs := runAdmin(t, "unix:"+filepath.Join(t.TempDir(), "none.sock"), "approvals", "list")
	if code != 1 || !strings.Contains(errs, "admin API") {
		t.Fatalf("%d %q", code, errs)
	}
	if code, _, errs := runAdmin(t, "ftp://x", "approvals", "list"); code != 1 || !strings.Contains(errs, "admin.url") {
		t.Fatalf("%d %q", code, errs)
	}
}
