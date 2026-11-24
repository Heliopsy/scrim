// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/redactscope"
	"github.com/heliopsy/scrim/internal/run"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

// openbaoRoot is the dev root token of the OpenBao container, generated per
// run.
var openbaoRoot = "root-" + podtest.RandHex(12)

// openbaoSvc is a dev-mode OpenBao in rootless podman, or the server
// SCRIM_TEST_OPENBAO_ADDR names (with its root token in
// SCRIM_TEST_OPENBAO_TOKEN).
var openbaoSvc = &podtest.Service{
	Name: "openbao", Env: "SCRIM_TEST_OPENBAO_ADDR", ImageEnv: "SCRIM_TEST_OPENBAO_IMAGE",
	Image:   "quay.io/openbao/openbao:2.7.3",
	Port:    "8200/tcp",
	Memory:  "256m",
	RunArgs: []string{"-e", "BAO_DEV_ROOT_TOKEN_ID=" + openbaoRoot},
	Args:    []string{"server", "-dev", "-dev-listen-address=0.0.0.0:8200"},
	Ready: func(ctx context.Context, addr string) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/sys/health", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("health: %d", resp.StatusCode)
		}
		return nil
	},
}

// bao calls OpenBao with token. Bodies are test setup.
func bao(t *testing.T, addr, token, method, path string, body any) map[string]any {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, addr+"/v1/"+path, r) //nolint:noctx // test setup
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return out
}

// TestEndToEndRealDataPlaneRedactionIdentity is the 12.2d verification, on
// the real data plane against OpenBao: agent-a has its own store credential
// whose policy reads only kv/agents/a; scrim's redaction identity reads
// both kv/agents/a and kv/prod/payments.
//
//   - Default: the payments value, which agent-a's own identity cannot read
//     (the store says so), is still redacted from agent-a's provider
//     request, as is its own value; the leak checker finds neither in what
//     the provider received or in the log.
//   - With the weakening setting redaction.limit-to-agent-identity: the
//     setting is listed as weakened and warned about; agent-a's session is
//     redacted only for what its identity can read, so the payments value
//     reaches the provider from that session and only from it. The same
//     request with no session, or with a token of agent-a's session id and
//     another secret, is redacted for both.
func TestEndToEndRealDataPlaneRedactionIdentity(t *testing.T) {
	bin := realDataPlane(t)
	addr := "http://" + openbaoSvc.Addr(t)
	t.Cleanup(openbaoSvc.Stop)
	root := openbaoRoot
	if v := os.Getenv("SCRIM_TEST_OPENBAO_TOKEN"); v != "" {
		root = v
	}
	mount := "kv-" + podtest.RandHex(4)
	bao(t, addr, root, "POST", "sys/mounts/"+mount, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
	payments := leak.NewSeed("payments", leak.KindPassword, seed(t, "pay-"))
	own := leak.NewSeed("own", leak.KindPassword, seed(t, "own-"))
	bao(t, addr, root, "POST", mount+"/data/prod/payments", map[string]any{"data": map[string]string{"key": payments.Value()}})
	bao(t, addr, root, "POST", mount+"/data/agents/a", map[string]any{"data": map[string]string{"key": own.Value()}})
	bao(t, addr, root, "PUT", "sys/policies/acl/scrim-redid-scrim", map[string]any{"policy": `
path "` + mount + `/data/*"     { capabilities = ["read"] }
path "` + mount + `/metadata/*" { capabilities = ["read", "list"] }
`})
	bao(t, addr, root, "PUT", "sys/policies/acl/scrim-redid-agent-a", map[string]any{"policy": `
path "` + mount + `/data/agents/a" { capabilities = ["read"] }
`})
	token := func(policy string) string {
		out := bao(t, addr, root, "POST", "auth/token/create", map[string]any{"policies": []string{policy}, "ttl": "30m"})
		tok, _ := out["auth"].(map[string]any)["client_token"].(string)
		if tok == "" {
			t.Fatal("no token")
		}
		return tok
	}
	scrimToken, agentToken := token("scrim-redid-scrim"), token("scrim-redid-agent-a")
	tokenEnv := []string{"SCRIM_TEST_BAO_TOKEN=" + scrimToken, "SCRIM_TEST_BAO_AGENT_A=" + agentToken}
	paymentsRef := "bao://" + mount + "/prod/payments"
	ownRef := "bao://" + mount + "/agents/a"

	checker := leak.NewChecker([]leak.Seed{payments, own})
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"log line: ` +
		payments.Value() + ` and ` + own.Value() + `"}]}`

	start := func(t *testing.T, extra ...string) (*harness, *Daemon, *fakeprovider.Server) {
		t.Helper()
		fake := fakeprovider.New(fakeprovider.Options{})
		up := httptest.NewServer(fake)
		t.Cleanup(up.Close)
		h := newHarness(t, seed(t, "tok-"))
		h.editConfig(t, harnessRedact, harnessRedact+`  bao:
    kind: openbao
    address: `+addr+`
    auth: {method: token}
    token: env:SCRIM_TEST_BAO_TOKEN
    redact: [`+paymentsRef+`, `+ownRef+`]
`)
		h.editConfig(t, "catalog:\n", `identity:
  peers:
    agent-a: "uid:`+fmt.Sprint(os.Getuid())+`"
  store-credentials:
    bao/agent-a: env:SCRIM_TEST_BAO_AGENT_A
catalog:
`)
		h.opts.Config.Environ = append(append(h.opts.Config.Environ, tokenEnv...), extra...)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		t.Cleanup(cancel)
		d := h.startReal(t, ctx, bin, up.URL)
		return h, d, fake
	}
	mint := func(t *testing.T, d *Daemon) (string, string) {
		t.Helper()
		mc := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
		defer mc.Close()
		m, err := mc.Mint(t.Context(), localapi.MintInput{Name: "redid"})
		if err != nil {
			t.Fatal(err)
		}
		if m.Session.Agent != "agent-a" {
			t.Fatalf("session agent %q", m.Session.Agent)
		}
		var tok string
		_ = m.Token.Expose(func(b []byte) error { tok = string(b); return nil })
		m.Token.Wipe()
		return m.Session.ID, tok
	}
	// send posts body with hdr and returns what the provider received.
	send := func(t *testing.T, d *Daemon, fake *fakeprovider.Server, hdr map[string]string) string {
		t.Helper()
		before := len(fake.Exchanges())
		if code := sendMessagesWith(t, t.Context(), d, body, hdr); code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		ex := fake.Exchanges()
		if len(ex) != before+1 {
			t.Fatalf("the provider saw %d new requests", len(ex)-before)
		}
		return string(ex[len(ex)-1].Body)
	}
	leaked := func(text string) map[string]bool {
		out := map[string]bool{}
		for _, f := range checker.CheckText(1, text) {
			out[f.Seed.Name] = true
		}
		return out
	}

	t.Run("default", func(t *testing.T) {
		h, d, fake := start(t)
		// The store refuses agent-a's own identity for the payments value
		// and allows its own path.
		access := d.App().PolicyParts.Gate.StoreAccess
		if access == nil {
			t.Fatal("no per-agent store identity")
		}
		a := identity.Identity{Agent: "agent-a", Source: identity.SourcePeer}
		if _, err := access.Check(t.Context(), a, nil, stores.OpRead, stores.MustParseRef(paymentsRef)); !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("agent-a reading payments: %v", err)
		}
		if _, err := access.Check(t.Context(), a, nil, stores.OpRead, stores.MustParseRef(ownRef)); err != nil {
			t.Fatalf("agent-a reading its own path: %v", err)
		}
		_, tok := mint(t, d)
		// Keep sending for longer than the weakening setting takes to narrow
		// the session's redaction (see the next subtest), so a narrowing
		// that should not happen would show.
		for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			got := send(t, d, fake, map[string]string{run.SessionHeader: tok})
			if l := leaked(got); len(l) > 0 {
				t.Fatalf("leaked to the provider from agent-a's session: %v", l)
			}
			if !strings.Contains(got, "⟦scrim:") {
				t.Fatalf("no placeholder: %s", got)
			}
		}
		if l := leaked(h.logs.String()); len(l) > 0 {
			t.Fatalf("leaked to the log: %v", l)
		}
		for _, w := range d.App().Config.Current().Weakened() {
			if w.Setting.Key == redactscope.LimitKey {
				t.Fatal("the weakening setting is on by default")
			}
		}
	})

	// The same narrowing with the session minted on replica A and the
	// request sent through replica B (state-and-scaling "Every replica
	// redacts scrim's own tokens", agent-identity "Stricter per-agent
	// redaction is weakening"), then the session revoked on A: B gives its
	// requests the whole redaction set again.
	t.Run("limit-to-agent-identity across replicas", func(t *testing.T) {
		dsn := pgtest.FreshDSN(t)
		env := append(replicaEnv(dsn), "SCRIM_REDACTION_LIMIT_TO_AGENT_IDENTITY=true")
		_, a, _ := start(t, env...)
		hb, b, fake := start(t, env...)
		within(t, "both events subscriptions", 15*time.Second, func() bool {
			return a.App().Events.Listening() && b.App().Events.Listening()
		})
		sid, tok := mint(t, a)
		eventually(t, "agent-a's exemption on B", func() bool {
			return strings.Contains(hb.logs.String(), "values this agent's own store identity cannot read are not redacted")
		})
		hdr := map[string]string{run.SessionHeader: tok}
		var got string
		for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			got = send(t, b, fake, hdr)
			if leaked(got)["payments"] || time.Now().After(deadline) {
				break
			}
		}
		if l := leaked(got); !l["payments"] || l["own"] {
			t.Fatalf("agent-a's session minted on A, through B: leaked %v, want payments only", l)
		}
		if l := leaked(send(t, b, fake, nil)); len(l) > 0 {
			t.Fatalf("no session, through B: leaked %v", l)
		}
		if err := a.runtime.Sessions.Revoke(t.Context(), sid, "test"); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(fast); ; time.Sleep(50 * time.Millisecond) {
			got = send(t, b, fake, hdr)
			if len(leaked(got)) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("B still narrows a session revoked on A: leaked %v", leaked(got))
			}
		}
		if l := leaked(hb.logs.String()); len(l) > 0 {
			t.Fatalf("leaked to the log: %v", l)
		}
	})

	t.Run("limit-to-agent-identity", func(t *testing.T) {
		h, d, fake := start(t, "SCRIM_REDACTION_LIMIT_TO_AGENT_IDENTITY=true")
		weak := false
		for _, w := range d.App().Config.Current().Weakened() {
			weak = weak || w.Setting.Key == redactscope.LimitKey
		}
		if !weak || !strings.Contains(h.logs.String(), "provider requests of these agents' scrim run sessions are not redacted") {
			t.Fatalf("the weakening setting is not reported or warned\n%s", h.logs.String())
		}
		sid, tok := mint(t, d)
		// The check runs in the background and the snapshot follows it.
		eventually(t, "agent-a's exemption", func() bool {
			return strings.Contains(h.logs.String(), "values this agent's own store identity cannot read are not redacted")
		})
		hdr := map[string]string{run.SessionHeader: tok}
		var got string
		deadline := time.Now().Add(15 * time.Second)
		for {
			got = send(t, d, fake, hdr)
			if leaked(got)["payments"] || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if l := leaked(got); !l["payments"] || l["own"] {
			t.Fatalf("agent-a's session: leaked %v, want payments only", l)
		}
		forged := tok[:len("scrim_st_")+len(sid)+1] + strings.Repeat("A", len(tok)-len("scrim_st_")-len(sid)-1)
		for what, hdr := range map[string]map[string]string{
			"no session":      nil,
			"bare session id": {run.SessionHeader: sid},
			"forged session":  {run.SessionHeader: forged},
		} {
			if l := leaked(send(t, d, fake, hdr)); len(l) > 0 {
				t.Errorf("%s: leaked %v", what, l)
			}
		}
		if l := leaked(h.logs.String()); len(l) > 0 {
			t.Fatalf("leaked to the log: %v", l)
		}
	})
}
