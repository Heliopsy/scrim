// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
)

// TestEndToEndRealDataPlaneSharedTokens is specs/state-and-scaling "Every
// replica redacts scrim's own tokens" through the real data plane: two
// replicas share PostgreSQL state, a session is minted through replica A as
// `scrim run` mints it, and the agent's provider request carrying its token
// goes through replica B. The fake provider receives a placeholder for the
// token and the leak checker finds it in no request and no log, with each
// events backend. Before tokens were shared, B forwarded the token as is.
func TestEndToEndRealDataPlaneSharedTokens(t *testing.T) {
	bin := realDataPlane(t)
	for _, backend := range []string{"postgres", "valkey", "nats"} {
		t.Run(backend, func(t *testing.T) {
			fake := fakeprovider.New(fakeprovider.Options{})
			up := httptest.NewServer(fake)
			t.Cleanup(up.Close)
			dsn := pgtest.FreshDSN(t)
			env := append(replicaEnv(dsn), eventsEnv(t, backend)...)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			t.Cleanup(cancel)
			start := func() (*harness, *Daemon) {
				h := newHarness(t, seed(t, "tok-"))
				h.opts.Config.Environ = append(h.opts.Config.Environ, env...)
				return h, h.startReal(t, ctx, bin, up.URL)
			}
			ha, a := start()
			hb, b := start()
			within(t, "both events subscriptions", 15*time.Second, func() bool {
				return a.App().Events.Listening() && b.App().Events.Listening()
			})
			values := func(d *Daemon) uint32 {
				st, err := d.Supervisor().Status(ctx)
				if err != nil {
					return 0
				}
				return st.GetValueCount()
			}
			before := values(b)

			mc := localapi.NewClient(a.Addrs().AgentAPI, secret.Value{})
			m, err := mc.Mint(ctx, localapi.MintInput{Name: "shared"})
			mc.Close()
			if err != nil {
				t.Fatalf("mint on A: %v\n%s", err, ha.logs.String())
			}
			var tok string
			_ = m.Token.Expose(func(b []byte) error { tok = string(b); return nil })
			m.Token.Wipe()
			sid := m.Session.ID
			took := within(t, "B's data plane holds the token", fast, func() bool { return values(b) > before })
			t.Logf("%s: the token minted on A was in B's data plane after %s", backend, took)

			checker := leak.NewChecker([]leak.Seed{leak.NewSeed("session", leak.KindAPIKey, tok, identity.TokenPrefix+sid+"_")})
			// The agent prints its own SCRIM_SESSION_TOKEN into a prompt that
			// goes through B.
			body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"env: SCRIM_SESSION_TOKEN=` +
				tok + `"}]}`
			n := len(fake.Exchanges())
			if code := sendMessages(t, ctx, b, body); code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			ex := fake.Exchanges()
			if len(ex) != n+1 {
				t.Fatalf("the provider saw %d requests", len(ex)-n)
			}
			got := string(ex[len(ex)-1].Body)
			if f := checker.CheckText(1, got); len(f) > 0 {
				t.Fatalf("B forwarded the session token minted on A: %v", f)
			}
			if !strings.Contains(got, "⟦scrim:") {
				t.Fatalf("no placeholder in what the provider received: %s", got)
			}
			for _, l := range []string{ha.logs.String(), hb.logs.String()} {
				if f := checker.CheckText(1, l); len(f) > 0 {
					t.Fatalf("the token reached a log: %v", f)
				}
			}
		})
	}
}
