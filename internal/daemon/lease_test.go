// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

func TestLeaseOwnedAndShared(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_PROXY_CHAIN_URL=http://127.0.0.1:8787")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	own, err := Acquire(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if own.Shared() {
		t.Fatal("first lease reused a daemon that does not exist")
	}
	ep := own.Endpoints()
	if !strings.HasPrefix(ep.LLMBaseURL, "http://127.0.0.1:") || !strings.HasPrefix(ep.ForwardProxy, "http://127.0.0.1:") ||
		ep.APISocket == "" || ep.Routes["anthropic"] != "/anthropic" || !bytes.Contains(ep.CACertPEM, []byte("BEGIN CERTIFICATE")) ||
		strings.Join(ep.Bypass, ",") != "127.0.0.1:8787" {
		t.Fatalf("endpoints = %+v", ep)
	}
	if err := own.Ready(ctx); err != nil {
		t.Fatal(err)
	}

	shared, err := Acquire(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if !shared.Shared() {
		t.Fatal("second lease started another daemon")
	}
	sep := shared.Endpoints()
	if sep.LLMBaseURL != ep.LLMBaseURL || !bytes.Equal(sep.CACertPEM, ep.CACertPEM) || sep.APISocket != ep.APISocket {
		t.Fatalf("shared endpoints = %+v, own = %+v", sep, ep)
	}
	if err := shared.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := shared.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := own.Ready(ctx); err != nil {
		t.Fatal("releasing the shared lease stopped the daemon")
	}
	if err := own.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := shared.Ready(ctx); err == nil {
		t.Fatal("daemon still answers after its owner released it")
	}
}

// A minted session token is redacted like any store value.
func TestSessionTokenRedacted(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	c := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
	defer c.Close()
	m, err := c.Mint(ctx, localapi.MintInput{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var tok string
	_ = m.Token.Expose(func(b []byte) error { tok = string(b); return nil })
	if !strings.HasPrefix(tok, "scrim_st_") {
		t.Fatalf("token shape %q", tok[:min(len(tok), 9)])
	}
	eventually(t, "the session token in a snapshot", func() bool {
		for _, v := range h.snapshot(t).GetValues() {
			if string(v.GetValue()) == tok {
				return len(v.GetBoundHosts()) == 0
			}
		}
		return false
	})
	if strings.Contains(h.logs.String(), tok) {
		t.Fatal("the session token reached the log")
	}
	rt := d.Info().Runtime
	modes := strings.Join(rt.Interception, "; ")
	if rt.Sessions != 1 || !strings.Contains(modes, "wrapper (1 scrim run session(s))") || !strings.Contains(modes, "base-url http://127.0.0.1:") ||
		!strings.Contains(modes, "forward-proxy http://127.0.0.1:") {
		t.Fatalf("runtime = %+v", rt)
	}
	for _, p := range rt.Protections {
		if p.Name == "redaction" && !p.Active || p.Name == "direct egress blocked" && p.Active {
			t.Fatalf("protections = %+v", rt.Protections)
		}
	}
	if st := (Info{}).StatusDataPlane(); st.Running || st.Healthy {
		t.Fatalf("empty info claims a running data plane: %+v", st)
	}
}
