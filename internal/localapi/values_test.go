// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/secret"
)

func TestValuesFramingRoundTrip(t *testing.T) {
	in := []NamedValue{{Name: ".env#A_TOKEN", Value: secret.FromString("value-one-123")},
		{Name: "config/app.yaml#password", Value: secret.FromString("value\x00two\n")}}
	body, err := EncodeValues(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeValues(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Name != in[0].Name || !out[1].Value.Equal(in[1].Value) {
		t.Fatalf("round trip lost values: %d", len(out))
	}
	for _, bad := range [][]byte{{0xff}, {3, 'a'}, {1, 'a', 0}, {1, 'a', 9, 'x'}} {
		if _, err := DecodeValues(bad); err == nil {
			t.Errorf("DecodeValues(%v) accepted a malformed body", bad)
		}
	}
}

func TestSessionValuesRoute(t *testing.T) {
	var mu sync.Mutex
	got := map[string]map[string]string{}
	var ended []string
	h := startWith(t, func(s *Server) {
		s.SessionValues = func(_ context.Context, sid string, vs []NamedValue) error {
			mu.Lock()
			defer mu.Unlock()
			m := map[string]string{}
			for _, v := range vs {
				_ = v.Value.Expose(func(b []byte) error { m[v.Name] = string(b); return nil })
				v.Value.Wipe()
			}
			got[sid] = m
			return nil
		}
		s.SessionEnded = func(id string) { mu.Lock(); ended = append(ended, id); mu.Unlock() }
	})
	val := "proj-" + strings.Repeat("9f", 12)
	vals := []NamedValue{{Name: ".env#API_TOKEN", Value: secret.FromString(val)}}

	// Only a session registers values.
	if _, err := h.peer.RegisterValues(bg, vals); codeOf(t, err) != agenttools.CodeInvalid {
		t.Fatalf("peer registration: %v", err)
	}
	m, err := h.peer.Mint(bg, MintInput{Name: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(h.socket, m.Token)
	defer c.Close()
	out, err := c.RegisterValues(bg, vals)
	if err != nil || out.Registered != 1 {
		t.Fatalf("register: %v %+v", err, out)
	}
	mu.Lock()
	if got[m.Session.ID][".env#API_TOKEN"] != val {
		t.Errorf("the server did not receive the value for session %s", m.Session.ID)
	}
	mu.Unlock()
	if vals[0].Value.Wiped() {
		t.Error("RegisterValues wiped the caller's value")
	}
	raw, _ := json.Marshal(h.audit.All())
	if strings.Contains(string(raw), val) {
		t.Error("the audit log holds a registered value")
	}
	if !strings.Contains(string(raw), ToolSessionValues) {
		t.Error("the registration is not audited")
	}
	if err := c.EndSession(bg); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ended) != 1 || ended[0] != m.Session.ID {
		t.Errorf("SessionEnded got %v, want the ended session", ended)
	}
}
