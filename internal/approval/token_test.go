// SPDX-License-Identifier: AGPL-3.0-only

package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

func key(b byte) secret.Value {
	return secret.New([]byte(strings.Repeat(string(rune('a'+b)), MinKeyLen)))
}

func TestTokenRoundTrip(t *testing.T) {
	s, err := NewSigner("k1", map[string]secret.Value{"k1": key(0)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tok, err := s.Mint("appr-a", ActionApprove, now.Add(time.Minute), "ntfy")
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Verify(tok, "appr-a", now)
	if err != nil || c.Action != ActionApprove || c.Via != "ntfy" {
		t.Fatalf("claims %+v, %v", c, err)
	}
	if _, err := s.Verify(tok, "appr-b", now); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("token for A accepted for B: %v", err)
	}
	if _, err := s.Verify(tok, "appr-a", now.Add(time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token accepted: %v", err)
	}
	// Flip one character of each part in turn.
	parts := strings.Split(tok, ".")
	for i := range parts {
		p := append([]string(nil), parts...)
		b := []byte(p[i])
		b[len(b)/2] ^= 1
		p[i] = string(b)
		if _, err := s.Verify(strings.Join(p, "."), "appr-a", now); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("tampered part %d accepted: %v", i, err)
		}
	}
	for _, bad := range []string{"", "v1", "v1.k1.x.y", "v2." + strings.Join(parts[1:], "."), tok + ".x"} {
		if _, err := s.Verify(bad, "appr-a", now); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("%q accepted: %v", bad, err)
		}
	}
	other, _ := NewSigner("k1", map[string]secret.Value{"k1": key(1)})
	if _, err := other.Verify(tok, "appr-a", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("token verified under another key: %v", err)
	}
}

func TestTokenRotation(t *testing.T) {
	old, _ := NewSigner("k1", map[string]secret.Value{"k1": key(0)})
	now := time.Now()
	tok, _ := old.Mint("a", ActionDeny, now.Add(time.Minute), "")
	rotated, err := NewSigner("k2", map[string]secret.Value{"k1": key(0), "k2": key(1)})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := rotated.Verify(tok, "a", now); err != nil || c.Action != ActionDeny {
		t.Fatalf("old-key token after rotation: %+v %v", c, err)
	}
	fresh, _ := rotated.Mint("a", ActionDeny, now.Add(time.Minute), "")
	if !strings.HasPrefix(fresh, "v1.k2.") {
		t.Fatalf("not signed with current key: %s", fresh[:8])
	}
	dropped, _ := NewSigner("k2", map[string]secret.Value{"k2": key(1)})
	if _, err := dropped.Verify(tok, "a", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("token of a removed key accepted")
	}
}

func TestSignerRejectsWeakKeys(t *testing.T) {
	if _, err := NewSigner("k", map[string]secret.Value{"k": secret.New([]byte("short"))}); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := NewSigner("missing", map[string]secret.Value{"k": key(0)}); err == nil {
		t.Fatal("missing current key accepted")
	}
	if _, err := NewSigner("K!", map[string]secret.Value{"K!": key(0)}); err == nil {
		t.Fatal("bad key ID accepted")
	}
}

func TestTokenFromLink(t *testing.T) {
	id, tok, err := TokenFromLink("https://scrim.example/v1/approvals/abc/decide?t=v1.k.p.s")
	if err != nil || id != "abc" || tok != "v1.k.p.s" {
		t.Fatalf("%q %q %v", id, tok, err)
	}
	if _, _, err := TokenFromLink("/v1/approvals/abc/decide"); err == nil {
		t.Fatal("link without token accepted")
	}
	if _, _, err := TokenFromLink("/v1/approvals/abc?t=x"); err == nil {
		t.Fatal("non-decide link accepted")
	}
}
