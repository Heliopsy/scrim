// SPDX-License-Identifier: AGPL-3.0-only

package tokenseal_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/tokenseal"
)

func ring(t *testing.T, versions ...int) (*placeholder.Ring, [][]byte) {
	t.Helper()
	r := &placeholder.Ring{}
	var raw [][]byte
	for _, v := range versions {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		raw = append(raw, bytes.Clone(k))
		r.Keys = append(r.Keys, placeholder.Key{Version: v, Key: secret.New(k)})
	}
	t.Cleanup(r.Wipe)
	return r, raw
}

func sealer(t *testing.T, r *placeholder.Ring) *tokenseal.Sealer {
	t.Helper()
	s, err := tokenseal.New(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Wipe)
	return s
}

func token(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 33)
	_, _ = rand.Read(b)
	return []byte("scrim_st_" + hex.EncodeToString(b))
}

func open(t *testing.T, s *tokenseal.Sealer, kind, id string, v int, sealed []byte) ([]byte, error) {
	t.Helper()
	val, err := s.Open(kind, id, v, sealed)
	if err != nil {
		return nil, err
	}
	defer val.Wipe()
	var out []byte
	_ = val.Expose(func(b []byte) error { out = bytes.Clone(b); return nil })
	return out, nil
}

// A token sealed by one process opens in another built from the same keys,
// and only as the row it was sealed for.
func TestSealOpen(t *testing.T) {
	r, raw := ring(t, 2, 1)
	a := sealer(t, r)
	tok := token(t)
	v, sealed, err := a.Seal("session", "s1", tok)
	if err != nil || v != 2 {
		t.Fatalf("Seal: v%d, %v", v, err)
	}
	// No form of the token is in the sealed bytes.
	for _, form := range [][]byte{tok, []byte(hex.EncodeToString(tok)), []byte(base64.StdEncoding.EncodeToString(tok)), tok[9:25]} {
		if bytes.Contains(sealed, form) {
			t.Fatal("sealed bytes contain the token")
		}
	}
	// Another process with the same placeholder keys.
	r2 := &placeholder.Ring{Keys: []placeholder.Key{{Version: 2, Key: secret.New(raw[0])}, {Version: 1, Key: secret.New(raw[1])}}}
	defer r2.Wipe()
	b := sealer(t, r2)
	got, err := open(t, b, "session", "s1", v, sealed)
	if err != nil || !bytes.Equal(got, tok) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if b.ID(tok) != a.ID(tok) {
		t.Fatal("IDs differ across processes with the same keys")
	}
	// Two seals of the same token differ (random nonce).
	_, again, _ := a.Seal("session", "s1", tok)
	if bytes.Equal(again, sealed) {
		t.Fatal("two seals are identical")
	}

	flipped := bytes.Clone(sealed)
	flipped[len(flipped)/2] ^= 1
	for name, tc := range map[string]struct {
		kind, id string
		v        int
		sealed   []byte
		want     error
	}{
		"other kind":    {"kubernetes", "s1", v, sealed, tokenseal.ErrOpen},
		"other id":      {"session", "s2", v, sealed, tokenseal.ErrOpen},
		"other version": {"session", "s1", 1, sealed, tokenseal.ErrOpen},
		"missing ver":   {"session", "s1", 3, sealed, tokenseal.ErrUnknownVersion},
		"flipped bit":   {"session", "s1", v, flipped, tokenseal.ErrOpen},
		"truncated":     {"session", "s1", v, sealed[:10], tokenseal.ErrOpen},
	} {
		if got, err := open(t, b, tc.kind, tc.id, tc.v, tc.sealed); !errors.Is(err, tc.want) || got != nil {
			t.Errorf("%s: %q, %v; want %v", name, got, err, tc.want)
		}
	}
}

// Rows sealed before a rotation still open while the ring keeps the old
// version; other keys open nothing.
func TestRotationAndOtherKeys(t *testing.T) {
	r1, raw := ring(t, 1)
	old := sealer(t, r1)
	tok := token(t)
	v, sealed, _ := old.Seal("issuer", old.ID(tok), tok)
	id := old.ID(tok)

	k2 := make([]byte, 32)
	_, _ = rand.Read(k2)
	rotated := &placeholder.Ring{Keys: []placeholder.Key{{Version: 2, Key: secret.New(k2)}, {Version: 1, Key: secret.New(raw[0])}}}
	defer rotated.Wipe()
	nw := sealer(t, rotated)
	if got, err := open(t, nw, "issuer", id, v, sealed); err != nil || !bytes.Equal(got, tok) {
		t.Fatalf("old row after rotation: %q, %v", got, err)
	}
	if nw.Version() != 2 || nw.ID(tok) == id {
		t.Fatal("new rows do not use the current key")
	}

	other, _ := ring(t, 1)
	if _, err := open(t, sealer(t, other), "issuer", id, v, sealed); !errors.Is(err, tokenseal.ErrOpen) {
		t.Fatalf("another ring opened the row: %v", err)
	}
}

func TestNoKeys(t *testing.T) {
	if _, err := tokenseal.New(&placeholder.Ring{}); err == nil {
		t.Fatal("a sealer without keys")
	}
}
