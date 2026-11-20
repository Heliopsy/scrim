// SPDX-License-Identifier: AGPL-3.0-only

package bwcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
)

// Known-answer vectors computed independently with Python's hashlib and the
// cryptography package (PBKDF2, HKDF-Expand, AES-CBC, HMAC) and Node's
// crypto.argon2Sync (Argon2id). The inputs are test strings, not secrets.
const (
	katPassword   = "scrim-kat-password"
	katEmail      = " KAT@Example.com " // normalised to kat@example.com
	katMKPBKDF2   = "11ab4dfc31046187b8c1980e05902fa91600a9afb5f320cb5c94c21aa5c16742"
	katMPH        = "v/kxH1Er2fsH6drFH9w37ni6PaxoDIkUJsJel50eNGM="
	katStretchEnc = "6b4ccba05e4359fc6a106c1c0b480c7f75c53d18f6e2adddf198f7925e2b0cee"
	katStretchMAC = "e9fc22b19c03991ff063a3d8c2db951fc75100cb00c1e1f070f0ce56cd91561c"
	katEncString  = "2.AAECAwQFBgcICQoLDA0ODw==|KrC2BGlT0lckYTBHJB4b/A==|W9RMmS3uK3zVPqaV9YENIoAjPmDM7dJTrCUVZU6k/eQ="
	katPlaintext  = "kat-plaintext"
	katMKArgon2   = "22a3a4cb6a8f77c87a8a62268614ca77e3530200a926982705757eb78efb0f92"
)

func hexOf(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	if err := v.Expose(func(b []byte) error { s = hex.EncodeToString(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func str(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	if err := v.Expose(func(b []byte) error { s = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func randomValue(t *testing.T, n int) secret.Value {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return secret.Adopt(b)
}

func TestMasterKeyPBKDF2KnownAnswer(t *testing.T) {
	pw := secret.FromString(katPassword)
	mk, err := MasterKey(pw, katEmail, KDFParams{Type: KDFPBKDF2, Iterations: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if got := hexOf(t, mk); got != katMKPBKDF2 {
		t.Fatalf("master key mismatch")
	}
	h, err := MasterPasswordHash(mk, pw)
	if err != nil {
		t.Fatal(err)
	}
	if str(t, h) != katMPH {
		t.Fatalf("master password hash mismatch")
	}
	sk, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if got := hexOf(t, sk.Value()); got != katStretchEnc+katStretchMAC {
		t.Fatalf("stretched key mismatch")
	}
	pt, err := sk.DecryptString(katEncString)
	if err != nil {
		t.Fatal(err)
	}
	if str(t, pt) != katPlaintext {
		t.Fatalf("decrypted plaintext mismatch")
	}
}

func TestMasterKeyArgon2idKnownAnswer(t *testing.T) {
	mk, err := MasterKey(secret.FromString(katPassword), katEmail, DefaultArgon2id())
	if err != nil {
		t.Fatal(err)
	}
	if got := hexOf(t, mk); got != katMKArgon2 {
		t.Fatalf("argon2id master key mismatch")
	}
}

func TestKDFBounds(t *testing.T) {
	bad := []KDFParams{
		{Type: KDFPBKDF2, Iterations: 4999},
		{Type: KDFPBKDF2, Iterations: PBKDF2MaxIterations + 1},
		{Type: KDFArgon2id, Iterations: 1, MemoryMiB: 64, Parallelism: 4},
		{Type: KDFArgon2id, Iterations: 3, MemoryMiB: 15, Parallelism: 4},
		{Type: KDFArgon2id, Iterations: 3, MemoryMiB: 1 << 20, Parallelism: 4},
		{Type: KDFArgon2id, Iterations: 3, MemoryMiB: 64, Parallelism: 0},
		{Type: KDFArgon2id, Iterations: 3, MemoryMiB: 64, Parallelism: 17},
		{Type: 7, Iterations: 600000},
	}
	for _, p := range bad {
		if _, err := MasterKey(secret.FromString("x"), "a@b", p); !errors.Is(err, ErrKDFParams) {
			t.Errorf("%+v: want ErrKDFParams, got %v", p, err)
		}
	}
	if err := DefaultPBKDF2().Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := MasterKey(secret.Value{}, "a@b", DefaultPBKDF2()); err == nil {
		t.Fatal("empty password accepted")
	}
	if _, err := MasterKey(secret.FromString("x"), "  ", DefaultPBKDF2()); err == nil {
		t.Fatal("empty email accepted")
	}
}

func TestSymmetricRoundTrip(t *testing.T) {
	k, err := GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1000} {
		pt := randomValue(t, n)
		e, err := k.Encrypt(pt)
		if err != nil {
			t.Fatal(err)
		}
		if e.Type != EncAESCBC256HMACSHA256B64 || len(e.IV) != 16 || len(e.MAC) != 32 {
			t.Fatalf("unexpected EncString shape for %d bytes", n)
		}
		parsed, err := ParseEncString(e.String())
		if err != nil {
			t.Fatal(err)
		}
		got, err := k.Decrypt(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(pt) {
			t.Fatalf("round trip of %d bytes failed", n)
		}
	}
}

func TestEncryptUsesFreshIV(t *testing.T) {
	k, _ := GenerateSymmetricKey()
	pt := randomValue(t, 24)
	a, _ := k.Encrypt(pt)
	b, _ := k.Encrypt(pt)
	if bytes.Equal(a.IV, b.IV) || bytes.Equal(a.Data, b.Data) {
		t.Fatal("two encryptions share IV or ciphertext")
	}
}

// Every bit of IV, ciphertext and MAC is covered by the MAC: flipping any of
// them must fail with ErrMAC before decryption.
func TestDecryptRejectsTampering(t *testing.T) {
	k, _ := GenerateSymmetricKey()
	e, _ := k.Encrypt(randomValue(t, 40))
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 0x01
		return c
	}
	cases := map[string]EncString{}
	for i := range e.IV {
		cases[fmt.Sprintf("iv[%d]", i)] = EncString{Type: e.Type, IV: flip(e.IV, i), Data: e.Data, MAC: e.MAC}
	}
	for i := range e.Data {
		cases[fmt.Sprintf("data[%d]", i)] = EncString{Type: e.Type, IV: e.IV, Data: flip(e.Data, i), MAC: e.MAC}
	}
	for i := range e.MAC {
		cases[fmt.Sprintf("mac[%d]", i)] = EncString{Type: e.Type, IV: e.IV, Data: e.Data, MAC: flip(e.MAC, i)}
	}
	for name, c := range cases {
		if _, err := k.Decrypt(c); !errors.Is(err, ErrMAC) {
			t.Fatalf("%s: want ErrMAC, got %v", name, err)
		}
	}
	other, _ := GenerateSymmetricKey()
	if _, err := other.Decrypt(e); !errors.Is(err, ErrMAC) {
		t.Fatalf("wrong key: want ErrMAC, got %v", err)
	}
}

func TestDecryptRefusesUnauthenticatedTypes(t *testing.T) {
	k, _ := GenerateSymmetricKey()
	iv := base64.StdEncoding.EncodeToString(make([]byte, 16))
	ct := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for _, s := range []string{
		"0." + iv + "|" + ct,
		iv + "|" + ct, // legacy unprefixed type 0
		"1." + iv + "|" + ct + "|" + ct,
		"4." + ct,
	} {
		if _, err := k.DecryptString(s); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%q: want ErrUnsupported, got %v", s, err)
		}
	}
}

func TestBadPaddingAfterValidMAC(t *testing.T) {
	// Encrypt a full block of zero bytes without padding by hand, then MAC
	// it correctly: the MAC passes and padding must be refused.
	k, _ := GenerateSymmetricKey()
	e, _ := k.Encrypt(randomValue(t, 16)) // 32 bytes ciphertext
	// Truncate to the first block and re-MAC: last plaintext byte is random,
	// so padding is invalid with probability 1-1/256 per attempt; retry.
	for range 64 {
		trunc := EncString{Type: e.Type, IV: e.IV, Data: e.Data[:16]}
		_ = k.expose(func(_, mac []byte) error {
			trunc.MAC = macOf(mac, trunc.IV, trunc.Data)
			return nil
		})
		_, err := k.Decrypt(trunc)
		if errors.Is(err, ErrPadding) {
			return
		}
		e, _ = k.Encrypt(randomValue(t, 16))
	}
	t.Fatal("padding was never rejected")
}

func TestParseEncStringErrors(t *testing.T) {
	for _, s := range []string{"", "9.abc", "x.abc", "2.a|b", "2.!!|!!|!!", "3.a|b", "nopipes"} {
		if _, err := ParseEncString(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: want ErrMalformed, got %v", s, err)
		}
	}
	k, _ := GenerateSymmetricKey()
	short := EncString{Type: EncAESCBC256HMACSHA256B64, IV: []byte{1}, Data: make([]byte, 16), MAC: make([]byte, 32)}
	if _, err := k.Decrypt(short); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short IV: %v", err)
	}
}

func TestKeysNeverPrint(t *testing.T) {
	k, _ := GenerateSymmetricKey()
	raw := hexOf(t, k.Value())
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		out := fmt.Sprintf(f, k)
		if strings.Contains(out, raw) || !strings.Contains(out, secret.Marker) {
			t.Fatalf("%s printed key material or no marker: %q", f, out)
		}
	}
	reg, err := NewRegistration(secret.FromString("pw-"+t.Name()), "a@example.com", KDFParams{Type: KDFPBKDF2, Iterations: 5000})
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Wipe()
	pk, err := DecryptPrivateKey(reg.UserKey, reg.Keys.EncryptedPrivateKey.String())
	if err != nil {
		t.Fatal(err)
	}
	if out := fmt.Sprintf("%v %+v %#v", pk, pk, pk); strings.Contains(out, "N:") || !strings.Contains(out, secret.Marker) {
		t.Fatalf("private key printed: %q", out)
	}
}

func TestWipedKeyRefuses(t *testing.T) {
	k, _ := GenerateSymmetricKey()
	e, _ := k.Encrypt(randomValue(t, 8))
	k.Wipe()
	if _, err := k.Decrypt(e); !errors.Is(err, ErrKey) {
		t.Fatalf("wiped key: %v", err)
	}
	if _, err := NewSymmetricKey(randomValue(t, 32)); !errors.Is(err, ErrKey) {
		t.Fatalf("32-byte key accepted: %v", err)
	}
}

func TestRegistrationUnlockAndOrgKey(t *testing.T) {
	pw := randomValue(t, 20)
	email := "Agent@Example.com"
	for _, p := range []KDFParams{{Type: KDFPBKDF2, Iterations: 5000}, {Type: KDFArgon2id, Iterations: 2, MemoryMiB: 16, Parallelism: 1}} {
		t.Run(p.Type.String(), func(t *testing.T) {
			reg, err := NewRegistration(pw, email, p)
			if err != nil {
				t.Fatal(err)
			}
			defer reg.Wipe()
			uk, err := UnlockUserKey(pw, "agent@example.com", p, reg.ProtectedUserKey.String())
			if err != nil {
				t.Fatal(err)
			}
			if !uk.Value().Equal(reg.UserKey.Value()) {
				t.Fatal("unlocked user key differs")
			}
			if _, err := UnlockUserKey(randomValue(t, 20), email, p, reg.ProtectedUserKey.String()); !errors.Is(err, ErrMAC) {
				t.Fatalf("wrong password: want ErrMAC, got %v", err)
			}

			// Organisation key: wrapped for the account's public key, as the
			// server hands it out, then unwrapped with the private key.
			pub, err := ParsePublicKey(reg.Keys.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			orgKey, _ := GenerateSymmetricKey()
			wrapped, err := EncryptRSA(pub, orgKey.Value())
			if err != nil {
				t.Fatal(err)
			}
			pk, err := DecryptPrivateKey(uk, reg.Keys.EncryptedPrivateKey.String())
			if err != nil {
				t.Fatal(err)
			}
			got, err := pk.DecryptKey(wrapped.String())
			if err != nil {
				t.Fatal(err)
			}
			if !got.Value().Equal(orgKey.Value()) {
				t.Fatal("org key differs")
			}
			if _, err := pk.DecryptKey("2." + strings.Repeat("A", 4) + "|A|A"); err == nil {
				t.Fatal("symmetric EncString accepted as RSA")
			}
		})
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	k, _ := GenerateSymmetricKey()
	e, err := k.EncryptMetadata("GitHub")
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.DecryptMetadata(e.String())
	if err != nil || got != "GitHub" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := k.DecryptMetadata(""); got != "" || err != nil {
		t.Fatal("empty metadata should decrypt to empty")
	}
}

func FuzzParseEncString(f *testing.F) {
	f.Add(katEncString)
	f.Add("4.AAAA")
	f.Add("AAAA|AAAA")
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseEncString(s)
		if err != nil {
			return
		}
		k, _ := GenerateSymmetricKey()
		_, _ = k.Decrypt(e) // must not panic
	})
}
