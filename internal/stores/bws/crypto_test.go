// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// Known-answer tests against the official SDK.
//
// Vectors come from:
//   - bitwarden/sdk-internal at c5c08aebe8830f3c0fa54348b63f895137f2b827:
//     crates/bitwarden-core/src/auth/access_token.rs (can_decode_access_token,
//     malformed_tokens) and crates/bitwarden-crypto/src/keys/shareable_key.rs
//     (test_derive_shareable_key);
//   - bitwarden/sdk-sm at db735a12a8da505d99bec9498e3b21b4584acc6c:
//     crates/fake-server/src/routes.rs and README.md, whose recorded login
//     response and ciphertexts the SDK's own CLI and bindings tests run
//     against (constants in fake_test.go).

func plainOf(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func keyB64(t *testing.T, k bwcrypto.SymmetricKey) string {
	t.Helper()
	var s string
	_ = k.Value().Expose(func(b []byte) error { s = base64.StdEncoding.EncodeToString(b); return nil })
	return s
}

func TestAccessTokenKnownAnswer(t *testing.T) {
	tok, err := parseAccessToken(secret.FromString(officialToken))
	if err != nil {
		t.Fatal(err)
	}
	if tok.id != officialTokenID {
		t.Errorf("access token ID %q", tok.id)
	}
	if plainOf(t, tok.clientSecret) != officialSecret {
		t.Errorf("client secret mismatch")
	}
	const want = "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg=="
	if got := keyB64(t, tok.key); got != want {
		t.Errorf("derived key %s, want %s", got, want)
	}
}

func TestAccessTokenMalformed(t *testing.T) {
	// malformed_tokens: an unpadded key is accepted, the rest refused.
	if _, err := parseAccessToken(secret.FromString("0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ")); err != nil {
		t.Errorf("unpadded key refused: %v", err)
	}
	for _, bad := range []string{
		"1.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
		"0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw.X8vbvA0bduihIDe/qrzIQQ==",
		"ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
		"1.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe9qrzIQQ==",
		// Not from the SDK: a non-UUID ID and a key of the wrong length.
		"0.not-a-uuid.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
		"0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQX8vb",
	} {
		_, err := parseAccessToken(secret.FromString(bad))
		if err == nil {
			t.Errorf("accepted %q", bad)
			continue
		}
		if containsAny(err.Error(), "C2IgxjjLF7qSshsbwe8JGcbM075YXw", "X8vbvA0bduihIDe") {
			t.Errorf("error quotes the token: %v", err)
		}
	}
}

func TestDeriveShareableKeyKnownAnswer(t *testing.T) {
	for _, c := range []struct{ secret, name, info, want string }{
		{"&/$%F1a895g67HlX", "test_key", "", "4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe+ktR+U6qswxNnQ=="},
		{"67t9b5g67$%Dh89n", "test_key", "test", "F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++1LDW4iFD+infng=="},
	} {
		k, err := deriveShareableKey([]byte(c.secret), c.name, c.info)
		if err != nil {
			t.Fatal(err)
		}
		if got := keyB64(t, k); got != c.want {
			t.Errorf("derive(%q, %q, %q) = %s, want %s", c.secret, c.name, c.info, got, c.want)
		}
	}
}

// TestOfficialLogin decrypts the recorded login payload with the key derived
// from the recorded access token and reads the organisation from the
// recorded bearer token.
func TestOfficialLogin(t *testing.T) {
	tok, err := parseAccessToken(secret.FromString(officialToken))
	if err != nil {
		t.Fatal(err)
	}
	k, err := orgKeyFromPayload(tok.key, officialPayload)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyB64(t, k); got != officialOrgKey {
		t.Errorf("organization key %s", got)
	}
	org, err := jwtOrganization(secret.FromString(officialJWT))
	if err != nil || org != officialOrg {
		t.Errorf("organization %q, %v", org, err)
	}
	// Another token's key does not open the payload.
	other, _ := parseAccessToken(secret.FromString("0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:AAAAAAAAAAAAAAAAAAAAAA=="))
	if _, err := orgKeyFromPayload(other.key, officialPayload); err == nil {
		t.Errorf("payload decrypted under the wrong key")
	}
}

// officialBtwValue is the value of the secret GET /secrets/{id} returns in
// the SDK's fake server: 581 bytes of ASCII art.
const officialBtwValue = "" +
	"2.IYOGfBMSOI5qOxfYGHd6Rg==|0PBFivy/Qtp4lg4vv1+yPn/sDeRsNWmRnUYgwmAgPzUqZA9ZojvuggVSp/isPPc2mYO5UQfb" +
	"/co/81fDhQqopHrwat0l8SRB+sv/uEuomDdMkjaYl+jqblXebIDN42ZCy1wbERZgFmCMm3k1OIj1z5WHdRFGTWDLFlP316SgkAKO" +
	"waZF0eNmcQ90Py5Mrq9rKeVozsPWIL3aAXNchID6kJnqxbx717BxKQ9Vj/dMAaBlQoGrl/cYA6hoUBq7wOSMWkZ8PAorLhc3OSDw" +
	"GT/iamlAfePbkbjVqlTK2WrQ5ZHIo5Qzwpd/cvn6a0rSW5cPQ6DLrrOBdgDU3ELJ3eB+vZ/IWl9jXsCQ3re6Pv4pOToAMYDYEkC7" +
	"DlwbSiCWLegqbexwPNLRLa2hM9n+V8nVPgNic+LyakfsLqx1ReDFY0A7qRs7pE/EabYyj1O44HwZT3sSFKGYPlTBmQh6S21T7eGJ" +
	"4+OV+dhnFSpjiJ7IjOhfAzwq8cUiAeIEvKECBD++C+TsGwNAYK57F8Dd2gEwSaDhkiEPssa/c9ZBQnarNWzmZN1gj4udXRmsXqAY" +
	"6GcrZiLhBIpW2Yap8VVdgbQ9vwN77NzLfFW/FsdlAPB22dvjR1SzszgweG2QstGi9PcKY0Mp1zSvswWdGjdBpbfuExXBD62Fp+DW" +
	"OmFzWPo2MyqSQLaegvO4G+v8DRlf7VHA34Yvcbzv9Jtq4+H+Z7SkglRcQvKrn9uv7qOlZPvGJs1Ri86BAopXIGsj/5XfQTdtQdhs" +
	"4c0vviMSrNWtNvIgfg==|Z6BNqVlCknATGieykii0vF9xKu+JT3u2WqtbDhSYvkY="

func TestOfficialCiphertexts(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString(officialOrgKey)
	k, err := bwcrypto.NewSymmetricKey(secret.Adopt(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := officialCipher
	for enc, want := range map[string]string{
		c.prodName: c.plainProd, c.devName: c.plainDev, c.tuxKey: c.plainTuxKey, c.tuxValue: c.plainTux,
		c.tuxNote: c.plainEmpty, c.ferrisKey: c.plainFerris, c.ferrisNote: c.plainTEST,
		c.syncedKey: c.plainSyncedK, c.syncedValue: c.plainSyncedV, c.btwKey: c.plainBtw, c.btwNote: c.plainEmpty,
	} {
		v, err := k.DecryptString(enc)
		if err != nil {
			t.Errorf("%.12s: %v", enc, err)
			continue
		}
		if got := plainOf(t, v); got != want {
			t.Errorf("%.12s decrypts to %q, want %q", enc, got, want)
		}
	}
	v, err := k.DecryptString(officialBtwValue)
	if err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	_ = v.Expose(func(b []byte) error { sum = sha256.Sum256(b); return nil })
	if got := hex.EncodeToString(sum[:]); got != "035ebba2f7976aac45e51bbad30c35afb4b89474dd73927d3d9989d23626b7a9" || v.Len() != 581 {
		t.Errorf("long value: %d bytes, sha256 %s", v.Len(), got)
	}
}
