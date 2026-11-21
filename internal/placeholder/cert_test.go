// SPDX-License-Identifier: AGPL-3.0-only

package placeholder

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

// testdata/cert.json holds placeholder certificate public keys the data
// plane checks too (scrim-toolproxy `clientcert::tests::shared_vector`).
func TestClientCertificateVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/cert.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Placeholder  string `json:"placeholder"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		got := hex.EncodeToString(ClientCertificateKey(r.Placeholder).Public().(ed25519.PublicKey))
		if got != r.PublicKeyHex {
			t.Errorf("%s: got %s, want %s", r.Placeholder, got, r.PublicKeyHex)
		}
	}
}

func TestClientCertificateLoadsAsTLSKeyPair(t *testing.T) {
	ph := "⟦scrim:kind-admin:01aabbccddeeff0011⟧"
	c, k, err := ClientCertificate(ph, "scrim placeholder kind-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(c, k); err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(c)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(ed25519.PublicKey).Equal(ClientCertificateKey(ph).Public()) {
		t.Fatal("certificate key is not the derived key")
	}
}
