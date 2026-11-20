// SPDX-License-Identifier: AGPL-3.0-only

package vwtest

import (
	"encoding/pem"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// TLSFront serves the server over HTTPS with a throwaway certificate for
// 127.0.0.1, for clients that refuse plain http. It returns the HTTPS URL and
// a PEM file holding the certificate to trust.
func (s *Server) TLSFront(t testing.TB) (string, string) {
	t.Helper()
	target, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	t.Cleanup(ts.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return ts.URL, ca
}
