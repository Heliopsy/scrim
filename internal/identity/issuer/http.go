// SPDX-License-Identifier: AGPL-3.0-only

package issuer

import (
	"net/http"
	"net/url"
	"strings"
)

// Handler serves the discovery document and the JWKS at their paths under
// the issuer URL's path, and nothing else. Both are public: they hold
// public keys only.
func (i *Issuer) Handler() http.Handler {
	u, _ := url.Parse(i.url)
	base := strings.TrimSuffix(u.EscapedPath(), "/")
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+DiscoveryPath, func(w http.ResponseWriter, _ *http.Request) {
		writePublic(w, i.discovery)
	})
	mux.HandleFunc("GET "+base+JWKSPath, func(w http.ResponseWriter, _ *http.Request) {
		i.mu.Lock()
		b := i.jwks
		i.mu.Unlock()
		writePublic(w, b)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	return mux
}

// writePublic sends a public JSON document. A verifier may cache it for
// five minutes: the next key is published a whole rotation period before
// it signs, so a cached JWKS always holds the signing key.
func writePublic(w http.ResponseWriter, b []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}
