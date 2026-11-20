// SPDX-License-Identifier: AGPL-3.0-only

// Package stub holds two stand-in proxies used to validate the leak suite
// itself: a pass-through proxy that forwards everything (the suite must
// report leaks against it) and a naive redactor that replaces only verbatim
// and JSON-escaped values (the suite must report exactly the leaks a
// verbatim-only redactor has). Neither is a redactor anyone should use.
package stub

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/leak"
)

// PassThrough returns a reverse proxy that forwards every request unchanged.
func PassThrough(upstream *url.URL) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.Transport = transport()
	rp.FlushInterval = -1
	return rp
}

// transport gives each stand-in its own connection pool, so it never shares
// connections with the harness client or another stand-in.
func transport() *http.Transport {
	return http.DefaultTransport.(*http.Transport).Clone()
}

// Placeholder renders the design D3 placeholder for a seed under key.
func Placeholder(key []byte, s leak.Seed) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s.Value()))
	slug := strings.NewReplacer("/", "-", "_", "-").Replace(s.Name)
	return "⟦scrim:" + slug + ":" + hex.EncodeToString(m.Sum(nil))[:16] + "⟧"
}

// Naive returns a reverse proxy that replaces each seed's verbatim and
// JSON-escaped forms in the request body with its placeholder, and restores
// placeholders in response bodies. It matches nothing else.
func Naive(upstream *url.URL, seeds []leak.Seed) http.Handler {
	key := []byte("scrim-leak-stub-key")
	type pair struct{ from, to []byte }
	var out []pair
	var back []pair
	for _, s := range seeds {
		ph := Placeholder(key, s)
		var esc bytes.Buffer
		enc := json.NewEncoder(&esc)
		enc.SetEscapeHTML(false) // clients do not escape < > &
		_ = enc.Encode(s.Value())
		q := bytes.TrimSpace(esc.Bytes())
		jsonForm := q[1 : len(q)-1]
		out = append(out, pair{jsonForm, []byte(ph)})
		if string(jsonForm) != s.Value() {
			out = append(out, pair{[]byte(s.Value()), []byte(ph)})
		}
		back = append(back, pair{[]byte(ph), jsonForm})
	}
	rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(upstream)
		pr.Out.Host = pr.In.Host
		r := pr.Out
		if r.Body == nil {
			return
		}
		b, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			b = nil
		}
		for _, p := range out {
			b = bytes.ReplaceAll(b, p.from, p.to)
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}, Transport: transport(), FlushInterval: -1}
	rp.ModifyResponse = func(resp *http.Response) error {
		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		for _, p := range back {
			b = bytes.ReplaceAll(b, p.from, p.to)
		}
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
		return nil
	}
	return rp
}
