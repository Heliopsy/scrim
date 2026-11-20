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
	"net/url"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/leak"
)

// PassThrough returns a proxy that forwards every request unchanged.
func PassThrough(upstream *url.URL) http.Handler {
	return &forwarder{upstream: upstream, client: &http.Client{Transport: transport()}}
}

// forwarder relays one request and streams the response back, flushing
// after every read so streamed events pass through as they arrive.
type forwarder struct {
	upstream *url.URL
	client   *http.Client
	rewrite  func([]byte) []byte
	restore  func([]byte) []byte
}

func (f *forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read request", http.StatusBadGateway)
		return
	}
	if f.rewrite != nil {
		body = f.rewrite(body)
	}
	u := *f.upstream
	u.Path = strings.TrimRight(u.Path, "/") + r.URL.Path
	u.RawQuery = r.URL.RawQuery
	out, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build request", http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		if k == "Content-Length" || k == "Connection" {
			continue
		}
		out.Header[k] = vs
	}
	resp, err := f.client.Do(out)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range resp.Header {
		if k == "Content-Length" {
			continue
		}
		w.Header()[k] = vs
	}
	if f.restore != nil {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		b = f.restore(b)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(b)
		return
	}
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
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

// Naive returns a proxy that replaces each seed's verbatim and
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
	return &forwarder{
		upstream: upstream,
		client:   &http.Client{Transport: transport()},
		rewrite: func(b []byte) []byte {
			for _, p := range out {
				b = bytes.ReplaceAll(b, p.from, p.to)
			}
			return b
		},
		restore: func(b []byte) []byte {
			for _, p := range back {
				b = bytes.ReplaceAll(b, p.from, p.to)
			}
			return b
		},
	}
}
