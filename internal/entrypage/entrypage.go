// SPDX-License-Identifier: AGPL-3.0-only

// Package entrypage serves the page where a human types a value an agent
// asked for with secret_ask_human. The value goes from the form straight to
// the store through the agent tools service; the agent learns only whether
// it was stored, declined or timed out.
//
// The page listens on loopback only and each link carries a one-time token
// of 256 bits that is burned on the first submission or decline. Requests
// are refused unless their Host is the loopback address the page listens on
// (so a DNS-rebound name cannot reach it) and, for submissions, unless the
// browser reports a same-origin request. The page has no scripts, no
// external assets and a Content-Security-Policy that allows only its own
// inline stylesheet by hash.
package entrypage

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/secret"
)

// Backend is the part of the agent tools service the page needs.
type Backend interface {
	Entry(tok string) (agenttools.EntryView, bool)
	SubmitAsk(ctx context.Context, tok string, v secret.Value) error
	DeclineAsk(ctx context.Context, tok string) error
}

//go:embed page.css
var css string

//go:embed page.html.tmpl
var pageHTML string

var page = template.Must(template.New("page").Parse(pageHTML))

// cspHeader allows nothing but the page's own stylesheet, matched by hash,
// and form posts back to the page.
var cspHeader = func() string {
	sum := sha256.Sum256([]byte(css))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; img-src 'none'"
}()

// maxForm bounds a submitted form: a value of MaxValueSize, percent-encoded,
// plus the other fields.
const maxForm = 3*agenttools.MaxValueSize + 1024

// Page serves entry links.
type Page struct {
	b      Backend
	addr   string // host:port the page is served on
	logger *slog.Logger
}

// New returns a page for b served on addr, the loopback host:port of its
// listener.
func New(b Backend, addr string, logger *slog.Logger) *Page {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Page{b: b, addr: addr, logger: logger}
}

// Listen opens a listener for the page. The address must be a loopback IP
// address; port 0 picks a free port.
func Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("entrypage: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("entrypage: %s is not a loopback IP address; the entry page serves only this machine", host)
	}
	return net.Listen("tcp", addr)
}

// Links builds entry URLs for a page served on Addr.
type Links struct{ Addr string }

// Base is the page's origin, http://<addr>.
func (l Links) Base() string { return "http://" + l.Addr }

// EntryURL implements agenttools.EntryLinks.
func (l Links) EntryURL(tok string) (string, error) {
	if tok == "" || strings.ContainsAny(tok, "/?#%") {
		return "", errors.New("entrypage: malformed token")
	}
	return l.Base() + "/entry/" + tok, nil
}

// Serve serves the page on ln until ctx ends.
func (p *Page) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		ErrorLog:          slog.NewLogLogger(p.logger.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// Handler returns the page's routes.
func (p *Page) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /entry/{token}", p.show)
	mux.HandleFunc("POST /entry/{token}", p.submit)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		p.render(w, http.StatusNotFound, view{Title: "Not found", Message: "There is nothing here."})
	})
	return p.guard(mux)
}

// guard sets the security headers on every response and refuses requests
// for any Host other than the page's own loopback address.
func (p *Page) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspHeader)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		if r.Host != p.addr {
			p.render(w, http.StatusMisdirectedRequest, view{Title: "Wrong address",
				Message: "Open the entry link exactly as scrim sent it."})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type view struct {
	Title   string
	Message string
	Entry   *agenttools.EntryView
	Expires string
	Error   string
}

func (p *Page) render(w http.ResponseWriter, status int, v view) {
	var buf bytes.Buffer
	err := page.Execute(&buf, struct {
		view
		CSS template.CSS
	}{v, template.CSS(css)}) // #nosec G203 -- the stylesheet is a compiled-in constant
	if err != nil {
		p.logger.Error("rendering the entry page failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

var gone = view{Title: "Link used or expired",
	Message: "This entry link has already been used, was declined, or has expired. Ask the agent to request the value again if it is still needed."}

func (p *Page) show(w http.ResponseWriter, r *http.Request) {
	e, ok := p.b.Entry(r.PathValue("token"))
	if !ok {
		p.render(w, http.StatusGone, gone)
		return
	}
	p.render(w, http.StatusOK, view{Title: "Enter a secret", Entry: &e, Expires: e.ExpiresAt.Format(time.RFC1123)})
}

func (p *Page) submit(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r, p.addr) {
		p.render(w, http.StatusForbidden, view{Title: "Refused", Message: "The form was not submitted from this page."})
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		p.render(w, http.StatusUnsupportedMediaType, view{Title: "Refused", Message: "The form was not submitted from this page."})
		return
	}
	tok := r.PathValue("token")
	e, ok := p.b.Entry(tok)
	if !ok {
		p.render(w, http.StatusGone, gone)
		return
	}
	body, err := readBody(http.MaxBytesReader(w, r.Body, maxForm))
	if err != nil {
		p.render(w, http.StatusRequestEntityTooLarge, view{Title: "Too large",
			Message: fmt.Sprintf("The value is larger than %d bytes and was not stored.", agenttools.MaxValueSize)})
		return
	}
	form := parseForm(body)
	secret.WipeBytes(body)
	value := form["value"]
	delete(form, "value")
	switch string(form["action"]) {
	case "decline":
		secret.WipeBytes(value)
		if err := p.b.DeclineAsk(r.Context(), tok); err != nil {
			p.render(w, http.StatusGone, gone)
			return
		}
		p.render(w, http.StatusOK, view{Title: "Declined", Message: "Nothing was stored. The agent has been told you declined. You can close this tab."})
	case "store":
		if len(value) == 0 {
			p.render(w, http.StatusUnprocessableEntity, view{Title: "Enter a secret", Entry: &e,
				Expires: e.ExpiresAt.Format(time.RFC1123), Error: "Enter a value, or decline."})
			return
		}
		err := p.b.SubmitAsk(r.Context(), tok, secret.Adopt(value))
		if agenttools.CodeOf(err) == agenttools.CodeNotFound {
			p.render(w, http.StatusGone, gone)
			return
		}
		if err != nil {
			p.render(w, http.StatusServiceUnavailable, view{Title: "Not stored",
				Message: "scrim could not store the value (" + agenttools.Public(err).Message + "). The agent has been told it was not stored."})
			return
		}
		p.render(w, http.StatusOK, view{Title: "Stored", Message: "The value is stored in " + e.Store + ". The agent receives only the reference " +
			e.Ref + ", never the value. You can close this tab."})
	default:
		secret.WipeBytes(value)
		p.render(w, http.StatusBadRequest, view{Title: "Refused", Message: "The form was not submitted from this page."})
	}
}

// sameOrigin accepts a submission only when the browser says it came from
// the page itself. Browsers send Origin on every POST; Sec-Fetch-Site is
// checked when present.
func sameOrigin(r *http.Request, addr string) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	return err == nil && u.Scheme == "http" && u.Host == addr
}

// readBody reads the whole body into a buffer that is wiped as it grows.
func readBody(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	for {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), 2*cap(buf))
			copy(grown, buf)
			secret.WipeBytes(buf)
			buf = grown
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			return buf, nil
		}
		if err != nil {
			secret.WipeBytes(buf)
			return nil, err
		}
	}
}

// parseForm decodes application/x-www-form-urlencoded into byte slices, so
// the value never becomes an immutable Go string. Malformed escapes are kept
// literally.
func parseForm(body []byte) map[string][]byte {
	out := map[string][]byte{}
	for pair := range bytes.SplitSeq(body, []byte("&")) {
		k, v, _ := bytes.Cut(pair, []byte("="))
		key := string(unescape(k))
		if _, dup := out[key]; dup || key == "" {
			continue
		}
		out[key] = unescape(v)
	}
	return out
}

func unescape(s []byte) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out = append(out, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		default:
			out = append(out, c)
		}
	}
	return out
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}
