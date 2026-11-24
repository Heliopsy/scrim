// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

// Forwarder serves an agent pod's local endpoints and carries each
// connection to the central scrim. It holds no secret value: the token it
// presents is the pod's own, read from its file per connection.
type Forwarder struct {
	// Central is host:port of the edge listener.
	Central string
	// TLS verifies the central scrim: RootCAs is the edge CA, ServerName
	// the name in its certificate.
	TLS *tls.Config
	// Token returns the pod's service account token. The forwarder wipes
	// what it returns. Nil sends none: the pod is identified by the client
	// certificate TLS presents (ClientCertificateFiles).
	Token func() ([]byte, error)
	// DialTimeout bounds connecting and upgrading; zero takes 10 seconds.
	DialTimeout time.Duration
	Log         *slog.Logger

	once  sync.Once
	proxy *httputil.ReverseProxy
}

// NewTLSConfig returns the client TLS configuration that trusts only the
// CA certificates in caPEM (the edge CA), for serverName. It announces
// [EdgeCAProto] so a listener in its upgrade window serves it the edge
// CA's certificate.
func NewTLSConfig(caPEM []byte, serverName string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("edge: the CA file holds no PEM certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName,
		NextProtos: []string{EdgeCAProto, "http/1.1"}}, nil
}

// ClientCertificateFiles returns a TLS client certificate source that
// reads the certificate and key files on every handshake, so a certificate
// rotated in the pod (a SPIFFE helper writing short-lived SVIDs) is used at
// once.
func ClientCertificateFiles(certFile, keyFile string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("edge: reading the client certificate: %w", err)
		}
		return &c, nil
	}
}

// token returns the pod's token, nil when the forwarder sends none.
func (f *Forwarder) token() ([]byte, error) {
	if f.Token == nil {
		return nil, nil
	}
	return f.Token()
}

// TokenFile returns a token source that reads path on every call.
func TokenFile(path string) func() ([]byte, error) {
	return func() ([]byte, error) {
		raw, err := os.ReadFile(path) // #nosec G304 -- the configured token file
		if err != nil {
			return nil, fmt.Errorf("edge: reading the service account token: %w", err)
		}
		tok := bytes.TrimSpace(raw)
		if len(tok) == 0 {
			secret.WipeBytes(raw)
			return nil, errors.New("edge: the service account token file is empty")
		}
		out := bytes.Clone(tok)
		secret.WipeBytes(raw)
		return out, nil
	}
}

func (f *Forwarder) log() *slog.Logger {
	if f.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return f.Log
}

func (f *Forwarder) timeout() time.Duration {
	if f.DialTimeout > 0 {
		return f.DialTimeout
	}
	return 10 * time.Second
}

func (f *Forwarder) dialTLS(ctx context.Context) (net.Conn, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: f.timeout(), KeepAlive: 30 * time.Second}, Config: f.TLS}
	c, err := d.DialContext(ctx, "tcp", f.Central)
	if err != nil {
		return nil, fmt.Errorf("edge: cannot reach the central scrim at %s: %w", f.Central, err)
	}
	return c, nil
}

// RefusedError is the central scrim's answer to a tunnel it did not open.
type RefusedError struct {
	Status int
	Err    agenttools.Error
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("edge: the central scrim refused the connection (%d %s: %s)", e.Status, e.Err.Code, e.Err.Message)
}

// Dial opens a tunnel to path on the edge listener: TLS, then an HTTP
// Upgrade carrying the token. The returned connection carries the tool's
// protocol.
func (f *Forwarder) Dial(ctx context.Context, path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	c, err := f.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := f.token()
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	req := make([]byte, 0, 256+len(tok))
	req = append(req, "GET "+path+" HTTP/1.1\r\nHost: "+f.host()+"\r\nConnection: Upgrade\r\nUpgrade: "+Protocol...)
	if tok != nil {
		req = append(req, "\r\nAuthorization: Bearer "...)
		req = append(req, tok...)
	}
	req = append(req, "\r\n\r\n"...)
	secret.WipeBytes(tok)
	_, err = c.Write(req)
	secret.WipeBytes(req)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("edge: writing to the central scrim: %w", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("edge: reading the central scrim's answer: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), Protocol) {
		re := &RefusedError{Status: resp.StatusCode}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var eb localapi.ErrorBody
		if json.Unmarshal(raw, &eb) == nil && eb.Error.Code != "" {
			re.Err = eb.Error
		} else {
			re.Err = agenttools.Error{Code: agenttools.CodeInternal, Message: "unexpected answer"}
		}
		_ = resp.Body.Close()
		_ = c.Close()
		return nil, re
	}
	_ = c.SetDeadline(time.Time{})
	return &Conn{Conn: c, r: br}, nil
}

func (f *Forwarder) host() string {
	if f.TLS != nil && f.TLS.ServerName != "" {
		return f.TLS.ServerName
	}
	return f.Central
}

// ServeTunnel accepts local connections on ln until ctx ends and carries
// each through a tunnel to path. A connection whose tunnel cannot be opened
// is closed: nothing in the pod can answer for the central scrim.
func (f *Forwarder) ServeTunnel(ctx context.Context, ln net.Listener, path string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		wg.Go(func() { f.carry(ctx, c, path) })
	}
}

func (f *Forwarder) carry(ctx context.Context, local net.Conn, path string) {
	defer func() { _ = local.Close() }()
	up, err := f.Dial(ctx, path)
	if err != nil {
		f.log().Warn("local connection refused: the central scrim is unavailable", "endpoint", path, "error", err)
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(ctx, func() {
		_ = local.Close()
		_ = up.Close()
	})
	defer stop()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, local); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, up); closeWrite(local); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	type cw interface{ CloseWrite() error }
	if ec, ok := c.(*Conn); ok {
		c = ec.Conn
	}
	if w, ok := c.(cw); ok {
		_ = w.CloseWrite()
		return
	}
	_ = c.Close()
}

// APIHandler forwards agent API requests to the central scrim, each with
// the pod's token in place of any Authorization the local client sent.
// When the central scrim cannot be reached the client gets an
// `unavailable` error; nothing is answered locally.
func (f *Forwarder) APIHandler() http.Handler {
	f.once.Do(func() {
		tr := &http.Transport{
			DialTLSContext:      func(ctx context.Context, _, _ string) (net.Conn, error) { return f.dialTLS(ctx) },
			ForceAttemptHTTP2:   false,
			TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
			DisableCompression:  true,
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: f.timeout(),
		}
		target := &url.URL{Scheme: "https", Host: f.host()}
		f.proxy = &httputil.ReverseProxy{
			Transport: tr,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = f.host()
				// The handler replaced Authorization with the pod's token.
				pr.Out.Header.Del("Cookie")
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				f.log().Warn("agent API request failed: the central scrim is unavailable", "error", err)
				writeError(w, http.StatusServiceUnavailable,
					agenttools.Errorf(agenttools.CodeUnavailable, "cannot reach the central scrim; the request was not run"))
			},
			ErrorLog: slog.NewLogLogger(f.log().Handler(), slog.LevelWarn),
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !apiRoute(r.URL.Path) {
			writeError(w, http.StatusNotFound, agenttools.Errorf(agenttools.CodeNotFound, "this route is not served to agent pods"))
			return
		}
		tok, err := f.token()
		if err != nil {
			f.log().Warn("agent API request refused", "error", err)
			writeError(w, http.StatusServiceUnavailable,
				agenttools.Errorf(agenttools.CodeUnavailable, "the pod's service account token cannot be read"))
			return
		}
		r2 := r.Clone(r.Context())
		// Whatever the local client sent is dropped: the pod's token (or
		// its client certificate, in the handshake) is the only credential
		// that leaves.
		r2.Header.Del("Authorization")
		if tok != nil {
			r2.Header.Set("Authorization", "Bearer "+string(tok))
			secret.WipeBytes(tok)
		}
		f.proxy.ServeHTTP(w, r2)
	})
}

// ServeAPI serves APIHandler on ln until ctx ends.
func (f *Forwarder) ServeAPI(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           f.APIHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: an exec call or an approval may take as long as
		// the central scrim allows, and the central scrim bounds both. The
		// socket is reachable from inside this pod only.
		IdleTimeout: 2 * time.Minute,
		ErrorLog:    slog.NewLogLogger(f.log().Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shut, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = srv.Shutdown(shut)
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// Check asks the central scrim who this pod is (GET /v1/whoami) and
// returns the identity it verified. An error means the forwarder cannot
// serve anything: unreachable, a certificate that does not verify, or a
// token the central scrim refused.
func (f *Forwarder) Check(ctx context.Context) (identity.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://edge/v1/whoami", nil)
	if err != nil {
		return identity.Identity{}, err
	}
	rec := &recorder{header: http.Header{}}
	f.APIHandler().ServeHTTP(rec, req)
	if rec.status != http.StatusOK {
		var eb localapi.ErrorBody
		if json.Unmarshal(rec.body.Bytes(), &eb) == nil && eb.Error.Code != "" {
			return identity.Identity{}, &RefusedError{Status: rec.status, Err: eb.Error}
		}
		return identity.Identity{}, fmt.Errorf("edge: the central scrim answered %d", rec.status)
	}
	var id identity.Identity
	if err := json.Unmarshal(rec.body.Bytes(), &id); err != nil {
		return identity.Identity{}, fmt.Errorf("edge: unexpected whoami answer: %w", err)
	}
	if id.Agent == "" || id.Source != identity.SourceKubernetes && id.Source != identity.SourceCertificate {
		return identity.Identity{}, errors.New("edge: the central scrim does not know this pod as an agent")
	}
	return id, nil
}

// recorder is a minimal in-memory ResponseWriter for Check.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(s int) {
	if r.status == 0 {
		r.status = s
	}
}
