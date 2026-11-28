// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/sshagent"
)

// Identifier verifies a Kubernetes service account token and returns the
// agent it belongs to (identity.KubeResolver.Resolve). A token the cluster
// does not accept is an [identity.RefusedError].
type Identifier func(ctx context.Context, tok []byte) (identity.Identity, error)

// ToolEdge is the audit tool name of a refused edge connection.
const ToolEdge = "edge"

// Server is the central scrim's edge listener.
type Server struct {
	// Identify verifies the token every request and tunnel carries.
	Identify Identifier
	// Certificates verifies the client certificate a forwarder presents
	// instead of a token; nil ignores client certificates. The listener
	// must request them (tls.RequestClientCert): the chain is verified
	// here, against the trust anchors and CRLs in force.
	Certificates *identity.CertResolver
	// API serves the agent API routes (localapi.Server.Handler). Requests
	// reach it with the verified caller in their context
	// (localapi.WithCaller); only the routes in [APIRoutes] are passed on.
	API http.Handler
	// SSH is scrim's ssh-agent keyring; nil refuses ssh-agent tunnels.
	SSH localapi.SSHAgent
	// Database returns the function that serves a connection to the named
	// database's auth proxy, and false for a name that is not configured.
	Database func(name string) (func(ctx context.Context, c net.Conn), bool)
	// Auditor records refused tokens.
	Auditor agenttools.Auditor
	Log     *slog.Logger
	Now     func() time.Time

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// APIRoutes are the agent API path prefixes the edge listener passes on:
// the agent tools, ssh-agent, exec broker, database tool and redaction.
// Session routes are not among them (a pod has no `scrim run` session),
// nor is the daemon's endpoint list.
var APIRoutes = []string{
	"/v1/version", "/v1/whoami", "/v1/secrets", "/v1/asks", "/v1/status/", "/v1/grants", "/v1/redact",
	"/v1/ssh/", "/v1/exec", "/v1/databases",
}

func apiRoute(p string) bool {
	for _, r := range APIRoutes {
		if p == r || strings.HasSuffix(r, "/") && strings.HasPrefix(p, r) || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func (s *Server) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func (s *Server) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// Handler returns the edge listener's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathSSHAgent, s.sshAgent)
	mux.HandleFunc("GET "+PathDatabase+"/{name}", s.database)
	mux.HandleFunc("/v1/", s.api)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, agenttools.Errorf(agenttools.CodeNotFound, "no such route on the edge listener"))
	})
	return mux
}

// TLSConfig is the edge listener's TLS configuration around a certificate
// source: TLS 1.3, HTTP/1.1 only (tunnels are HTTP Upgrades).
func TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, GetCertificate: getCert}
}

// Serve serves TLS on ln until ctx ends, then closes every tunnel.
func (s *Server) Serve(ctx context.Context, ln net.Listener, cfg *tls.Config) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 10 * time.Second,
		// Asks and approvals on API routes wait up to MaxAskWait; tunnels
		// clear their deadlines once upgraded.
		ReadTimeout:  time.Minute,
		WriteTimeout: agenttools.MaxAskWait + time.Minute,
		IdleTimeout:  2 * time.Minute,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     slog.NewLogLogger(s.log().Handler(), slog.LevelWarn),
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(tls.NewListener(ln, cfg)) }()
	select {
	case err := <-errc:
		s.closeAll()
		return err
	case <-ctx.Done():
		s.closeAll()
		shut, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = srv.Shutdown(shut)
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func (s *Server) track(c net.Conn, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	if on {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

// identify verifies the request's client certificate or token. A client
// certificate, when the listener takes them and the forwarder presented
// one, is the caller and the token is ignored. Otherwise only a Kubernetes
// service account token that maps to a known agent is accepted: session
// tokens are bound to a local process tree and mean nothing here, and there
// are no peer credentials to fall back to.
func (s *Server) identify(r *http.Request) (identity.Identity, int, error) {
	tok := bearer(r)
	defer secret.WipeBytes(tok)
	r.Header.Del("Authorization")
	if s.Certificates != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return s.identifyCertificate(r)
	}
	if len(tok) == 0 {
		return identity.Identity{}, http.StatusUnauthorized,
			agenttools.Errorf(agenttools.CodeUnauthenticated, "the edge listener needs the pod's service account token")
	}
	if !identity.LooksLikeKubernetesToken(tok) {
		s.refused(r.Context(), "not a Kubernetes service account token")
		return identity.Identity{}, http.StatusUnauthorized,
			agenttools.Errorf(agenttools.CodeUnauthenticated, "the edge listener accepts Kubernetes service account tokens only")
	}
	if s.Identify == nil {
		return identity.Identity{}, http.StatusServiceUnavailable,
			agenttools.Errorf(agenttools.CodeUnavailable, "Kubernetes identity is not enabled on this scrim")
	}
	id, err := s.Identify(r.Context(), tok)
	if re, refused := identity.IsRefused(err); refused {
		s.refused(r.Context(), string(re.Reason))
		return identity.Identity{}, http.StatusUnauthorized,
			agenttools.Errorf(agenttools.CodeUnauthenticated, "the service account token was refused")
	}
	if err != nil {
		s.log().Error("verifying an edge caller failed", "error", err)
		return identity.Identity{}, http.StatusServiceUnavailable,
			agenttools.Errorf(agenttools.CodeUnavailable, "the caller's identity could not be checked")
	}
	if !id.Known() {
		s.refused(r.Context(), "service account not mapped to an agent")
		return identity.Identity{}, http.StatusUnauthorized,
			agenttools.Errorf(agenttools.CodeUnauthenticated, "this service account is not mapped to an agent")
	}
	return id, 0, nil
}

func (s *Server) identifyCertificate(r *http.Request) (identity.Identity, int, error) {
	id, err := s.Certificates.ResolveCertificates(r.TLS.PeerCertificates)
	if re, refused := identity.IsRefused(err); refused {
		s.refusedAs(r.Context(), identity.SourceCertificate, "client certificate "+string(re.Reason))
		return identity.Identity{}, http.StatusUnauthorized,
			agenttools.Errorf(agenttools.CodeUnauthenticated, "the client certificate was refused")
	}
	if err != nil {
		s.log().Error("verifying an edge caller failed", "error", err)
		return identity.Identity{}, http.StatusServiceUnavailable,
			agenttools.Errorf(agenttools.CodeUnavailable, "the caller's identity could not be checked")
	}
	if !id.Known() {
		s.refusedAs(r.Context(), identity.SourceCertificate, "client certificate not mapped to an agent")
		return identity.Identity{}, http.StatusUnauthorized,
			agenttools.Errorf(agenttools.CodeUnauthenticated, "this client certificate is not mapped to an agent")
	}
	return id, 0, nil
}

func (s *Server) refused(ctx context.Context, reason string) {
	s.refusedAs(ctx, identity.SourceKubernetes, reason)
}

func (s *Server) refusedAs(ctx context.Context, src identity.Source, reason string) {
	s.log().Warn("edge connection refused", "reason", reason)
	if s.Auditor == nil {
		return
	}
	e := agenttools.AuditEntry{Time: s.now().UTC(), Source: string(src), Tool: ToolEdge,
		Outcome: agenttools.OutcomeRefused, Detail: reason}
	if err := s.Auditor.Record(ctx, e); err != nil {
		s.log().Error("audit write failed", "tool", ToolEdge, "error", err)
	}
}

func bearer(r *http.Request) []byte {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return nil
	}
	return []byte(strings.TrimSpace(h[len(p):]))
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if !apiRoute(r.URL.Path) {
		writeError(w, http.StatusNotFound, agenttools.Errorf(agenttools.CodeNotFound, "this route is not served to agent pods"))
		return
	}
	// Read before identify, which removes the header: kept for the
	// request, so a store write can log in as the pod's service account
	// (Kubernetes passthrough).
	tok := bearer(r)
	defer secret.WipeBytes(tok)
	id, status, err := s.identify(r)
	if err != nil {
		writeError(w, status, err)
		return
	}
	if s.API == nil {
		writeError(w, http.StatusServiceUnavailable, agenttools.Errorf(agenttools.CodeUnavailable, "the agent API is not available"))
		return
	}
	ctx := localapi.WithCaller(r.Context(), id)
	if id.Source == identity.SourceKubernetes {
		ctx = identity.WithKubernetesToken(ctx, tok)
	}
	s.API.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) sshAgent(w http.ResponseWriter, r *http.Request) {
	if s.SSH == nil {
		writeError(w, http.StatusNotFound, agenttools.Errorf(agenttools.CodeNotFound, "this scrim has no ssh-agent"))
		return
	}
	s.tunnel(w, r, func(ctx context.Context, c *Conn) {
		srv := &sshagent.Server{Backend: boundSSH{keyring: s.SSH, id: c.id}, Log: s.log().With("tunnel", "ssh-agent")}
		_ = srv.ServeConn(ctx, c)
	})
}

func (s *Server) database(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var serve func(context.Context, net.Conn)
	ok := false
	if s.Database != nil {
		serve, ok = s.Database(name)
	}
	if !ok {
		writeError(w, http.StatusNotFound, agenttools.Errorf(agenttools.CodeNotFound, "no database %q is configured", name))
		return
	}
	s.tunnel(w, r, func(ctx context.Context, c *Conn) { serve(ctx, c) })
}

// tunnel verifies the caller, upgrades the connection and hands it to serve
// with the caller attached.
func (s *Server) tunnel(w http.ResponseWriter, r *http.Request, serve func(context.Context, *Conn)) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), Protocol) || !headerHas(r.Header, "Connection", "upgrade") {
		writeError(w, http.StatusBadRequest, agenttools.Errorf(agenttools.CodeInvalid, "a tunnel is an Upgrade to %s", Protocol))
		return
	}
	id, status, err := s.identify(r)
	if err != nil {
		writeError(w, status, err)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, agenttools.Errorf(agenttools.CodeInternal, "the connection cannot be upgraded"))
		return
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	s.track(c, true)
	defer func() {
		s.track(c, false)
		_ = c.Close()
	}()
	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + Protocol + "\r\n\r\n")); err != nil {
		return
	}
	s.log().Debug("edge tunnel opened", "path", r.URL.Path, "agent", id.Principal())
	serve(r.Context(), &Conn{Conn: c, r: brw.Reader, id: id})
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for f := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), token) {
				return true
			}
		}
	}
	return false
}

// boundSSH serves one tunnel's ssh-agent requests as the tunnel's agent.
type boundSSH struct {
	keyring localapi.SSHAgent
	id      identity.Identity
}

func (b boundSSH) SSHKeys(ctx context.Context, bindings []sshagent.Binding) ([]sshagent.Key, error) {
	return b.keyring.Keys(ctx, b.id, bindings)
}

func (b boundSSH) SSHSign(ctx context.Context, req sshagent.SignRequest) (sshagent.Signature, error) {
	return b.keyring.Sign(ctx, b.id, req)
}

func writeError(w http.ResponseWriter, status int, err error) {
	raw, _ := json.Marshal(localapi.ErrorBody{Error: *agenttools.Public(err)})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(localapi.HeaderAPIVersion, localapi.Version)
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}
