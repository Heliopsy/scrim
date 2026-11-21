// SPDX-License-Identifier: AGPL-3.0-only

// Package localapi is the control plane's local API: versioned JSON over
// HTTP/1.1 on a Unix socket. The MCP server (`scrim mcp`), the agent-facing
// CLI and `scrim run` are its clients.
//
// Every request is attributed from the transport alone: the socket's peer
// credentials, plus a session token in the Authorization header when the
// caller has one. Nothing in a request body or header other than that token
// can change who the caller is.
//
// One route takes a value: PUT /v1/secrets/value, whose body is the raw
// bytes of a value read from standard input or extracted by secret_capture.
// No route returns a value. The session token minted by POST /v1/sessions is
// the only credential the API ever returns, once, to the process that will
// start the agent.
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// Version is the API version, the first path segment of every route.
const Version = "v1"

// HeaderAPIVersion carries Version on every response.
const HeaderAPIVersion = "Scrim-Api-Version"

// ToolAuth is the audit tool name of a refused credential.
const ToolAuth = "auth"

// Server serves the local API.
type Server struct {
	Resolver identity.Resolver
	Sessions *identity.Manager
	Tools    *agenttools.Service
	// Auditor records refused credentials and swept sessions.
	Auditor agenttools.Auditor
	Logger  *slog.Logger
	// ServerVersion is the scrim version reported by /v1/version.
	ServerVersion string
	// SweepEvery is how often sessions whose `scrim run` died are revoked.
	// Zero takes 15 seconds; negative disables the sweep.
	SweepEvery time.Duration
	Now        func() time.Time
	// Endpoints, when set, serves GET /v1/endpoints: where a daemon this
	// caller did not start offers its listeners, for `scrim run` under
	// another user than the daemon's (a system service).
	Endpoints func() Endpoints
	// Redactor, when set, serves POST /v1/redact: the data plane's redactor
	// and guard over text an agent hook hands in (a tool result, a prompt).
	// It owns text and wipes it.
	Redactor func(ctx context.Context, text []byte) (Redacted, error)
}

// Redacted is what the redactor returns: text with every known value
// replaced by its placeholder, and the store references found (for the
// audit log only).
type Redacted struct {
	Text         []byte
	Replacements int
	Refs         []string
}

// RedactOutput is the answer of POST /v1/redact. It holds no secret value:
// the text passed the guard.
type RedactOutput struct {
	Text         string `json:"text"`
	Replacements int    `json:"replacements"`
}

// MaxRedactSize bounds the text POST /v1/redact accepts, below the data
// plane's gRPC message limit. Larger text is refused, never passed through.
const MaxRedactSize = 3 << 20

// ToolRedact is the audit tool name of a redaction that replaced values or
// failed.
const ToolRedact = "redact"

type ctxKey int

const (
	peerKey ctxKey = iota
	peerErrKey
)

func (s *Server) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

func (s *Server) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// ConnContext records the connection's peer credentials. It is the
// http.Server hook that attributes every request on the connection.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	p, err := identity.PeerOf(c)
	if err != nil {
		return context.WithValue(ctx, peerErrKey, err)
	}
	return context.WithValue(ctx, peerKey, p)
}

// PeerFrom returns the peer credentials ConnContext recorded.
func PeerFrom(ctx context.Context) (identity.Peer, bool) {
	p, ok := ctx.Value(peerKey).(identity.Peer)
	return p, ok
}

// Serve serves the API on ln until ctx ends, and sweeps dead sessions.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ConnContext:       ConnContext,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		// Asks wait up to MaxAskWait for a human.
		WriteTimeout: agenttools.MaxAskWait + time.Minute,
		IdleTimeout:  2 * time.Minute,
		ErrorLog:     slog.NewLogLogger(s.logger().Handler(), slog.LevelWarn),
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if s.Sessions != nil && s.SweepEvery >= 0 {
		go s.sweep(ctx)
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

func (s *Server) sweep(ctx context.Context) {
	every := s.SweepEvery
	if every == 0 {
		every = 15 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SweepOnce(ctx)
		}
	}
}

// SweepOnce revokes sessions whose root process exited, and audits each.
func (s *Server) SweepOnce(ctx context.Context) {
	gone, err := s.Sessions.Sweep(ctx)
	if err != nil {
		s.logger().Warn("sweeping sessions failed", "error", err)
	}
	for _, sess := range gone {
		s.audit(ctx, agenttools.AuditEntry{Agent: sess.Agent, Principal: sess.Agent + "/" + sess.ID,
			Source: string(identity.SourceSession), SessionID: sess.ID, UID: sess.UID, Tool: "session_revoke",
			Outcome: agenttools.OutcomeOK, Detail: identity.RevokeRootExited})
	}
}

func (s *Server) audit(ctx context.Context, e agenttools.AuditEntry) {
	if s.Auditor == nil {
		return
	}
	e.Time = s.now().UTC()
	if err := s.Auditor.Record(ctx, e); err != nil {
		s.logger().Error("audit write failed", "tool", e.Tool, "error", err)
	}
}

// Handler returns the API's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	open := func(pattern string, h func(http.ResponseWriter, *http.Request)) { mux.HandleFunc(pattern, h) }
	authed := func(pattern string, h func(http.ResponseWriter, *http.Request, identity.Identity)) {
		mux.HandleFunc(pattern, s.authenticate(h))
	}
	v := "/" + Version
	open("GET "+v+"/version", s.version)
	open("GET "+v+"/endpoints", s.endpoints)
	mux.HandleFunc("GET "+v+"/whoami", s.whoami)
	authed("POST "+v+"/sessions", s.mint)
	authed("DELETE "+v+"/sessions/self", s.revokeSelf)
	authed("DELETE "+v+"/sessions/{id}", s.revoke)
	authed("GET "+v+"/secrets", s.list)
	authed("POST "+v+"/secrets/request", s.request)
	authed("POST "+v+"/secrets/generate", s.generate)
	authed("POST "+v+"/secrets/check", s.check)
	authed("PUT "+v+"/secrets/value", s.put)
	authed("POST "+v+"/asks", s.ask)
	authed("GET "+v+"/status/{id}", s.status)
	authed("GET "+v+"/grants", s.grants)
	authed("POST "+v+"/redact", s.redact)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, agenttools.Errorf(agenttools.CodeNotFound, "no such route in API %s", Version))
	})
	return withVersion(mux)
}

func withVersion(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderAPIVersion, Version)
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// resolve establishes the caller's identity from the transport.
func (s *Server) resolve(r *http.Request) (identity.Identity, error) {
	peer, ok := PeerFrom(r.Context())
	if !ok {
		return identity.Unknown(identity.Peer{}), nil
	}
	tok, err := bearer(r)
	if err != nil {
		return identity.Identity{}, err
	}
	id, err := s.Resolver.Resolve(r.Context(), peer, tok)
	secret.WipeBytes(tok)
	if re, refused := identity.IsRefused(err); refused {
		s.audit(r.Context(), agenttools.AuditEntry{Source: string(identity.SourceSession), SessionID: re.SessionID,
			UID: peer.UID, PID: peer.PID, Tool: ToolAuth, Outcome: agenttools.OutcomeRefused, Detail: string(re.Reason)})
		return identity.Identity{}, agenttools.Errorf(agenttools.CodeUnauthenticated, "the session token was refused")
	}
	if err != nil {
		s.logger().Error("resolving the caller failed", "error", err)
		return identity.Identity{}, agenttools.Errorf(agenttools.CodeUnavailable, "the caller's identity could not be checked")
	}
	return id, nil
}

// bearer returns the session token from the Authorization header, nil when
// there is none.
func bearer(r *http.Request) ([]byte, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, nil
	}
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return nil, agenttools.Errorf(agenttools.CodeUnauthenticated, "the Authorization header must be a Bearer session token")
	}
	return []byte(strings.TrimSpace(h[len(p):])), nil
}

func (s *Server) authenticate(h func(http.ResponseWriter, *http.Request, identity.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.resolve(r)
		if err != nil {
			writeError(w, err)
			return
		}
		if !id.Known() {
			s.audit(r.Context(), agenttools.AuditEntry{Source: string(identity.SourceUnknown), UID: id.Peer.UID,
				PID: id.Peer.PID, Tool: ToolAuth, Outcome: agenttools.OutcomeRefused, Detail: "unknown caller"})
			writeError(w, agenttools.Errorf(agenttools.CodeUnauthenticated, "this local user is not mapped to an agent"))
			return
		}
		h(w, r, id)
	}
}

// VersionInfo is the answer of GET /v1/version.
type VersionInfo struct {
	API    string `json:"api"`
	Server string `json:"server,omitempty"`
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, VersionInfo{API: Version, Server: s.ServerVersion})
}

// Endpoints is the answer of GET /v1/endpoints. None of it is secret: the
// listener addresses, the loopback upstreams to bypass and the public CA
// certificates clients must trust.
type Endpoints struct {
	Ready    bool              `json:"ready"`
	Problems map[string]string `json:"problems,omitempty"`
	// BaseURL is the LLM proxy's base URL, for example http://127.0.0.1:9790.
	BaseURL string `json:"base_url,omitempty"`
	// ForwardProxy is the forward proxy listener (host:port), or empty.
	ForwardProxy string   `json:"forward_proxy,omitempty"`
	Bypass       []string `json:"bypass,omitempty"`
	CAPEM        string   `json:"ca_pem,omitempty"`
}

func (s *Server) endpoints(w http.ResponseWriter, _ *http.Request) {
	if s.Endpoints == nil {
		writeError(w, agenttools.Errorf(agenttools.CodeNotFound, "this API serves no daemon endpoints"))
		return
	}
	writeJSON(w, http.StatusOK, s.Endpoints())
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	id, err := s.resolve(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, id)
}

// MintInput is the body of POST /v1/sessions.
type MintInput struct {
	Name       string           `json:"name,omitempty"`
	TTLSeconds int              `json:"ttl_seconds,omitempty"`
	Scopes     []identity.Scope `json:"scopes,omitempty"`
}

// SessionInfo describes a session without its token.
type SessionInfo struct {
	ID        string           `json:"id"`
	Agent     string           `json:"agent"`
	Name      string           `json:"name,omitempty"`
	Scopes    []identity.Scope `json:"scopes"`
	CreatedAt time.Time        `json:"created_at"`
	ExpiresAt time.Time        `json:"expires_at"`
	RootPID   int32            `json:"root_pid"`
}

func sessionInfo(s identity.Session) SessionInfo {
	return SessionInfo{ID: s.ID, Agent: s.Agent, Name: s.Name, Scopes: s.Scopes, CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt, RootPID: s.Root.PID}
}

func (s *Server) mint(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	if s.Sessions == nil {
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "sessions are not enabled"))
		return
	}
	var in MintInput
	if !decode(w, r, &in) {
		return
	}
	if in.TTLSeconds < 0 {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "ttl_seconds must not be negative"))
		return
	}
	m, err := s.Sessions.Mint(r.Context(), id, identity.MintRequest{Name: in.Name,
		TTL: time.Duration(in.TTLSeconds) * time.Second, Scopes: in.Scopes})
	entry := agenttools.AuditEntry{Agent: id.Agent, Principal: id.Principal(), Source: string(id.Source),
		UID: id.Peer.UID, PID: id.Peer.PID, Tool: "session_mint", Outcome: agenttools.OutcomeOK}
	if err != nil {
		entry.Outcome = agenttools.OutcomeDenied
		s.audit(r.Context(), entry)
		if errors.Is(err, identity.ErrMintRefused) {
			writeError(w, agenttools.Errorf(agenttools.CodeForbidden, "%s", strings.TrimPrefix(err.Error(), "identity: ")))
			return
		}
		s.logger().Error("minting a session failed", "error", err)
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "the session could not be stored"))
		return
	}
	defer m.Token.Wipe()
	entry.SessionID = m.Session.ID
	s.audit(r.Context(), entry)
	info, err := json.Marshal(sessionInfo(m.Session))
	if err != nil {
		writeError(w, agenttools.Errorf(agenttools.CodeInternal, "encoding the session failed"))
		return
	}
	// The token is written by hand: secret.Value refuses to marshal its bytes.
	// Its alphabet needs no JSON escaping.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = m.Token.Expose(func(tok []byte) error {
		buf := make([]byte, 0, len(tok)+len(info)+32)
		buf = append(buf, `{"token":"`...)
		buf = append(buf, tok...)
		buf = append(buf, `","session":`...)
		buf = append(buf, info...)
		buf = append(buf, "}\n"...)
		_, err := w.Write(buf)
		secret.WipeBytes(buf)
		return err
	})
}

func (s *Server) revokeSelf(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	if id.Source != identity.SourceSession {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the caller has no session to end"))
		return
	}
	s.revokeID(w, r, id, id.SessionID, identity.RevokeEnded)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	sid := r.PathValue("id")
	if s.Sessions == nil {
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "sessions are not enabled"))
		return
	}
	// A session can end itself; ending another needs a mapped local user of
	// the same uid with the mint scope. Anything else is not found, so session
	// IDs cannot be probed.
	sess, err := s.Sessions.Get(r.Context(), sid)
	allowed := err == nil && (id.SessionID == sid ||
		id.Source == identity.SourcePeer && id.Has(identity.ScopeSessionsMint) && id.Peer.UID == sess.UID)
	if !allowed {
		writeError(w, agenttools.Errorf(agenttools.CodeNotFound, "no session %s", sid))
		return
	}
	s.revokeID(w, r, id, sid, identity.RevokeOperator)
}

func (s *Server) revokeID(w http.ResponseWriter, r *http.Request, id identity.Identity, sid, reason string) {
	if err := s.Sessions.Revoke(r.Context(), sid, reason); err != nil {
		s.logger().Error("revoking a session failed", "session", sid, "error", err)
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "the session could not be revoked"))
		return
	}
	s.audit(r.Context(), agenttools.AuditEntry{Agent: id.Agent, Principal: id.Principal(), Source: string(id.Source),
		SessionID: sid, UID: id.Peer.UID, PID: id.Peer.PID, Tool: "session_revoke", Outcome: agenttools.OutcomeOK, Detail: reason})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": sid})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	q := r.URL.Query()
	out, err := s.Tools.List(r.Context(), id, agenttools.ListInput{Store: q.Get("store"), Prefix: q.Get("prefix"), Binding: q.Get("binding")})
	reply(w, out, err)
}

func (s *Server) request(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	var in agenttools.RequestInput
	if decode(w, r, &in) {
		out, err := s.Tools.Request(r.Context(), id, in)
		reply(w, out, err)
	}
}

func (s *Server) generate(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	var in agenttools.GenInput
	if decode(w, r, &in) {
		out, err := s.Tools.Generate(r.Context(), id, in)
		reply(w, out, err)
	}
}

func (s *Server) check(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	var in agenttools.CheckInput
	if decode(w, r, &in) {
		out, err := s.Tools.Check(r.Context(), id, in)
		reply(w, out, err)
	}
}

// put stores the raw request body as a value. The reference and options
// travel in the query so the body is the value and nothing else.
func (s *Server) put(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	q := r.URL.Query()
	in := agenttools.PutInput{Ref: q.Get("ref"), Store: q.Get("store"), Origin: q.Get("origin")}
	if o := q.Get("overwrite"); o != "" {
		b, err := strconv.ParseBool(o)
		if err != nil {
			writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "overwrite must be true or false"))
			return
		}
		in.Overwrite = b
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/octet-stream" {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the value must be sent as application/octet-stream"))
		return
	}
	body := http.MaxBytesReader(w, r.Body, agenttools.MaxValueSize+1)
	v, err := agenttools.ReadValue(body, true)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := s.Tools.Put(r.Context(), id, in, v)
	reply(w, out, err)
}

func (s *Server) ask(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	var in agenttools.AskInput
	if decode(w, r, &in) {
		out, err := s.Tools.Ask(r.Context(), id, in)
		reply(w, out, err)
	}
}

func (s *Server) status(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	out, err := s.Tools.Status(r.Context(), id, agenttools.StatusInput{ID: r.PathValue("id")})
	reply(w, out, err)
}

func (s *Server) grants(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	out, err := s.Tools.Grants(r.Context(), id)
	reply(w, out, err)
}

// redact runs the request body, raw bytes, through the data plane's redactor
// and guard. Only the redacted text goes back. A call that replaced values or
// failed is audited with the references involved, never the text.
func (s *Server) redact(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	if s.Redactor == nil {
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "redaction is not available from this scrim process"))
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/octet-stream" {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the text must be sent as application/octet-stream"))
		return
	}
	text, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRedactSize+1))
	if err != nil || len(text) > MaxRedactSize {
		secret.WipeBytes(text)
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the text is larger than %d bytes; it is not redacted", MaxRedactSize))
		return
	}
	entry := agenttools.AuditEntry{Agent: id.Agent, Principal: id.Principal(), Source: string(id.Source), SessionID: id.SessionID,
		UID: id.Peer.UID, PID: id.Peer.PID, Tool: ToolRedact}
	out, err := s.Redactor(r.Context(), text)
	if err != nil {
		s.logger().Warn("redaction for an agent hook failed", "agent", id.Agent, "error", err)
		entry.Outcome, entry.Detail = agenttools.OutcomeError, "redaction failed; the text was withheld"
		s.audit(r.Context(), entry)
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "scrim could not redact the text; it is withheld"))
		return
	}
	if out.Replacements > 0 {
		entry.Outcome = agenttools.OutcomeOK
		entry.Ref = strings.Join(out.Refs, ",")
		entry.Detail = strconv.Itoa(out.Replacements) + " values replaced"
		s.audit(r.Context(), entry)
	}
	writeJSON(w, http.StatusOK, RedactOutput{Text: string(out.Text), Replacements: out.Replacements})
}

// maxBody bounds a JSON request body.
const maxBody = 64 << 10

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the request body is not valid JSON for this route"))
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the request body has trailing data"))
		return false
	}
	return true
}

func reply(w http.ResponseWriter, out any, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ErrorBody is the envelope of every error response.
type ErrorBody struct {
	Error agenttools.Error `json:"error"`
}

var statusOf = map[agenttools.Code]int{
	agenttools.CodeInvalid:         http.StatusBadRequest,
	agenttools.CodeUnauthenticated: http.StatusUnauthorized,
	agenttools.CodeForbidden:       http.StatusForbidden,
	agenttools.CodeDenied:          http.StatusForbidden,
	agenttools.CodeNeedsApproval:   http.StatusForbidden,
	agenttools.CodeNotFound:        http.StatusNotFound,
	agenttools.CodeConflict:        http.StatusConflict,
	agenttools.CodeUnavailable:     http.StatusServiceUnavailable,
	agenttools.CodeInternal:        http.StatusInternalServerError,
}

func writeError(w http.ResponseWriter, err error) {
	e := agenttools.Public(err)
	st, ok := statusOf[e.Code]
	if !ok {
		st = http.StatusInternalServerError
	}
	writeJSON(w, st, ErrorBody{Error: *e})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		status, raw = http.StatusInternalServerError, []byte(`{"error":{"code":"internal","message":"encoding the response failed"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}

// errUnexpected is returned by the client for a response it cannot read.
var errUnexpected = fmt.Errorf("localapi: unexpected response")
