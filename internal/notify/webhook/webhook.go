// SPDX-License-Identifier: AGPL-3.0-only

// Package webhook delivers approval requests to an HTTP approval service
// with submit-then-poll, compatible with nono's approval webhook protocol v1
// (docs/protocols/approval-webhook-v1.md in nolabs-ai/nono), so one approval
// service can serve both.
//
// Submit: POST <url> with {"backend": name, "request": {...}}. The receiver
// answers 200 with a final decision, or 202 {"state": "pending"} after
// holding the request for up to X-Nono-Timeout-Secs. Poll: GET
// <url>/<request_id> with the same hold semantics until a final state or the
// approval's expiry. Final decisions are granted, denied or timeout, in any
// of nono's accepted spellings.
//
// The receiver can also settle the approval later by POSTing to the decision
// link it received in request.scrim.approve_url or deny_url (the "signed
// callback"): the link's token is the authority.
//
// A grant or denial settles the approval through the same single-use token
// path as a phone button. Anything else (an error status, a redirect, an
// unknown decision, a timeout) settles nothing: the approval stays pending
// for other notifiers and is denied when it expires.
//
// With notify.webhook.secret set, every request is signed:
//
//	X-Scrim-Timestamp:     Unix milliseconds
//	X-Scrim-Request-Id:    random nonce, fresh per HTTP request
//	X-Scrim-Content-SHA256: sha256:<hex of the body>
//	X-Scrim-Signature:     hmac-sha256=<base64url of HMAC-SHA256(secret, canonical)>
//
// where canonical is "scrim-webhook-v1\n<METHOD>\n<path>\n<timestamp>\n<request id>\n<digest>".
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/version"
)

// Settings.
var (
	URL = config.Register(config.Spec[string]{
		Key:         "notify.webhook.url",
		Default:     "",
		Description: "Approval service URL for the webhook notifier (nono approval webhook v1 compatible). https, or http to a loopback host. Empty disables it.",
	})
	Secret = config.Register(config.Spec[config.SecretRef]{
		Key:         "notify.webhook.secret",
		Default:     "",
		Description: "Reference to the shared secret (at least 32 bytes) that signs webhook requests with HMAC-SHA256. Empty sends unsigned requests.",
	})
	Hold = config.Register(config.Spec[time.Duration]{
		Key:         "notify.webhook.hold",
		Default:     30 * time.Second,
		Description: "Longest time one submit or poll request is held open by the receiver (sent as X-Nono-Timeout-Secs, capped by the approval's remaining time).",
	})
	PollInterval = config.Register(config.Spec[time.Duration]{
		Key:         "notify.webhook.poll-interval",
		Default:     2 * time.Second,
		Description: "Pause between polls when the receiver answers pending without holding.",
	})
)

// Settler settles an approval with a decision-link token.
type Settler interface {
	SettleToken(ctx context.Context, approvalID, token string) error
}

// SettlerFunc adapts a function to Settler.
type SettlerFunc func(ctx context.Context, approvalID, token string) error

// SettleToken implements Settler.
func (f SettlerFunc) SettleToken(ctx context.Context, id, token string) error {
	return f(ctx, id, token)
}

// Options configure a Notifier.
type Options struct {
	// Name is the notifier name, sent as "backend"; default "webhook".
	Name   string
	URL    string
	Secret secret.Value
	// Hold and PollInterval as in the settings.
	Hold         time.Duration
	PollInterval time.Duration
	Settler      Settler
	// TokenFromLink extracts the token from a decision link.
	TokenFromLink func(link string) (id, token string, err error)
	Client        *http.Client
	Log           *slog.Logger
}

// Notifier is the webhook notifier.
type Notifier struct{ o Options }

// New validates o.
func New(o Options) (*Notifier, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("webhook: url %q is not an absolute URL", o.URL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, errors.New("webhook: plain http is only allowed to a loopback host")
		}
	default:
		return nil, fmt.Errorf("webhook: url scheme %q is not https", u.Scheme)
	}
	if o.Settler == nil || o.TokenFromLink == nil {
		return nil, errors.New("webhook: Settler and TokenFromLink are required")
	}
	if o.Secret.Len() > 0 && o.Secret.Len() < 32 {
		return nil, errors.New("webhook: secret must be at least 32 bytes")
	}
	if o.Name == "" {
		o.Name = "webhook"
	}
	if o.Hold <= 0 {
		o.Hold = 30 * time.Second
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 2 * time.Second
	}
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	hc := *o.Client
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	o.Client = &hc
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	o.URL = strings.TrimRight(o.URL, "/")
	return &Notifier{o: o}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Name implements notify.Notifier.
func (n *Notifier) Name() string { return n.o.Name }

// Envelope is the submit body.
type Envelope struct {
	Backend string      `json:"backend"`
	Request RequestBody `json:"request"`
}

// RequestBody is nono's ApprovalRequest with a scrim extension. Receivers
// ignore fields they do not know.
type RequestBody struct {
	CapabilityType string `json:"capability_type"`
	RequestID      string `json:"request_id"`
	SessionID      string `json:"session_id"`
	Reason         string `json:"reason"`
	ChildPID       int    `json:"child_pid"`
	// endpoint
	RouteID         string  `json:"route_id,omitempty"`
	CredentialRoute *string `json:"credential_route,omitempty"`
	Upstream        string  `json:"upstream,omitempty"`
	Method          string  `json:"method,omitempty"`
	Path            string  `json:"path,omitempty"`
	RuleLabel       string  `json:"rule_label,omitempty"`
	Operation       *string `json:"operation,omitempty"`
	// command
	Command       string   `json:"command,omitempty"`
	Args          []string `json:"args,omitempty"`
	Caller        string   `json:"caller,omitempty"`
	InterceptRule string   `json:"intercept_rule,omitempty"`

	Scrim Extension `json:"scrim"`
}

// Extension carries scrim's own fields.
type Extension struct {
	Agent      string    `json:"agent"`
	AgentKind  string    `json:"agent_kind,omitempty"`
	Action     string    `json:"action,omitempty"`
	Ref        string    `json:"ref,omitempty"`
	Name       string    `json:"name,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Tool       string    `json:"tool,omitempty"`
	Rule       string    `json:"rule"`
	ExpiresAt  time.Time `json:"expires_at"`
	ApproveURL string    `json:"approve_url,omitempty"`
	DenyURL    string    `json:"deny_url,omitempty"`
	Summary    string    `json:"summary"`
}

// Build returns the submit body for r.
func (n *Notifier) Build(r notify.Request) Envelope {
	s := r.Summary
	path, _, _ := strings.Cut(s.Path, "?")
	session := r.Agent.Session
	if session == "" {
		session = r.Agent.ID
	}
	b := RequestBody{
		RequestID: r.ApprovalID, SessionID: session, Reason: r.Reason,
		Scrim: Extension{
			Agent: r.Agent.ID, AgentKind: string(r.Agent.Kind), Action: string(s.Action), Name: s.Name,
			Provider: s.Provider, Tool: s.Tool, Rule: r.Rule, ExpiresAt: r.ExpiresAt, Summary: notify.Title(r),
		},
	}
	if !s.Ref.IsZero() {
		b.Scrim.Ref = s.Ref.String()
	}
	if notify.Absolute(r.ApproveURL) {
		b.Scrim.ApproveURL, b.Scrim.DenyURL = r.ApproveURL, r.DenyURL
	}
	switch {
	case s.Host != "":
		b.CapabilityType = "endpoint"
		b.RouteID = r.Rule
		if b.Scrim.Ref != "" {
			ref := b.Scrim.Ref
			b.CredentialRoute = &ref
		}
		b.Upstream, b.Method, b.Path = s.Host, s.Method, path
		b.RuleLabel = fmt.Sprintf("%s[%s %s]", r.Rule, s.Method, path)
	case s.Command != "" || s.Tool != "":
		b.CapabilityType = "command"
		b.Command = s.Command
		if b.Command == "" {
			b.Command = s.Tool
		}
		b.Caller = s.Tool
		b.InterceptRule = r.Rule
	default:
		// No nono equivalent: a store write, generation or capture.
		b.CapabilityType = "secret"
	}
	return Envelope{Backend: n.o.Name, Request: b}
}

// Status is a submit or poll response body.
type Status struct {
	RequestID string `json:"request_id"`
	State     string `json:"state"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
}

// Verdict is a parsed response.
type Verdict int

// Verdicts.
const (
	Pending Verdict = iota
	Granted
	Denied
	TimedOut
	Invalid
)

// Parse maps a response to a verdict like nono's client does: 200 or 202
// with a recognised decision or state, anything else invalid.
func Parse(status int, body []byte) Verdict {
	if status != http.StatusOK && status != http.StatusAccepted {
		return Invalid
	}
	var s Status
	if json.Unmarshal(body, &s) != nil {
		return Invalid
	}
	d := s.Decision
	if d == "" {
		d = s.State
	}
	switch strings.ToLower(d) {
	case "grant", "granted", "approve", "approved", "allow", "allowed",
		"grant_session", "granted_session", "allow_session", "always_allow":
		return Granted
	case "deny", "denied", "reject", "rejected", "block", "blocked",
		"deny_session", "denied_session", "always_deny":
		return Denied
	case "timeout", "timed_out":
		return TimedOut
	case "pending":
		return Pending
	}
	return Invalid
}

// Notify submits r and, if the receiver answers pending, keeps polling in
// the background until a final answer or r.ExpiresAt. It returns once the
// receiver has accepted the request (or answered it).
func (n *Notifier) Notify(ctx context.Context, r notify.Request) error {
	body, err := json.Marshal(n.Build(r))
	if err != nil {
		return err
	}
	v, err := n.call(ctx, http.MethodPost, n.o.URL, body, r.ExpiresAt)
	if err != nil {
		return err
	}
	switch v {
	case Pending:
		bg, cancel := context.WithDeadline(context.WithoutCancel(ctx), r.ExpiresAt)
		go func() {
			defer cancel()
			n.poll(bg, r)
		}()
		return nil
	case Invalid:
		return errors.New("webhook: receiver answered without a recognised decision")
	}
	return n.settle(ctx, r, v)
}

func (n *Notifier) poll(ctx context.Context, r notify.Request) {
	u := n.o.URL + "/" + url.PathEscape(r.ApprovalID)
	for ctx.Err() == nil {
		start := time.Now()
		v, err := n.call(ctx, http.MethodGet, u, nil, r.ExpiresAt)
		switch {
		case err != nil:
			n.o.Log.Warn("webhook poll failed", "notifier", n.o.Name, "approval", r.ApprovalID, "err", err)
		case v == Pending:
		case v == Invalid:
			n.o.Log.Warn("webhook poll: no recognised decision; leaving the approval pending", "notifier", n.o.Name, "approval", r.ApprovalID)
			return
		default:
			if err := n.settle(ctx, r, v); err != nil {
				n.o.Log.Warn("webhook decision not applied", "notifier", n.o.Name, "approval", r.ApprovalID, "err", err)
			}
			return
		}
		// A receiver that does not hold gets polled at PollInterval.
		if wait := n.o.PollInterval - time.Since(start); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
	}
}

func (n *Notifier) settle(ctx context.Context, r notify.Request, v Verdict) error {
	var link string
	switch v {
	case Granted:
		link = r.ApproveURL
	case Denied:
		link = r.DenyURL
	default:
		return nil // timeout: the approval expires on its own
	}
	id, tok, err := n.o.TokenFromLink(link)
	if err != nil {
		return err
	}
	if id != r.ApprovalID {
		return errors.New("webhook: decision link names another approval")
	}
	return n.o.Settler.SettleToken(ctx, id, tok)
}

// call does one submit or poll with the hold budget, never following
// redirects.
func (n *Notifier) call(ctx context.Context, method, u string, body []byte, deadline time.Time) (Verdict, error) {
	hold := n.o.Hold
	if left := time.Until(deadline); left < hold {
		hold = left
	}
	if hold <= 0 {
		return Invalid, context.DeadlineExceeded
	}
	ctx, cancel := context.WithTimeout(ctx, hold+5*time.Second)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return Invalid, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "scrim/"+version.Version)
	req.Header.Set("X-Nono-Timeout-Secs", strconv.Itoa(max(1, int(hold.Seconds()))))
	if n.o.Secret.Len() > 0 {
		if err := n.sign(req, body); err != nil {
			return Invalid, err
		}
	}
	resp, err := n.o.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return Invalid, fmt.Errorf("webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Invalid, err
	}
	v := Parse(resp.StatusCode, data)
	if v == Invalid {
		return Invalid, fmt.Errorf("webhook: receiver answered %s", resp.Status)
	}
	return v, nil
}

// Canonical returns the string a signature covers.
func Canonical(method, path, timestamp, requestID, digest string) string {
	return strings.Join([]string{"scrim-webhook-v1", method, path, timestamp, requestID, digest}, "\n")
}

func (n *Notifier) sign(req *http.Request, body []byte) error {
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	rid := hex.EncodeToString(nonce)
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	canon := Canonical(req.Method, req.URL.RequestURI(), ts, rid, digest)
	var sig []byte
	err := n.o.Secret.Expose(func(k []byte) error {
		h := hmac.New(sha256.New, k)
		h.Write([]byte(canon))
		sig = h.Sum(nil)
		return nil
	})
	if err != nil {
		return err
	}
	req.Header.Set("X-Scrim-Timestamp", ts)
	req.Header.Set("X-Scrim-Request-Id", rid)
	req.Header.Set("X-Scrim-Content-SHA256", digest)
	req.Header.Set("X-Scrim-Signature", "hmac-sha256="+base64.RawURLEncoding.EncodeToString(sig))
	return nil
}

// Verify checks a signed request on the receiving side, for receivers
// written in Go and for tests. It does not track nonces; a receiver must
// reject a repeated X-Scrim-Request-Id within the skew window.
func Verify(secretKey []byte, r *http.Request, body []byte, skew time.Duration, now time.Time) error {
	ts := r.Header.Get("X-Scrim-Timestamp")
	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("webhook: bad timestamp")
	}
	if d := now.Sub(time.UnixMilli(ms)); d > skew || d < -skew {
		return errors.New("webhook: timestamp outside the skew window")
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if r.Header.Get("X-Scrim-Content-SHA256") != digest {
		return errors.New("webhook: body digest mismatch")
	}
	sig, ok := strings.CutPrefix(r.Header.Get("X-Scrim-Signature"), "hmac-sha256=")
	if !ok {
		return errors.New("webhook: missing signature")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return errors.New("webhook: bad signature encoding")
	}
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(Canonical(r.Method, r.URL.RequestURI(), ts, r.Header.Get("X-Scrim-Request-Id"), digest)))
	if !hmac.Equal(got, h.Sum(nil)) {
		return errors.New("webhook: signature does not verify")
	}
	return nil
}
