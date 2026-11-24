// SPDX-License-Identifier: AGPL-3.0-only

// Package issuer makes scrim an OpenID Connect style identity provider for
// its agents (specs/agent-identity "scrim as an identity provider for
// agents"). It signs short-lived JWTs for one agent and one audience, and
// serves the discovery document and JWKS that let a store or cloud verify
// them (OpenBao and Vault JWT auth, AWS AssumeRoleWithWebIdentity, Google
// workload identity federation, Entra ID federated credentials, Infisical
// OIDC machine identities).
//
// Tokens are minted only for an identity scrim has already established
// from the transport, and only for scrim's own use toward a store: they are
// never handed to an agent. Each one is reported through
// [Options.OnMint] so it joins the redaction set until it expires.
//
// Signing keys are generated and rotated in a private directory, or
// supplied by the operator (for replicas that must publish the same JWKS).
// A generated key is published one rotation period before it starts to
// sign, and stays published after it is replaced until the last token it
// signed has expired, so rotation never breaks a live token whichever copy
// of the JWKS a verifier holds. Private keys never reach a log, error,
// metric or response: [signingKey] formats as its key ID.
package issuer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// RetireLeeway is how long past a replaced key's last possible token
// expiry it stays published, covering verifiers' expiry leeway and clock
// skew (OpenBao's JWT auth accepts tokens up to 150 seconds late by
// default).
const RetireLeeway = 5 * time.Minute

// maxCached bounds the token cache; when full, expired entries go first and
// then everything.
const maxCached = 4096

// Errors Mint returns.
var (
	ErrUnknownCaller = errors.New("issuer: no token for an unknown caller")
	ErrNoAudience    = errors.New("issuer: an audience is required")
	ErrSessionEnded  = errors.New("issuer: the session has ended")
)

// Options build an Issuer.
type Options struct {
	// URL is the issuer (the iss claim); discovery lives under it.
	URL string
	// TokenTTL is each token's lifetime.
	TokenTTL time.Duration
	// RotateEvery is the rotation period of generated keys.
	RotateEvery time.Duration
	// KeyDir holds generated keys. Ignored when Keys is set.
	KeyDir string
	// Keys are operator-managed PEM keys; the first signs. Not owned.
	Keys secret.Value
	// Profile and Host fill the profile and host claims.
	Profile, Host string
	// OnMint receives a copy of every newly minted token and its expiry,
	// which it owns (it wipes the copy).
	OnMint func(token secret.Value, expires time.Time)
	// Log receives key events (key IDs only).
	Log *slog.Logger
	// Now and Generate are for tests.
	Now      func() time.Time
	Generate func() (*rsa.PrivateKey, error)
}

// Issuer signs identity tokens and publishes its keys.
type Issuer struct {
	url         string
	discovery   []byte
	ttl, rotate time.Duration
	profile     string
	host        string
	onMint      func(secret.Value, time.Time)
	log         *slog.Logger
	now         func() time.Time

	mu sync.Mutex
	// dir is nil for operator keys, which never rotate.
	dir    *keyDir
	state  diskState
	keys   map[string]signingKey
	signer signingKey
	jwks   []byte
	cache  map[[32]byte]cachedToken
}

type cachedToken struct {
	tok      secret.Value
	session  string
	expires  time.Time
	reuseTil time.Time
}

// String keeps fmt and slog from printing an Issuer's keys.
func (i *Issuer) String() string {
	if i == nil {
		return "issuer.Issuer(nil)"
	}
	return "issuer.Issuer(" + i.url + ")"
}

// GoString implements fmt.GoStringer like [Issuer.String].
func (i *Issuer) GoString() string { return i.String() }

// LogValue implements slog.LogValuer like [Issuer.String].
func (i *Issuer) LogValue() slog.Value { return slog.StringValue(i.String()) }

// MarshalJSON encodes an Issuer as [Issuer.String].
func (i *Issuer) MarshalJSON() ([]byte, error) { return json.Marshal(i.String()) }

// FromConfig builds the issuer the configuration describes, nil when
// identity.issuer.url is empty. getenv nil means os.Getenv.
func FromConfig(cfg *config.Config, getenv func(string) string, log *slog.Logger, onMint func(secret.Value, time.Time)) (*Issuer, error) {
	raw := URLSetting.Get(cfg)
	listen := ListenSetting.Get(cfg)
	if raw == "" {
		if listen != "" {
			return nil, fmt.Errorf("%s is set but %s is empty", ListenSetting.Name(), URLSetting.Name())
		}
		return nil, nil
	}
	if listen == "" {
		return nil, fmt.Errorf("%s is set: set %s to the address that serves its discovery document and JWKS", URLSetting.Name(), ListenSetting.Name())
	}
	o := Options{URL: raw, TokenTTL: TokenTTLSetting.Get(cfg), RotateEvery: RotateEverySetting.Get(cfg),
		Profile: cfg.Profile(), OnMint: onMint, Log: log}
	if _, err := checkURL(raw, InsecureHTTPSetting.Get(cfg)); err != nil {
		return nil, err
	}
	if ref := SigningKeysSetting.Get(cfg); ref != "" {
		v, ok := cfg.Secret(SigningKeysSetting)
		if !ok {
			return nil, fmt.Errorf("%s (%s) is set but could not be resolved", SigningKeysSetting.Name(), ref.Display())
		}
		o.Keys = v
	} else {
		o.KeyDir = KeyDirSetting.Get(cfg)
		if o.KeyDir == "" {
			d, err := DefaultKeyDir(getenv)
			if err != nil {
				return nil, err
			}
			o.KeyDir = d
		}
		if !filepath.IsAbs(o.KeyDir) {
			return nil, fmt.Errorf("%s %q must be an absolute path", KeyDirSetting.Name(), o.KeyDir)
		}
	}
	if h, err := os.Hostname(); err == nil {
		o.Host = h
	}
	return New(o)
}

// New loads or creates the signing keys and returns the issuer. A
// generated key set that is due for rotation is rotated now.
func New(o Options) (*Issuer, error) {
	if err := validIssuerURL(o.URL); err != nil || o.URL == "" {
		return nil, fmt.Errorf("issuer: URL %q: %w", o.URL, errors.Join(err, errors.New("required")))
	}
	if o.TokenTTL <= 0 {
		o.TokenTTL = DefaultTokenTTL
	}
	if o.RotateEvery <= 0 {
		o.RotateEvery = DefaultRotateEvery
	}
	if o.RotateEvery < o.TokenTTL+RetireLeeway {
		return nil, fmt.Errorf("issuer: %s (%s) must be longer than %s plus %s",
			RotateEverySetting.Name(), o.RotateEvery, TokenTTLSetting.Name(), RetireLeeway)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Generate == nil {
		o.Generate = generateKey
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	i := &Issuer{url: o.URL, ttl: o.TokenTTL, rotate: o.RotateEvery, profile: o.Profile, host: o.Host,
		onMint: o.OnMint, log: o.Log, now: o.Now, cache: map[[32]byte]cachedToken{}}
	disc, err := discoveryDoc(o.URL)
	if err != nil {
		return nil, err
	}
	i.discovery = disc
	if !o.Keys.IsZero() {
		keys, err := parseKeys(o.Keys)
		if err != nil {
			return nil, fmt.Errorf("issuer: %s: %w", SigningKeysSetting.Name(), err)
		}
		i.keys = map[string]signingKey{}
		for _, k := range keys {
			i.keys[k.kid] = k
		}
		i.signer = keys[0]
		i.publishLocked(keys)
		i.log.Info("identity issuer uses operator-managed signing keys", "signing_kid", i.signer.kid, "published", len(keys))
		return i, nil
	}
	if o.KeyDir == "" {
		return nil, errors.New("issuer: a key directory or operator keys are required")
	}
	if err := ensureDir(o.KeyDir); err != nil {
		return nil, err
	}
	i.dir = &keyDir{dir: o.KeyDir, generate: o.Generate}
	st, keys, err := i.dir.load()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := i.initKeys(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		i.state, i.keys = st, keys
		i.signer = keys[st.Current]
		i.publishStateLocked()
	}
	if err := i.Tick(); err != nil {
		return nil, err
	}
	return i, nil
}

// initKeys creates the first current and next keys.
func (i *Issuer) initKeys() error {
	cur, err := i.dir.newKey()
	if err != nil {
		return err
	}
	next, err := i.dir.newKey()
	if err != nil {
		return err
	}
	st := diskState{Version: stateVersion, Current: cur.kid, ActivatedAt: i.now().UTC(), Next: next.kid}
	if err := i.dir.save(st); err != nil {
		return err
	}
	i.state = st
	i.keys = map[string]signingKey{cur.kid: cur, next.kid: next}
	i.signer = cur
	i.publishStateLocked()
	i.log.Info("identity issuer generated its signing keys", "signing_kid", cur.kid, "next_kid", next.kid)
	return nil
}

// Tick rotates generated keys when the current one has signed for
// RotateEvery and drops replaced keys whose tokens have all expired. It is
// a no-op for operator keys.
func (i *Issuer) Tick() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.dir == nil {
		return nil
	}
	now := i.now().UTC()
	st := i.state
	st.Retiring = slices.Clone(st.Retiring)
	changed := false
	if !now.Before(st.ActivatedAt.Add(i.rotate)) {
		next, err := i.dir.newKey()
		if err != nil {
			return err
		}
		i.keys[next.kid] = next
		st.Retiring = append(st.Retiring, retiring{Kid: st.Current, RetireAt: now.Add(i.ttl + RetireLeeway)})
		st.Current, st.ActivatedAt, st.Next = st.Next, now, next.kid
		changed = true
		i.log.Info("identity issuer rotated its signing key", "signing_kid", st.Current, "next_kid", st.Next,
			"retiring_kid", st.Retiring[len(st.Retiring)-1].Kid)
	}
	kept := st.Retiring[:0]
	for _, r := range st.Retiring {
		if now.Before(r.RetireAt) {
			kept = append(kept, r)
			continue
		}
		delete(i.keys, r.Kid)
		changed = true
		i.log.Info("identity issuer stopped publishing a replaced key", "kid", r.Kid)
	}
	st.Retiring = kept
	if !changed {
		return nil
	}
	if err := i.dir.save(st); err != nil {
		return err
	}
	i.state = st
	i.signer = i.keys[st.Current]
	i.publishStateLocked()
	return nil
}

// Rotate rotates generated keys now, whatever their age. Operator keys
// cannot be rotated by scrim.
func (i *Issuer) Rotate() error {
	i.mu.Lock()
	if i.dir == nil {
		i.mu.Unlock()
		return fmt.Errorf("issuer: %s are rotated by the operator", SigningKeysSetting.Name())
	}
	i.state.ActivatedAt = i.now().UTC().Add(-i.rotate)
	i.mu.Unlock()
	return i.Tick()
}

// Run calls Tick every minute until ctx ends. A failed rotation is logged
// and retried: the current key keeps signing meanwhile.
func (i *Issuer) Run(ctx context.Context) {
	if i.dir == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := i.Tick(); err != nil {
			i.log.Error("identity issuer key rotation failed; the current key keeps signing", "err", err)
		}
	}
}

// publishStateLocked publishes current, next and retiring keys.
func (i *Issuer) publishStateLocked() {
	ks := []signingKey{i.keys[i.state.Current], i.keys[i.state.Next]}
	for _, r := range i.state.Retiring {
		ks = append(ks, i.keys[r.Kid])
	}
	i.publishLocked(ks)
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (i *Issuer) publishLocked(ks []signingKey) {
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: make([]jwk, 0, len(ks))}
	for _, k := range ks {
		pub := k.public()
		set.Keys = append(set.Keys, jwk{Kty: "RSA", Use: "sig", Alg: Alg, Kid: k.kid,
			N: b64(pub.N.Bytes()), E: b64(bigEndian(pub.E))})
	}
	b, _ := json.Marshal(set)
	i.jwks = b
}

func bigEndian(e int) []byte {
	var out []byte
	for ; e > 0; e >>= 8 {
		out = append([]byte{byte(e & 0xff)}, out...)
	}
	return out
}

// KeyIDs returns the signing key's ID and every published key ID.
func (i *Issuer) KeyIDs() (signing string, published []string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	var set struct {
		Keys []jwk `json:"keys"`
	}
	_ = json.Unmarshal(i.jwks, &set)
	for _, k := range set.Keys {
		published = append(published, k.Kid)
	}
	return i.signer.kid, published
}

// PublicKeys returns the published keys by ID, as a verifier sees them.
func (i *Issuer) PublicKeys() map[string]*rsa.PublicKey {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := map[string]*rsa.PublicKey{}
	for kid, k := range i.keys {
		out[kid] = k.public()
	}
	return out
}

// URL is the issuer URL.
func (i *Issuer) URL() string { return i.url }

// TokenTTL is the lifetime of a token minted now.
func (i *Issuer) TokenTTL() time.Duration { return i.ttl }

// ClaimsFor returns the claims a token for id and audience carries, without
// the times and token ID.
func (i *Issuer) ClaimsFor(id identity.Identity, audience string) (Claims, error) {
	if !id.Known() {
		return Claims{}, ErrUnknownCaller
	}
	if audience == "" {
		return Claims{}, ErrNoAudience
	}
	a := id.PolicyAgent()
	c := Claims{Issuer: i.url, Subject: Subject(id), Audience: audience, Agent: id.Agent, AgentKind: string(a.Kind),
		Session: id.SessionID, SessionName: id.SessionName, Profile: i.profile}
	switch id.Source {
	case identity.SourceKubernetes:
		c.Namespace = id.Labels[identity.LabelNamespace]
		c.ServiceAccount = id.Labels[identity.LabelServiceAccount]
		c.Pod = id.Labels[identity.LabelPod]
	case identity.SourceCertificate:
		// A certificate's holder runs anywhere; the machine scrim runs on
		// says nothing about it.
	default:
		c.Host = i.host
	}
	return c, nil
}

// Subject is the sub claim of id's tokens: stable for an agent across its
// sessions, so a store's trust policy can name it exactly (Entra ID
// federated credentials match the subject verbatim). `agent:<name>` for
// local agents, `k8s:<name>` for Kubernetes ones, whose derived names are
// <namespace>/<service account>, and `mtls:<name>` for agents identified by
// a client certificate.
func Subject(id identity.Identity) string {
	switch id.Source {
	case identity.SourceKubernetes:
		return "k8s:" + id.Agent
	case identity.SourceCertificate:
		return "mtls:" + id.Agent
	default:
		return "agent:" + id.Agent
	}
}

// Mint returns a token for id toward audience and its expiry; the caller
// owns and wipes the copy. A token minted for the same claims is reused
// while two thirds of its lifetime remain, so a burst of store operations
// does not grow the redaction set. A session's token never outlives the
// session.
func (i *Issuer) Mint(id identity.Identity, audience string) (secret.Value, time.Time, error) {
	c, err := i.ClaimsFor(id, audience)
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	now := i.now()
	exp := now.Add(i.ttl)
	if !id.ExpiresAt.IsZero() && id.ExpiresAt.Before(exp) {
		exp = id.ExpiresAt
	}
	if !exp.After(now.Add(time.Second)) {
		return secret.Value{}, time.Time{}, ErrSessionEnded
	}
	key := cacheKey(c)
	i.mu.Lock()
	if ct, ok := i.cache[key]; ok && now.Before(ct.reuseTil) {
		tok, until := copyValue(ct.tok), ct.expires
		i.mu.Unlock()
		return tok, until, nil
	}
	signer := i.signer
	i.mu.Unlock()

	c.IssuedAt, c.NotBefore, c.Expiry = now.Unix(), now.Unix(), exp.Unix()
	c.ID, err = randomID()
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	raw, err := sign(signer, c)
	if err != nil {
		return secret.Value{}, time.Time{}, fmt.Errorf("issuer: sign: %w", err)
	}
	tok := secret.Adopt(raw)
	expires := time.Unix(c.Expiry, 0)
	if i.onMint != nil {
		i.onMint(copyValue(tok), expires)
	}
	i.mu.Lock()
	i.pruneLocked(now)
	if old, ok := i.cache[key]; ok {
		old.tok.Wipe()
	}
	i.cache[key] = cachedToken{tok: tok, session: c.Session, expires: expires, reuseTil: now.Add(exp.Sub(now) * 2 / 3)}
	out := copyValue(tok)
	i.mu.Unlock()
	return out, expires, nil
}

func (i *Issuer) pruneLocked(now time.Time) {
	if len(i.cache) < maxCached {
		return
	}
	for k, ct := range i.cache {
		if !now.Before(ct.reuseTil) {
			ct.tok.Wipe()
			delete(i.cache, k)
		}
	}
	if len(i.cache) >= maxCached {
		for k, ct := range i.cache {
			ct.tok.Wipe()
			delete(i.cache, k)
		}
	}
}

// Forget drops cached tokens whose session is id, so an ended session's
// token is never handed out again.
func (i *Issuer) Forget(sessionID string) {
	if sessionID == "" {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	for k, ct := range i.cache {
		if ct.session == sessionID {
			ct.tok.Wipe()
			delete(i.cache, k)
		}
	}
}

// Close wipes every cached token.
func (i *Issuer) Close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	for k, ct := range i.cache {
		ct.tok.Wipe()
		delete(i.cache, k)
	}
}

func cacheKey(c Claims) [32]byte {
	b, _ := json.Marshal(c)
	return sha256.Sum256(b)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("issuer: token id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}

// Discovery and JWKS paths, under the issuer URL's path.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	JWKSPath      = "/.well-known/jwks.json"
)

func discoveryDoc(issuer string) ([]byte, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	doc := map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              u.String() + JWKSPath,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{Alg},
		"claims_supported": []string{"iss", "sub", "aud", "iat", "nbf", "exp", "jti", "agent", "agent_kind",
			"session", "session_name", "host", "namespace", "service_account", "pod", "profile"},
	}
	return json.Marshal(doc)
}
