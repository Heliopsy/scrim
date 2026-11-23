// SPDX-License-Identifier: AGPL-3.0-only

// Package sshkeys is the control plane's side of scrim's ssh-agent
// (specs/credential-injection, "SSH agent"): it offers the catalog's
// ssh_key entries, decides each signature through the policy gate (op
// ssh.sign: allow, deny, or ask a human, per signature or per grant
// window), signs with the key read from its store, and audits every
// signature and refusal.
//
// A private key is read from its store into a secret.Value, parsed in the
// narrowest scope that needs it and dropped after one signature. Its bytes
// never leave this package: the agent gets public keys and signatures.
// Parsed RSA and ECDSA keys live in big.Int values Go cannot wipe; ed25519
// keys are wiped after use.
package sshkeys

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/sshagent"
	"github.com/heliopsy/scrim/internal/stores"
)

// KnownHosts names the known_hosts files that give a verified host key its
// name (dest.host).
var KnownHosts = config.Register(config.Spec[[]string]{
	Key: "ssh-agent.known-hosts",
	Description: "known_hosts files (OpenSSH format) that name the hosts scrim's ssh-agent signs logins for: a login " +
		"whose session binding verifies a host key listed here sees that line's first plain host name as dest.host. " +
		"Use files the agent cannot write; hashed and wildcard entries are not used.",
})

// Tool is the tool name of every ssh-agent decision (tool.name, grant scope).
const Tool = "ssh"

// RuleRefused is the audit rule of a signature refused before policy.
const RuleRefused = "ssh-agent"

// unknownAtList are the attributes a key list cannot know yet.
var unknownAtList = []string{"ssh.kind", "ssh.user", "ssh.namespace"}

// Checker decides one operation; *gate.Gate implements it.
type Checker interface {
	Check(ctx context.Context, req policy.Request, o gate.Options) gate.Verdict
}

// Offerer says whether a request could be allowed; *policy.Live
// implements it.
type Offerer interface {
	MayAllow(req policy.Request, unknown ...string) bool
}

// Keyring serves the local API's ssh-agent routes.
type Keyring struct {
	// Catalog returns the catalog in force.
	Catalog func() *catalog.Catalog
	// Resolve reads one value from its store; the caller wipes it.
	Resolve func(ctx context.Context, ref stores.Ref) (secret.Value, error)
	// Gate decides, asks, leaves grants and audits each signature.
	Gate Checker
	// Offer decides which keys to list.
	Offer Offerer
	// DenyAll reports break-glass deny-all; nil means never.
	DenyAll func() bool
	// Labels gives the labels a list decision sees (the gate fills them
	// in for signatures).
	Labels func(ctx context.Context, ref stores.Ref) (map[string]string, error)
	// KnownHosts returns ssh-agent.known-hosts.
	KnownHosts func() []string
	// Record writes refusals made before policy to the audit log.
	Record func(ctx context.Context, e audit.Entry) error
	Log    *slog.Logger
	Now    func() time.Time
}

func (k *Keyring) log() *slog.Logger {
	if k.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return k.Log
}

func (k *Keyring) now() time.Time {
	if k.Now == nil {
		return time.Now()
	}
	return k.Now()
}

// key is one catalog key, loaded for one request.
type key struct {
	b      catalog.Binding
	signer ssh.Signer
	cert   ssh.Signer // nil without a certificate
	raw    any
	fp     string
}

func (k *key) wipe() {
	switch p := k.raw.(type) {
	case *ed25519.PrivateKey:
		secret.WipeBytes(*p)
	case ed25519.PrivateKey:
		secret.WipeBytes(p)
	case *rsa.PrivateKey:
		p.D.SetInt64(0)
		for _, q := range p.Primes {
			q.SetInt64(0)
		}
	case *ecdsa.PrivateKey:
		if p.D != nil { //nolint:staticcheck // the only handle on the scalar
			p.D.SetInt64(0) //nolint:staticcheck // see above
		}
	}
	k.raw, k.signer, k.cert = nil, nil, nil
}

func (k *key) blobs() [][]byte {
	out := [][]byte{k.signer.PublicKey().Marshal()}
	if k.cert != nil {
		out = append(out, k.cert.PublicKey().Marshal())
	}
	return out
}

// bindings returns the catalog's ssh_key entries.
func (k *Keyring) bindings() []catalog.Binding {
	cat := k.Catalog()
	if cat == nil {
		return nil
	}
	var out []catalog.Binding
	for _, e := range cat.Entries() {
		if e.OK && e.Binding.SSHKey && !e.Binding.Ref.IsZero() {
			out = append(out, e.Binding)
		}
	}
	return out
}

// load reads and parses one key. Errors name the entry, never the value.
func (k *Keyring) load(ctx context.Context, b catalog.Binding) (*key, error) {
	v, err := k.Resolve(ctx, b.Ref)
	if err != nil {
		return nil, fmt.Errorf("ssh key %s: %w", b.Name, err)
	}
	defer v.Wipe()
	out := &key{b: b}
	err = v.Expose(func(pem []byte) error {
		raw, err := ssh.ParseRawPrivateKey(pem)
		if err != nil {
			var pp *ssh.PassphraseMissingError
			if errors.As(err, &pp) {
				return errors.New("the key is encrypted; scrim needs it without a passphrase (the store protects it)")
			}
			return errors.New("the value is not an OpenSSH or PEM private key")
		}
		out.raw = raw
		s, err := ssh.NewSignerFromKey(raw)
		if err != nil {
			return errors.New("unsupported key type")
		}
		out.signer = s
		return nil
	})
	if err != nil {
		out.wipe()
		return nil, fmt.Errorf("ssh key %s: %w", b.Name, err)
	}
	out.fp = ssh.FingerprintSHA256(out.signer.PublicKey())
	if !b.SSHCertificate.IsZero() {
		if err := k.loadCert(ctx, out); err != nil {
			out.wipe()
			return nil, err
		}
	}
	return out, nil
}

func (k *Keyring) loadCert(ctx context.Context, out *key) error {
	b := out.b
	v, err := k.Resolve(ctx, b.SSHCertificate)
	if err != nil {
		return fmt.Errorf("ssh certificate of %s: %w", b.Name, err)
	}
	defer v.Wipe()
	var cert *ssh.Certificate
	err = v.Expose(func(line []byte) error {
		pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return errors.New("not an OpenSSH certificate line")
		}
		c, ok := pub.(*ssh.Certificate)
		if !ok {
			return errors.New("a public key, not a certificate")
		}
		cert = c
		return nil
	})
	if err != nil {
		return fmt.Errorf("ssh certificate of %s: %w", b.Name, err)
	}
	if !bytes.Equal(cert.Key.Marshal(), out.signer.PublicKey().Marshal()) {
		return fmt.Errorf("ssh certificate of %s: certifies another key", b.Name)
	}
	cs, err := ssh.NewCertSigner(cert, out.signer)
	if err != nil {
		return fmt.Errorf("ssh certificate of %s: %w", b.Name, err)
	}
	out.cert = cs
	return nil
}

func (k *Keyring) request(id identity.Identity, b catalog.Binding) policy.Request {
	return policy.Request{
		Agent: id.PolicyAgent(), Action: policy.ActionSign, Ref: b.Ref, Name: b.Name, Store: b.Ref.Scheme,
		SecretClass: string(b.Class), Tool: Tool, Time: k.now(),
	}
}

// Keys lists the keys the caller's policy could let it sign with, for the
// host the connection is bound to.
func (k *Keyring) Keys(ctx context.Context, id identity.Identity, bindings []sshagent.Binding) ([]sshagent.Key, error) {
	if err := authorize(id); err != nil {
		return nil, err
	}
	host, err := sshagent.HostOf(bindings)
	if err != nil {
		return nil, agenttools.Errorf(agenttools.CodeDenied, "%s", err.Error())
	}
	if k.DenyAll != nil && k.DenyAll() {
		return []sshagent.Key{}, nil
	}
	hostName, hostFP := k.hostOf(host)
	out := []sshagent.Key{}
	for _, b := range k.bindings() {
		kk, err := k.load(ctx, b)
		if err != nil {
			k.log().Warn("ssh key not offered", "name", b.Name, "ref", b.Ref.String(), "error", err)
			continue
		}
		req := k.request(id, b)
		req.Host = hostName
		req.SSH = policy.SSHRequest{Kind: policy.SSHKindList, Key: kk.fp, HostKey: hostFP}
		if k.Labels != nil {
			req.SecretLabels, err = k.Labels(ctx, b.Ref)
			req.SecretLabelsUnknown = err != nil
		}
		if k.Offer.MayAllow(req, unknownAtList...) {
			for _, blob := range kk.blobs() {
				out = append(out, sshagent.Key{Blob: blob, Comment: "scrim:" + b.Name})
			}
		}
		kk.wipe()
	}
	return out, nil
}

// Sign signs req.Data with the key it names, if the parsed data, the
// bindings and policy allow it.
func (k *Keyring) Sign(ctx context.Context, id identity.Identity, req sshagent.SignRequest) (sshagent.Signature, error) {
	if err := authorize(id); err != nil {
		return sshagent.Signature{}, err
	}
	refuse := func(ref stores.Ref, attrs map[string]string, reason string) (sshagent.Signature, error) {
		k.refused(ctx, id, ref, attrs, reason)
		return sshagent.Signature{}, agenttools.Errorf(agenttools.CodeDenied, "ssh signature refused: %s", reason)
	}
	signed, err := sshagent.ParseSigned(req.Data)
	if err != nil {
		return refuse(stores.Ref{}, nil, err.Error())
	}
	attrs := map[string]string{"ssh_kind": signed.Kind}
	if signed.User != "" {
		attrs["ssh_user"] = signed.User
	}
	if signed.Namespace != "" {
		attrs["ssh_namespace"] = signed.Namespace
	}
	host, err := sshagent.Check(signed, req.Key, req.Bindings)
	if err != nil {
		return refuse(stores.Ref{}, attrs, err.Error())
	}
	kk, err := k.find(ctx, req.Key)
	if err != nil {
		return refuse(stores.Ref{}, attrs, err.Error())
	}
	defer kk.wipe()
	hostName, hostFP := k.hostOf(host)
	attrs["ssh_key"] = kk.fp
	if hostFP != "" {
		attrs["ssh_host_key"] = hostFP
	}
	preq := k.request(id, kk.b)
	preq.Host = hostName
	preq.SSH = policy.SSHRequest{Kind: signed.Kind, User: signed.User, Namespace: signed.Namespace, Key: kk.fp, HostKey: hostFP}
	v := k.Gate.Check(ctx, preq, gate.Options{Wait: true, Attrs: attrs})
	if !v.Allowed() {
		reason := v.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return sshagent.Signature{}, agenttools.Errorf(agenttools.CodeDenied, "ssh signature refused: %s", reason)
	}
	signer := kk.signer
	if kk.cert != nil && bytes.Equal(req.Key, kk.cert.PublicKey().Marshal()) {
		signer = kk.cert
	}
	sig, err := sign(signer, req.Data, req.Flags)
	if err != nil {
		k.log().Error("ssh signature failed after it was allowed", "name", kk.b.Name, "error", err)
		return sshagent.Signature{}, agenttools.Errorf(agenttools.CodeInternal, "signing failed")
	}
	return sshagent.Signature{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}, nil
}

// find loads the catalog key whose public key or certificate is blob.
func (k *Keyring) find(ctx context.Context, blob []byte) (*key, error) {
	if _, err := ssh.ParsePublicKey(blob); err != nil {
		return nil, errors.New("malformed key")
	}
	for _, b := range k.bindings() {
		kk, err := k.load(ctx, b)
		if err != nil {
			k.log().Warn("ssh key could not be loaded", "name", b.Name, "ref", b.Ref.String(), "error", err)
			continue
		}
		for _, have := range kk.blobs() {
			if bytes.Equal(blob, have) {
				return kk, nil
			}
		}
		kk.wipe()
	}
	return nil, errors.New("no catalog ssh_key holds this key")
}

func authorize(id identity.Identity) error {
	if !id.Known() {
		return agenttools.Errorf(agenttools.CodeUnauthenticated, "the caller has no agent identity")
	}
	if !id.Has(identity.ScopeSecretsRequest) {
		return agenttools.Errorf(agenttools.CodeForbidden, "the caller's identity lacks scope %s", identity.ScopeSecretsRequest)
	}
	return nil
}

// refused audits a signature refused before policy was asked.
func (k *Keyring) refused(ctx context.Context, id identity.Identity, ref stores.Ref, attrs map[string]string, reason string) {
	k.log().Warn("ssh signature refused", "agent", id.String(), "reason", reason)
	if k.Record == nil {
		return
	}
	a := map[string]string{"action": string(policy.ActionSign), "status": string(gate.Denied)}
	for n, v := range attrs {
		a[n] = v
	}
	e := audit.Entry{Time: k.now(), Action: gate.ActionDecision, Actor: id.PolicyAgent().ID, Agent: id.PolicyAgent(), Ref: ref,
		Effect: policy.Deny, Rule: RuleRefused, Target: Tool, Outcome: audit.OutcomeRefused, Reason: reason, Attrs: a}
	if err := k.Record(ctx, e); err != nil {
		k.log().Error("audit write failed for a refused ssh signature", "error", err)
	}
}

// hostOf names a verified host key from ssh-agent.known-hosts, and returns
// its fingerprint. Both are empty without a host key.
func (k *Keyring) hostOf(host ssh.PublicKey) (name, fingerprint string) {
	if host == nil {
		return "", ""
	}
	fingerprint = ssh.FingerprintSHA256(host)
	if k.KnownHosts == nil {
		return "", fingerprint
	}
	want := host.Marshal()
	for _, f := range k.KnownHosts() {
		if n := lookupKnownHosts(f, want); n != "" {
			return n, fingerprint
		}
	}
	return "", fingerprint
}

// lookupKnownHosts returns the first plain host name file lists for the host
// key want, or empty. A @revoked line for the key names nothing, and stops
// the lookup.
func lookupKnownHosts(file string, want []byte) string {
	data, err := os.ReadFile(file) //nolint:gosec // an operator-configured path
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		marker, hosts, pub, _, _, err := ssh.ParseKnownHosts(sc.Bytes())
		if err != nil || !bytes.Equal(pub.Marshal(), want) {
			continue
		}
		switch marker {
		case "revoked":
			return ""
		case "":
		default:
			continue
		}
		for _, h := range hosts {
			if strings.HasPrefix(h, "|") || strings.ContainsAny(h, "*?!") {
				continue
			}
			if strings.HasPrefix(h, "[") {
				if hp, port, ok := strings.Cut(strings.TrimPrefix(h, "["), "]:"); ok {
					h = hp + ":" + port
				}
			}
			return strings.ToLower(h)
		}
	}
	return ""
}

// sign signs with the algorithm the flags ask for (RSA SHA-2).
func sign(s ssh.Signer, data []byte, flags uint32) (*ssh.Signature, error) {
	if flags&(sshagent.FlagRSASHA256|sshagent.FlagRSASHA512) == 0 {
		return s.Sign(rand.Reader, data)
	}
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("the key cannot sign with another algorithm")
	}
	alg := ssh.KeyAlgoRSASHA256
	if flags&sshagent.FlagRSASHA512 != 0 {
		alg = ssh.KeyAlgoRSASHA512
	}
	return as.SignWithAlgorithm(rand.Reader, data, alg)
}
