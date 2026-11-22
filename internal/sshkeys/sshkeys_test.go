// SPDX-License-Identifier: AGPL-3.0-only

package sshkeys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/sshagent"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

var dev = identity.Identity{Agent: "dev", Source: identity.SourceSession, SessionID: "s1",
	Scopes: identity.AgentScopes, Peer: identity.Peer{UID: 1000}}

type rig struct {
	k     *Keyring
	st    state.Store
	apps  *approval.Service
	bg    *breakglass.Switch
	pems  map[string][]byte // ref -> PEM, for the leak check
	host  ssh.Signer
	known string
}

// newRig builds a keyring over a real gate (memory state), a catalog of
// ssh_key entries and generated keys held in a map standing in for stores.
func newRig(t *testing.T, rules string, values map[string][]byte, entries ...catalog.Entry) *rig {
	t.Helper()
	ctx := context.Background()
	st := memstate.New()
	bg, err := breakglass.New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Parse([]byte(rules), false)
	if err != nil {
		t.Fatal(err)
	}
	live, err := policy.NewLive(cfg)
	if err != nil {
		t.Fatal(err)
	}
	limits := func(gs policy.GrantSettings) grant.Limits {
		l := grant.Limits{Default: 30 * time.Minute, Max: 8 * time.Hour}
		if gs.TTL > 0 {
			l.Default = gs.TTL.D()
		}
		return l
	}
	apps, err := approval.New(approval.Options{State: st, Signer: approval.RandomSigner(), BreakGlass: bg,
		Timeout: 5 * time.Second, PollInterval: 5 * time.Millisecond,
		Grants: func(rule string) (grant.Limits, policy.GrantSettings) {
			r, _ := live.Rule(rule)
			return limits(r.Grant), r.Grant
		}})
	if err != nil {
		t.Fatal(err)
	}
	g := &gate.Gate{Engine: bg.Engine(live), Rules: live, Grants: grant.NewService(st, bg), Approvals: apps,
		BreakGlass: bg, State: st, Limits: limits}
	cat, err := catalog.Compile(catalog.Input{Entries: entries}, catalog.Selection{})
	if err != nil {
		t.Fatal(err)
	}
	host := signer(t, ed25519Key(t))
	known := filepath.Join(t.TempDir(), "known_hosts")
	line := "|1|aGFzaA==|aGFzaA== " + string(ssh.MarshalAuthorizedKey(host.PublicKey())) +
		"git.scrim.test,10.0.0.1 " + string(ssh.MarshalAuthorizedKey(host.PublicKey()))
	if err := os.WriteFile(known, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &rig{st: st, apps: apps, bg: bg, pems: values, host: host, known: known}
	r.k = &Keyring{
		Catalog: func() *catalog.Catalog { return cat },
		Resolve: func(_ context.Context, ref stores.Ref) (secret.Value, error) {
			v, ok := values[ref.String()]
			if !ok {
				return secret.Value{}, stores.NewError(ref.Scheme, stores.OpRead, ref, stores.ErrNotFound, nil)
			}
			return secret.New(append([]byte(nil), v...)), nil
		},
		Gate: g, Offer: live, DenyAll: bg.Active,
		KnownHosts: func() []string { return []string{known} },
		Record: func(ctx context.Context, e audit.Entry) error {
			return state.Apply(ctx, st, func(state.Tx) (state.Change, error) { return state.Change{Audit: e}, nil })
		},
	}
	return r
}

func ed25519Key(t *testing.T) []byte {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(b)
}

func signer(t *testing.T, p []byte) ssh.Signer {
	t.Helper()
	s, err := ssh.ParsePrivateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (r *rig) bind(t *testing.T, session []byte) sshagent.Binding {
	t.Helper()
	sig, err := r.host.Sign(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	return sshagent.Binding{HostKey: r.host.PublicKey().Marshal(), SessionID: session, Signature: ssh.Marshal(sig)}
}

func put32(b []byte, s []byte) []byte {
	b = append(b, byte(len(s)>>24), byte(len(s)>>16), byte(len(s)>>8), byte(len(s)))
	return append(b, s...)
}

func login(session []byte, user string, pub ssh.PublicKey, hostKey ssh.PublicKey) []byte {
	b := put32(nil, session)
	b = append(b, 50)
	b = put32(b, []byte(user))
	b = put32(b, []byte("ssh-connection"))
	b = put32(b, []byte("publickey-hostbound-v00@openssh.com"))
	b = append(b, 1)
	b = put32(b, []byte(pub.Type()))
	b = put32(b, pub.Marshal())
	return put32(b, hostKey.Marshal())
}

func (r *rig) audit(t *testing.T) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	err := r.st.View(context.Background(), func(tx state.Tx) error {
		var err error
		out, err = tx.QueryAudit(context.Background(), state.AuditQuery{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// noLeak fails when any PEM body shows up in the audit log or in s.
func (r *rig) noLeak(t *testing.T, extra ...string) {
	t.Helper()
	raw, _ := json.Marshal(r.audit(t))
	hay := string(raw) + strings.Join(extra, "\n")
	for ref, p := range r.pems {
		blk, _ := pem.Decode(p)
		for _, line := range strings.Split(string(p), "\n") {
			if len(line) > 20 && !strings.HasPrefix(line, "-----") && strings.Contains(hay, line) {
				t.Fatalf("key material of %s leaked", ref)
			}
		}
		if blk != nil && strings.Contains(hay, string(blk.Bytes)) {
			t.Fatalf("key bytes of %s leaked", ref)
		}
	}
}

const allowGit = `default: deny
rules:
  - name: git-login
    decision: allow
    when: op == "ssh.sign" && secret.name == "deploy" && ssh.kind == "userauth" && ssh.user == "git" && dest.host == "git.scrim.test"
`

func TestListOnlyWhatPolicyMayAllow(t *testing.T) {
	deploy, other := ed25519Key(t), ed25519Key(t)
	r := newRig(t, allowGit, map[string][]byte{"mem://k/deploy": deploy, "mem://k/other": other},
		catalog.Entry{Name: "deploy", Ref: "mem://k/deploy", SSHKey: true},
		catalog.Entry{Name: "other", Ref: "mem://k/other", SSHKey: true},
		catalog.Entry{Name: "token", Ref: "mem://k/token", Hosts: []string{"api.example.com"}})
	ctx := context.Background()
	sess := []byte("session-identifier-0123456789")
	keys, err := r.k.Keys(ctx, dev, []sshagent.Binding{r.bind(t, sess)})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || string(keys[0].Blob) != string(signer(t, deploy).PublicKey().Marshal()) || keys[0].Comment != "scrim:deploy" {
		t.Fatalf("keys = %+v", keys)
	}
	// Without a binding the host is unknown, so the rule cannot allow.
	if keys, _ := r.k.Keys(ctx, dev, nil); len(keys) != 0 {
		t.Fatalf("unbound connection got %d keys", len(keys))
	}
	if err := r.bg.Engage(ctx, "test", "test"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := r.k.Keys(ctx, dev, []sshagent.Binding{r.bind(t, sess)}); len(keys) != 0 {
		t.Fatal("break-glass must hide every key")
	}
	if _, err := r.k.Keys(ctx, identity.Unknown(identity.Peer{}), nil); err == nil {
		t.Fatal("an unknown caller must be refused")
	}
	r.noLeak(t)
}

func TestSignAllowedDeniedAndAudited(t *testing.T) {
	deploy := ed25519Key(t)
	r := newRig(t, allowGit, map[string][]byte{"mem://k/deploy": deploy},
		catalog.Entry{Name: "deploy", Ref: "mem://k/deploy", SSHKey: true})
	ctx := context.Background()
	s := signer(t, deploy)
	sess := []byte("session-identifier-0123456789")
	data := login(sess, "git", s.PublicKey(), r.host.PublicKey())
	sig, err := r.k.Sign(ctx, dev, sshagent.SignRequest{Key: s.PublicKey().Marshal(), Data: data, Bindings: []sshagent.Binding{r.bind(t, sess)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PublicKey().Verify(data, &ssh.Signature{Format: sig.Format, Blob: sig.Blob}); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	var errs []string
	// Another user: policy denies.
	_, err = r.k.Sign(ctx, dev, sshagent.SignRequest{Key: s.PublicKey().Marshal(),
		Data: login(sess, "root", s.PublicKey(), r.host.PublicKey()), Bindings: []sshagent.Binding{r.bind(t, sess)}})
	if err == nil {
		t.Fatal("a login as root must be denied")
	}
	errs = append(errs, err.Error())
	// Refused before policy: arbitrary data, a session that does not match
	// the binding, a forwarded channel, a key scrim does not hold.
	stranger := signer(t, ed25519Key(t))
	for name, req := range map[string]sshagent.SignRequest{
		"raw data":      {Key: s.PublicKey().Marshal(), Data: []byte("sign me")},
		"other session": {Key: s.PublicKey().Marshal(), Data: login([]byte("another-session"), "git", s.PublicKey(), r.host.PublicKey()), Bindings: []sshagent.Binding{r.bind(t, sess)}},
		"forwarded":     {Key: s.PublicKey().Marshal(), Data: data, Bindings: []sshagent.Binding{func() sshagent.Binding { b := r.bind(t, sess); b.Forwarding = true; return b }()}},
		"unknown key":   {Key: stranger.PublicKey().Marshal(), Data: login(sess, "git", stranger.PublicKey(), r.host.PublicKey()), Bindings: []sshagent.Binding{r.bind(t, sess)}},
	} {
		if _, err := r.k.Sign(ctx, dev, req); err == nil {
			t.Errorf("%s: signed", name)
		} else {
			errs = append(errs, err.Error())
		}
	}
	entries := r.audit(t)
	var allowed, denied, refused int
	for _, e := range entries {
		if e.Action != gate.ActionDecision {
			continue
		}
		switch {
		case e.Rule == RuleRefused:
			refused++
		case e.Effect == policy.Allow:
			allowed++
			if e.Attrs["ssh_user"] != "git" || e.Attrs["ssh_host_key"] == "" || e.Attrs["ssh_key"] != ssh.FingerprintSHA256(s.PublicKey()) || e.Target != "git.scrim.test" {
				t.Errorf("allowed entry lacks detail: %+v", e)
			}
		default:
			denied++
		}
	}
	if allowed != 1 || denied != 1 || refused != 4 {
		t.Fatalf("audit: %d allowed, %d denied, %d refused; want 1, 1, 4", allowed, denied, refused)
	}
	r.noLeak(t, errs...)
}

func TestSignAskPerSignatureAndGrantWindow(t *testing.T) {
	deploy := ed25519Key(t)
	r := newRig(t, `default: deny
rules:
  - name: ask-each
    decision: ask
    when: op == "ssh.sign" && ssh.user == "each"
    grant: {scope: once}
  - name: ask-window
    decision: ask
    when: op == "ssh.sign" && ssh.user == "window"
    grant: {ttl: 10m}
`, map[string][]byte{"mem://k/deploy": deploy}, catalog.Entry{Name: "deploy", Ref: "mem://k/deploy", SSHKey: true})
	ctx := context.Background()
	s := signer(t, deploy)
	sign := func(user string, approve *bool) error {
		sess := []byte("session-" + user + fmt.Sprint(time.Now().UnixNano()))
		done := make(chan error, 1)
		go func() {
			_, err := r.k.Sign(ctx, dev, sshagent.SignRequest{Key: s.PublicKey().Marshal(),
				Data: login(sess, user, s.PublicKey(), r.host.PublicKey()), Bindings: []sshagent.Binding{r.bind(t, sess)}})
			done <- err
		}()
		if approve != nil {
			deadline := time.Now().Add(5 * time.Second)
			for {
				p, err := r.apps.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
				if err == nil && len(p) > 0 {
					if p[0].Request.SSH.User != user || p[0].Request.Tool != Tool {
						t.Errorf("approval shows %+v", p[0].Request.SSH)
					}
					if _, err := r.apps.Decide(ctx, p[0].ID, approval.Decision{Approve: *approve, By: "test", Via: "api"}); err != nil {
						t.Fatal(err)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no approval was created (%v)", <-done)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		return <-done
	}
	yes, no := true, false
	if err := sign("each", &yes); err != nil {
		t.Fatalf("approved signature: %v", err)
	}
	if err := sign("each", &no); err == nil {
		t.Fatal("a denied approval must refuse the signature")
	}
	if err := sign("each", &yes); err != nil {
		t.Fatalf("each signature asks again: %v", err)
	}
	if err := sign("window", &yes); err != nil {
		t.Fatal(err)
	}
	if err := sign("window", nil); err != nil {
		t.Fatalf("the grant window must cover the next signature: %v", err)
	}
}

func TestKeyTypesAndCertificate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509MarshalEC(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509MarshalPKCS1(rsaKey)})
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	edPEM := ed25519Key(t)
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(ed25519.NewKeyFromSeed(make([]byte, 32)), "", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	// A certificate for the ed25519 key, signed by a throwaway CA.
	ca := signer(t, ed25519Key(t))
	ed := signer(t, edPEM)
	cert := &ssh.Certificate{Key: ed.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"git"},
		ValidBefore: ssh.CertTimeInfinity, KeyId: "test"}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	values := map[string][]byte{
		"mem://k/rsa": rsaPEM, "mem://k/ec": ecPEM, "mem://k/ed": edPEM,
		"mem://k/ed-cert": ssh.MarshalAuthorizedKey(cert), "mem://k/enc": pem.EncodeToMemory(encBlock),
	}
	r := newRig(t, `default: deny
rules:
  - {name: all, decision: allow, when: 'op == "ssh.sign"'}
`, values,
		catalog.Entry{Name: "rsa", Ref: "mem://k/rsa", SSHKey: true},
		catalog.Entry{Name: "ec", Ref: "mem://k/ec", SSHKey: true},
		catalog.Entry{Name: "ed", Ref: "mem://k/ed", SSHKey: true, SSHCertificate: "mem://k/ed-cert"},
		catalog.Entry{Name: "enc", Ref: "mem://k/enc", SSHKey: true})
	ctx := context.Background()
	keys, err := r.k.Keys(ctx, dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 { // rsa, ec, ed and its certificate; the encrypted key is not offered
		t.Fatalf("got %d keys", len(keys))
	}
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			t.Fatal(err)
		}
		data := login([]byte("session-identifier"), "git", pub, r.host.PublicKey())
		flags := uint32(0)
		if pub.Type() == ssh.KeyAlgoRSA {
			flags = sshagent.FlagRSASHA512
		}
		sig, err := r.k.Sign(ctx, dev, sshagent.SignRequest{Key: k.Blob, Data: data, Flags: flags})
		if err != nil {
			t.Fatalf("%s: %v", pub.Type(), err)
		}
		if flags != 0 && sig.Format != ssh.KeyAlgoRSASHA512 {
			t.Errorf("rsa signed with %s", sig.Format)
		}
		if err := pub.Verify(data, &ssh.Signature{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}); err != nil {
			t.Errorf("%s: signature does not verify: %v", pub.Type(), err)
		}
	}
	r.noLeak(t)
}
