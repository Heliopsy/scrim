// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/edge"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

// edgeSetup is a daemon with Kubernetes identity against a fake TokenReview
// API and its edge listener on, as central scrim runs in a cluster.
type edgeSetup struct {
	h    *harness
	d    *Daemon
	kapi *fakeTokenReview
	ctx  context.Context
}

func startEdgeDaemon(t *testing.T, rules, entries, extraConfig string) *edgeSetup {
	t.Helper()
	h := newHarness(t, seed(t, "sk-edge-"))
	kapi := newFakeTokenReview(t)
	if err := os.WriteFile(filepath.Join(h.dir, "rules.yaml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(h.dir, "kube-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kapi.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokFile := filepath.Join(h.dir, "scrim-sa-token")
	if err := os.WriteFile(tokFile, []byte(kapi.reviewer), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(h.dir, "config.yaml")
	cfg, err := os.ReadFile(cfgPath) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	cfg = []byte(strings.Replace(string(cfg), "catalog:\n  entries:\n", "catalog:\n  entries:\n"+entries, 1))
	cfg = append(cfg, []byte(`identity:
  kubernetes:
    enabled: true
    api-server: `+kapi.srv.URL+`
    ca-file: `+caFile+`
    token-file: `+tokFile+`
edge:
  listen: 127.0.0.1:0
  server-names: [scrim.scrim.svc.cluster.local, 127.0.0.1]
  ca: {dir: `+filepath.Join(h.dir, "edge-ca")+`}
`+extraConfig)...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}
	t.Cleanup(func() { _ = d.Shutdown(context.Background()) })
	eventually(t, "daemon ready", func() bool { return d.Ready(ctx) })
	if d.Addrs().Edge == "" {
		t.Fatal("no edge listener address")
	}
	return &edgeSetup{h: h, d: d, kapi: kapi, ctx: ctx}
}

// forwarder returns a forwarder for the pod whose token is tok, trusting
// the daemon's edge CA as agent pods do.
func (s *edgeSetup) forwarder(t *testing.T, tok string) *edge.Forwarder {
	t.Helper()
	return s.forwarderTrusting(t, tok, s.d.EdgeTrustBundlePEM())
}

func (s *edgeSetup) forwarderTrusting(t *testing.T, tok, caPEM string) *edge.Forwarder {
	t.Helper()
	tc, err := edge.NewTLSConfig([]byte(caPEM), "scrim.scrim.svc.cluster.local")
	if err != nil {
		t.Fatal(err)
	}
	return &edge.Forwarder{Central: s.d.Addrs().Edge, TLS: tc, DialTimeout: 5 * time.Second,
		Token: func() ([]byte, error) { return []byte(tok), nil }}
}

// oldForwarder is a forwarder as scrim 1.0 built it: it trusts the
// interception CA and does not announce the edge CA.
func (s *edgeSetup) oldForwarder(t *testing.T, tok string) *edge.Forwarder {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(s.d.TrustBundlePEM())) {
		t.Fatal("no interception CA")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "scrim.scrim.svc.cluster.local",
		NextProtos: []string{"http/1.1"}}
	return &edge.Forwarder{Central: s.d.Addrs().Edge, TLS: tc, DialTimeout: 5 * time.Second,
		Token: func() ([]byte, error) { return []byte(tok), nil }}
}

// TestEdgeListenerHasItsOwnCA: the edge listener's certificate comes from
// the edge CA, a name-constrained CA with its own key. A forwarder that
// trusts the interception CA is refused; one that trusts the edge CA is
// served.
func TestEdgeListenerHasItsOwnCA(t *testing.T) {
	s := startEdgeDaemon(t, "default: deny\n", "", "")
	edgePEM, interception := s.d.EdgeTrustBundlePEM(), s.d.TrustBundlePEM()
	if edgePEM == "" || interception == "" {
		t.Fatal("no edge or interception CA")
	}
	if ca.SharesKey([]string{edgePEM}, []string{interception}) {
		t.Fatal("the edge CA has the interception CA's key")
	}
	blk, _ := pem.Decode([]byte(edgePEM))
	edgeCert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !edgeCert.PermittedDNSDomainsCritical || len(edgeCert.PermittedDNSDomains) != 1 ||
		edgeCert.PermittedDNSDomains[0] != "scrim.scrim.svc.cluster.local" || len(edgeCert.PermittedIPRanges) != 1 ||
		!edgeCert.MaxPathLenZero {
		t.Fatalf("edge CA constraints: dns %v ip %v pathlen0 %v", edgeCert.PermittedDNSDomains, edgeCert.PermittedIPRanges, edgeCert.MaxPathLenZero)
	}
	tok := s.kapi.issue("agents", "agent-a")
	if id, err := s.forwarder(t, tok).Check(s.ctx); err != nil || id.Agent == "" {
		t.Fatalf("forwarder trusting the edge CA: %v %v\n%s", id, err, s.h.logs.String())
	}
	if err := refusedCertificate(t, s.forwarderTrusting(t, tok, interception), s.ctx); err != nil {
		t.Fatalf("a forwarder trusting the interception CA: %v", err)
	}
	if err := refusedCertificate(t, s.oldForwarder(t, tok), s.ctx); err != nil {
		t.Fatalf("a 1.0 forwarder without %s: %v", edge.LegacyInterceptionCertificate.Name(), err)
	}
}

// refusedCertificate dials through f and reports an error unless the
// handshake failed on an unknown authority before the token was read.
func refusedCertificate(t *testing.T, f *edge.Forwarder, ctx context.Context) error {
	t.Helper()
	f.Token = func() ([]byte, error) {
		t.Error("the forwarder read its token for a central certificate it does not trust")
		return nil, errors.New("no token")
	}
	c, err := f.Dial(ctx, edge.PathSSHAgent)
	if err == nil {
		_ = c.Close()
		return errors.New("connected")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		return fmt.Errorf("failed otherwise: %w", err)
	}
	return nil
}

// TestEdgeLegacyInterceptionCertificate: during an upgrade window a 1.0
// forwarder, which trusts the interception CA and does not announce the
// edge CA, is served the interception CA's certificate, while a current
// forwarder still accepts only the edge CA.
func TestEdgeLegacyInterceptionCertificate(t *testing.T) {
	s := startEdgeDaemon(t, "default: deny\n", "", "  legacy-interception-certificate: true\n")
	tok := s.kapi.issue("agents", "agent-a")
	if id, err := s.oldForwarder(t, tok).Check(s.ctx); err != nil || id.Agent == "" {
		t.Fatalf("1.0 forwarder in the upgrade window: %v %v\n%s", id, err, s.h.logs.String())
	}
	if id, err := s.forwarder(t, tok).Check(s.ctx); err != nil || id.Agent == "" {
		t.Fatalf("forwarder trusting the edge CA: %v %v", id, err)
	}
	if err := refusedCertificate(t, s.forwarderTrusting(t, tok, s.d.TrustBundlePEM()), s.ctx); err != nil {
		t.Fatalf("a current forwarder trusting the interception CA: %v", err)
	}
	if !strings.Contains(s.h.logs.String(), "legacy-interception-certificate is on") {
		t.Fatal("no warning about the weakening setting")
	}
}

// sshServer accepts one key for any user and reports whether the login
// succeeded.
func sshServer(t *testing.T, authorized ssh.PublicKey) (addr string, host ssh.Signer) {
	t.Helper()
	_, hpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err = ssh.NewSignerFromKey(hpriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), authorized.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("unknown key")
	}}
	cfg.AddHostKey(host)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					_ = nc.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no")
				}
			}()
		}
	}()
	return ln.Addr().String(), host
}

// TestEdgeForwarder runs the daemon as central scrim with its edge listener
// and an in-process forwarder per pod, as `scrim edge` runs in agent pods:
//
//   - an SSH login signed through the forwarder for the service account and
//     user a rule allows; a login as another user is denied its signature,
//     and another service account is offered no key;
//   - the agent API through the forwarder answers as the pod's agent;
//   - a token the cluster does not accept opens no tunnel;
//   - every signature is audited as the pod's agent, and no token or key is
//     in a log or audit entry.
func TestEdgeForwarder(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(blk))
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCRIMTEST_SSH_KEY", keyPEM)
	sshAddr, host := sshServer(t, signer.PublicKey())
	// Go's SSH client sends no session binding, so dest.host stays empty
	// here; the kind test covers host-bound logins with OpenSSH.

	s := startEdgeDaemon(t, `default: deny
rules:
  - name: edge-git
    decision: allow
    when: >-
      op == "ssh.sign" && agent.labels.service_account == "agent-a" && ssh.user == "git"
`, "    deploy:\n      ref: testenv://SCRIMTEST_SSH_KEY\n      ssh_key: true\n",
		"")

	tokA, tokB := s.kapi.issue("agents", "agent-a"), s.kapi.issue("agents", "agent-b")
	forged := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.forged-" + seed(t, "")

	login := func(tok, user string) error {
		up, err := s.forwarder(t, tok).Dial(s.ctx, edge.PathSSHAgent)
		if err != nil {
			return err
		}
		defer func() { _ = up.Close() }()
		ag := agent.NewClient(up)
		cl, err := ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
			HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 10 * time.Second})
		if err != nil {
			return err
		}
		return cl.Close()
	}
	if err := login(tokA, "git"); err != nil {
		t.Fatalf("agent-a login through the forwarder: %v\n%s", err, s.h.logs.String())
	}
	if err := login(tokA, "root"); err == nil {
		t.Fatal("a login as another user went through although no rule allows its signature")
	}
	if err := login(tokB, "git"); err == nil {
		t.Fatal("agent-b's login went through although no rule allows its signature")
	}
	if up, err := s.forwarder(t, tokB).Dial(s.ctx, edge.PathSSHAgent); err != nil {
		t.Fatal(err)
	} else {
		keys, err := agent.NewClient(up).List()
		_ = up.Close()
		if err != nil || len(keys) != 0 {
			t.Fatalf("agent-b was offered %d keys (%v)", len(keys), err)
		}
	}
	var re *edge.RefusedError
	if err := login(forged, "git"); !errors.As(err, &re) || re.Status != http.StatusUnauthorized {
		t.Fatalf("a forged token: %v", err)
	}

	// The agent API through the forwarder: the pod's agent, never a local peer.
	sock := filepath.Join(shortTempDir(t), "api.sock")
	ln, err := localapi.Listen(sock, localapi.ListenOptions{Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.forwarder(t, tokA).ServeAPI(s.ctx, ln) }()
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	resp, err := hc.Get("http://scrim/v1/whoami")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var id identity.Identity
	if err := json.Unmarshal(body, &id); err != nil || id.Agent != "agents/agent-a" || id.Source != identity.SourceKubernetes {
		t.Fatalf("whoami through the forwarder: %s", body)
	}

	// Audit: the signatures were decided for the pods' agents; the forged
	// token was refused by the edge listener. No token or key anywhere.
	secrets := []string{tokA, tokB, forged, keyPEM[40:100]}
	var decisions []string
	refusedEdge := false
	_ = s.d.App().State.View(s.ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(s.ctx, state.AuditQuery{})
		for _, e := range es {
			b, _ := json.Marshal(e)
			for _, v := range secrets {
				if strings.Contains(string(b), v) {
					t.Errorf("a token or key is in the audit log: %s", e.Action)
				}
			}
			if e.Action == gate.ActionDecision && e.Attrs["action"] == "ssh.sign" {
				decisions = append(decisions, e.Agent.ID+"/"+e.Attrs["status"])
			}
			if e.Attrs["tool"] == edge.ToolEdge || strings.Contains(e.Action, edge.ToolEdge) {
				refusedEdge = true
			}
		}
		return err
	})
	all := strings.Join(decisions, " ")
	// agent-b is offered no key at all (listing is decided too), so its
	// login never gets as far as a signature.
	for _, want := range []string{"agents/agent-a/allowed", "agents/agent-a/denied"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q ssh.sign decision: %s", want, all)
		}
	}
	if !refusedEdge {
		t.Error("the forged token's refusal was not audited")
	}
	for _, v := range secrets {
		if strings.Contains(s.h.logs.String(), v) {
			t.Error("a token or key is in the daemon's log")
		}
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "scrim-edge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestEdgeForwarderDatabase opens the PostgreSQL auth proxy through an edge
// tunnel, as a client on a forwarded port in an agent pod does: the agent a
// rule allows is logged in as scrim's database user, with only a placeholder
// for a password; another service account is refused before scrim logs in;
// both are decided for the pod's agent; the password reaches no log.
func TestEdgeForwarderDatabase(t *testing.T) {
	dbtestPostgres.Start(t)
	pw := leak.Generate(leak.KindDBPassword)
	user := "edge_" + podtest.RandHex(4)
	dbtestPostgres.Exec(t, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", user, pw.Value()))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "db-ca.pem"), dbtestPostgres.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "db-pw"), []byte(pw.Value()), 0o600); err != nil {
		t.Fatal(err)
	}
	s := startEdgeDaemon(t, `default: deny
rules:
  - name: edge-db
    decision: allow
    when: op == "database.auth" && agent.labels.service_account == "agent-a" && dest.path == "/app"
`, "", fmt.Sprintf("databases:\n  app:\n    kind: postgres\n    address: %s\n    user: %s\n    password: file:%s\n"+
		"    database: scrim\n    listen: 127.0.0.1:0\n    tls-ca: %s\n    tls-server-name: localhost\n",
		dbtestPostgres.Addr, user, filepath.Join(dir, "db-pw"), filepath.Join(dir, "db-ca.pem")))

	connect := func(tok string) (*pgconn.PgConn, error) {
		f := s.forwarder(t, tok)
		cfg, err := pgconn.ParseConfig("host=127.0.0.1 port=5432 user=anything password=SCRIM_DB_PASSWORD dbname=scrim sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return f.Dial(ctx, edge.PathDatabase+"/app")
		}
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		defer cancel()
		return pgconn.ConnectConfig(ctx, cfg)
	}
	pc, err := connect(s.kapi.issue("agents", "agent-a"))
	if err != nil {
		t.Fatalf("agent-a through the tunnel: %v\n%s", err, s.h.logs.String())
	}
	res, err := pc.Exec(s.ctx, "SELECT current_user").ReadAll()
	if err != nil || len(res) != 1 || len(res[0].Rows) != 1 || string(res[0].Rows[0][0]) != user {
		t.Fatalf("query through the tunnel: %v %v", res, err)
	}
	_ = pc.Close(s.ctx)
	if pc, err := connect(s.kapi.issue("agents", "agent-b")); err == nil {
		_ = pc.Close(s.ctx)
		t.Fatal("agent-b was logged in although no rule allows it")
	} else if !strings.Contains(err.Error(), "denied by policy") {
		t.Fatalf("agent-b refused for another reason: %v", err)
	}

	var decisions []string
	_ = s.d.App().State.View(s.ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(s.ctx, state.AuditQuery{})
		for _, e := range es {
			if e.Action == gate.ActionDecision && e.Attrs["action"] == "database.auth" {
				decisions = append(decisions, e.Agent.ID+"/"+e.Attrs["status"])
			}
		}
		return err
	})
	all := strings.Join(decisions, " ")
	for _, want := range []string{"agents/agent-a/allowed", "agents/agent-b/denied"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q database.auth decision: %s", want, all)
		}
	}
	if strings.Contains(s.h.logs.String(), pw.Value()) {
		t.Error("the database password is in the daemon's log")
	}
}
