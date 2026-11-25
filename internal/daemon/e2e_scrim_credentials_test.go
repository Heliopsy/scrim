// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/plugin/plugintest"
	"github.com/heliopsy/scrim/internal/state/postgres"
	"github.com/heliopsy/scrim/internal/testing/certtest"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// scrimCredPlaceholder is how the placeholder of one of scrim's own
// credentials starts: the scrim-config value source, no reference.
const scrimCredPlaceholder = "⟦scrim:scrim-config-credential:"

// testCA is a CA certificate file and its PKCS#8 PEM key.
func testCA(t *testing.T, dir string) (certFile, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scrim credentials test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "operator-ca.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))
}

// credValue is a generated value long enough for every setting's minimum
// (approvals.signing-key and notify.webhook.secret need 32 bytes).
func credValue() string {
	return leak.Generate(leak.KindDBPassword).Value() + leak.Generate(leak.KindDBPassword).Value()
}

// credSeed is a leak seed for a generated credential. The fixed parts of a
// PEM block or a JWT header are public, so a log line that mentions a PEM
// type is not a finding.
func credSeed(what, v string) leak.Seed {
	var public []string
	for _, p := range []string{"-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----", "postgres://scrim:"} {
		if strings.Contains(v, p) {
			public = append(public, p)
		}
	}
	if head, _, ok := strings.Cut(v, "."); ok && strings.HasPrefix(v, "eyJ") {
		public = append(public, head+".")
	}
	return leak.NewSeed(what, leak.KindPassword, v, public...)
}

// TestScrimCredentialsRedactedRealDataPlane: every credential scrim holds
// for itself (each secret-ref setting, the notifier plugin and placeholder
// key collection fields, the password inside state.postgres.dsn, the NATS
// credentials file and scrim's own Kubernetes service account token),
// pasted into a model request, reaches the provider only as a placeholder
// of the scrim-config source and never appears in the log. A value rotated
// by a reload follows. The settings are taken from the registry, so a new
// secret-ref setting is covered without editing this test.
func TestScrimCredentialsRedactedRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()

	h := newHarness(t, seed(t, "tok-"))
	h.opts.DataPlaneEnv = nil
	env := []string{"SCRIM_DATAPLANE_PATH=" + bin, "SCRIM_PROXY_UPSTREAM_ANTHROPIC=" + up.URL}
	creds := map[string]string{} // what -> value
	var keys []string
	certFile, caKey := testCA(t, h.dir)
	for _, s := range config.Default.Settings() {
		if s.Kind != config.KindSecretRef {
			continue
		}
		v := credValue()
		switch s.Key {
		case ca.KeySetting.Name():
			v = caKey
			env = append(env, "SCRIM_TOOL_PROXY_CA_CERT_FILE="+certFile)
		case agentapi.CertListenerKey.Name():
			// A real pair: scrim refuses a listener key that does not match its certificate.
			agents := certtest.NewCA(t, "agents")
			server := agents.Issue(t, certtest.Leaf{CN: "scrim.example.test", ServerOnly: true})
			agentsFile, listenerFile := filepath.Join(h.dir, "agents-ca.pem"), filepath.Join(h.dir, "listener.crt")
			for f, b := range map[string][]byte{agentsFile: agents.PEM, listenerFile: server.CertPEM} {
				if err := os.WriteFile(f, b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			v = string(server.KeyPEM)
			env = append(env, "SCRIM_IDENTITY_CLIENT_CERTIFICATES_ENABLED=true",
				"SCRIM_IDENTITY_CLIENT_CERTIFICATES_CA=file:"+agentsFile,
				"SCRIM_IDENTITY_CLIENT_CERTIFICATES_LISTENER_CERT_FILE="+listenerFile)
		case postgres.DSNSetting.Name():
			pw := credValue()
			creds["state.postgres.dsn password"] = pw
			v = "postgres://scrim:" + pw + "@127.0.0.1:1/scrim?sslmode=verify-full"
		}
		name := "SCRIMCRED_" + strings.NewReplacer(".", "_", "-", "_").Replace(strings.ToUpper(s.Key))
		env = append(env, s.EnvVar()+"=env:"+name, name+"="+v)
		creds[s.Key] = v
		keys = append(keys, s.Key)
	}
	if len(keys) < 10 {
		t.Fatalf("only %d secret-ref settings found", len(keys))
	}

	// Collection secret fields: the notifier plugin's credential (the
	// example plugin takes a token only; TestScrimCredentialsSource covers
	// the other fields) and a placeholder key. Database passwords and store
	// credentials have their own sources and tests.
	plug := plugintest.Build(t, "./examples/plugins/filenotify")
	yaml := "notify:\n  plugins:\n    pager:\n      command: " + plug + "\n      options: {path: " + filepath.Join(h.dir, "approvals.jsonl") + "}\n"
	for _, f := range []string{"token"} {
		v := credValue()
		name := "SCRIMCRED_NOTIFY_PLUGIN_" + strings.ToUpper(f)
		env = append(env, name+"="+v)
		creds["notify.plugins.pager."+f] = v
		yaml += "      " + f + ": env:" + name + "\n"
	}
	pk := credValue()
	creds["redaction.placeholder-keys.k1.key"] = pk
	env = append(env, "SCRIMCRED_PLACEHOLDER_KEY="+pk)
	yaml += "redaction:\n  placeholder-keys:\n    k1:\n      version: 1\n      key: env:SCRIMCRED_PLACEHOLDER_KEY\n"

	// A rotating setting read from a file.
	ntfyFile := filepath.Join(h.dir, "ntfy-token")
	writeCred := func(path, v string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	creds["notify.ntfy.token"] = credValue()
	writeCred(ntfyFile, creds["notify.ntfy.token"])
	env = append(env, "SCRIM_NOTIFY_NTFY_TOKEN=file:"+ntfyFile)

	// Credential files scrim's clients read themselves.
	natsFile := filepath.Join(h.dir, "nats.creds")
	natsCreds := func(jwt, seed string) string {
		return "-----BEGIN NATS USER JWT-----\n" + jwt + "\n------END NATS USER JWT------\n\n" +
			"************************* IMPORTANT *************************\n\n" +
			"-----BEGIN USER NKEY SEED-----\n" + seed + "\n------END USER NKEY SEED------\n"
	}
	creds["nats.credentials-file jwt"] = leak.Generate(leak.KindJWT).Value()
	creds["nats.credentials-file seed"] = credValue()
	writeCred(natsFile, natsCreds(creds["nats.credentials-file jwt"], creds["nats.credentials-file seed"]))
	kubeFile := filepath.Join(h.dir, "sa-token")
	creds["identity.kubernetes.token-file"] = leak.Generate(leak.KindJWT).Value()
	writeCred(kubeFile, creds["identity.kubernetes.token-file"]+"\n")
	env = append(env, "SCRIM_NATS_CREDENTIALS_FILE="+natsFile,
		"SCRIM_IDENTITY_KUBERNETES_ENABLED=true", "SCRIM_IDENTITY_KUBERNETES_API_SERVER=https://127.0.0.1:1",
		"SCRIM_IDENTITY_KUBERNETES_CA_FILE="+certFile, "SCRIM_IDENTITY_KUBERNETES_TOKEN_FILE="+kubeFile)

	h.appendConfig(t, yaml)
	h.opts.Config.Environ = append(h.opts.Config.Environ, env...)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, h.logs.String())
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	deadline := time.Now().Add(30 * time.Second)
	for !d.Ready(ctx) {
		if time.Now().After(deadline) {
			t.Fatalf("daemon not ready: %+v\n%s", d.Info().Problems, h.logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	var seeds []leak.Seed
	for what, v := range creds {
		seeds = append(seeds, credSeed(what, v))
	}
	send := func(what, v string) {
		t.Helper()
		content, _ := json.Marshal("connect with " + v + " and retry")
		body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":` + string(content) + `}]}`
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.Addrs().BaseURL+"/anthropic/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "agent-own-key")
		req.Header.Set("anthropic-version", "2023-06-01")
		before := len(fake.Exchanges())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		reply, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d: %s", what, resp.StatusCode, reply)
			return
		}
		ex := fake.Exchanges()
		if len(ex) != before+1 {
			t.Fatalf("%s: provider saw %d new requests", what, len(ex)-before)
		}
		got := ex[len(ex)-1]
		if strings.Contains(string(got.Body), v) {
			t.Errorf("%s: the provider received the value", what)
		}
		if !slices.ContainsFunc(got.Placeholders, func(p string) bool { return strings.HasPrefix(p, scrimCredPlaceholder) }) {
			t.Errorf("%s: not redacted as one of scrim's credentials (placeholders %v)", what, got.Placeholders)
		}
	}
	for _, what := range slices.Sorted(func(yield func(string) bool) {
		for k := range creds {
			if !yield(k) {
				return
			}
		}
	}) {
		send(what, creds[what])
	}

	// Rotation: a reload reads the new file values and the set follows.
	rotated := map[string]string{"notify.ntfy.token": credValue(), "nats.credentials-file seed": credValue(),
		"identity.kubernetes.token-file": leak.Generate(leak.KindJWT).Value()}
	writeCred(ntfyFile, rotated["notify.ntfy.token"])
	writeCred(natsFile, natsCreds(creds["nats.credentials-file jwt"], rotated["nats.credentials-file seed"]))
	writeCred(kubeFile, rotated["identity.kubernetes.token-file"])
	for what, v := range rotated {
		seeds = append(seeds, credSeed(what+" rotated", v))
	}
	if res := d.app.Config.Reload(ctx, "test"); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	for what, v := range rotated {
		eventually(t, what+" rotated in the redaction set", func() bool {
			red, err := d.redact(ctx, []byte("x "+v+" y"))
			// A detector placeholder (JWTs) does not count: the value
			// must be in the set itself.
			return err == nil && !strings.Contains(string(red.Text), v) && strings.Contains(string(red.Text), scrimCredPlaceholder)
		})
		send(what+" rotated", v)
	}

	checker := leak.NewChecker(seeds)
	for _, ex := range fake.Exchanges() {
		if f := checker.Check(ex.Capture); len(f) > 0 {
			t.Errorf("a credential reached the provider: %v", f)
		}
	}
	if f := checker.CheckText(0, h.logs.String()); len(f) > 0 {
		t.Errorf("a credential reached the log: %v", f)
	}
}
