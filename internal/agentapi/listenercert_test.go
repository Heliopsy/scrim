// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/testing/certtest"
)

func TestListenerCertSource(t *testing.T) {
	ca := certtest.NewCA(t, "operator")
	server := ca.Issue(t, certtest.Leaf{CN: "scrim.example.test", ServerOnly: true})
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certFile := write("tls.crt", server.CertPEM)
	keyFile := write("tls.key", server.KeyPEM)
	caFile := write("agents.pem", ca.PEM)
	load := func(env ...string) *config.Config {
		t.Helper()
		cfg, err := config.Load(config.Default, config.EnvLayer(env))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	on := []string{"SCRIM_IDENTITY_CLIENT_CERTIFICATES_ENABLED=true", "SCRIM_IDENTITY_CLIENT_CERTIFICATES_CA=file:" + caFile}
	cert := "SCRIM_IDENTITY_CLIENT_CERTIFICATES_LISTENER_CERT_FILE=" + certFile
	key := "SCRIM_IDENTITY_CLIENT_CERTIFICATES_LISTENER_KEY=file:" + keyFile

	src, err := ListenerCertSource(context.Background(), load(on...))
	if err != nil || src != nil {
		t.Fatalf("unset: %v %v", src, err)
	}
	src, err = ListenerCertSource(context.Background(), load(append(on, cert, key)...))
	if err != nil || src.Current().Leaf.Subject.CommonName != "scrim.example.test" {
		t.Fatalf("set: %v %v", src, err)
	}

	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"certificate without key", append(on, cert), "needs identity.client-certificates.listener-key"},
		{"key without certificate", append(on, key), "needs identity.client-certificates.listener-cert-file"},
		{"without client certificates", []string{cert, key}, "needs identity.client-certificates.enabled"},
		{"missing file", append(on, "SCRIM_IDENTITY_CLIENT_CERTIFICATES_LISTENER_CERT_FILE="+filepath.Join(dir, "none"), key), "listener-cert-file"},
		{"wrong key", append(on, cert, "SCRIM_IDENTITY_CLIENT_CERTIFICATES_LISTENER_KEY=file:"+write("other.key", ca.KeyPEM(t))), "does not match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ListenerCertSource(context.Background(), load(c.env...))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one containing %q", err, c.want)
			}
		})
	}
}
