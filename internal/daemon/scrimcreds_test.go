// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// sourceValues collects what src puts in the redaction set.
func sourceValues(t *testing.T, src ValueSource) []string {
	t.Helper()
	var out []string
	src.EachValue(func(s refresh.Source, v secret.Value) {
		if !s.Ref.IsZero() || s.Retained || s.Pending {
			t.Errorf("scrim's own credential carries a reference or a state: %+v", s)
		}
		_ = v.Expose(func(b []byte) error { out = append(out, string(b)); return nil })
	})
	return out
}

// TestScrimCredentialsSource: a store credential (which the e2e test does
// not configure, since the store would have to answer) is in the set
// alongside the settings; database passwords are left to their own source.
// Every declared collection secret field reaches Config.EachSecret the
// same way, so the notifier plugin fields the e2e test cannot all set
// (the example plugin accepts a token only) take this path too.
func TestScrimCredentialsSource(t *testing.T) {
	dir := t.TempDir()
	vals := map[string]string{}
	var env []string
	ref := func(name string) string {
		v := leak.Generate(leak.KindDBPassword).Value()
		vals[name] = v
		env = append(env, "SCRIMCRED_"+name+"="+v)
		return "env:SCRIMCRED_" + name
	}
	doc := "apiVersion: " + config.APIVersion + "\nkind: Config\n" +
		"notify:\n  ntfy:\n    token: " + ref("NT") + "\n" +
		"stores:\n  bao:\n    kind: openbao\n    address: https://127.0.0.1:1\n    token: " + ref("ST") + "\n" +
		"databases:\n  app:\n    kind: postgres\n    address: 127.0.0.1:1\n    user: app\n    password: " + ref("DB") + "\n"
	path := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{path}, SystemDir: dir,
		Environ: append([]string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_STATE_HOME=" + dir}, env...)})
	if err != nil {
		t.Fatal(err)
	}
	src := newScrimCredentials(func() *config.Config { return cfg })
	defer src.close()
	got := sourceValues(t, src)
	for _, name := range []string{"NT", "ST"} {
		if !slices.Contains(got, vals[name]) {
			t.Errorf("SCRIMCRED_%s is not in the set", name)
		}
	}
	if slices.Contains(got, vals["DB"]) {
		t.Error("a database password is in the set twice (databasePasswords holds it)")
	}
}

func TestDSNPasswords(t *testing.T) {
	for _, c := range []struct {
		name, dsn string
		want      []string
	}{
		{"url", "postgres://scrim:pw-one@db:5432/scrim?sslmode=verify-full", []string{"pw-one"}},
		{"url encoded", "postgresql://scrim:p%40ss%2Fword@db/scrim", []string{"p%40ss%2Fword", "p@ss/word"}},
		{"url no password", "postgres://scrim@db/scrim", nil},
		{"url no user", "postgres://db/scrim", nil},
		{"keyword", "host=db user=scrim password=pw-two dbname=scrim", []string{"pw-two"}},
		{"keyword quoted", `host=db password = 'a b\'c' user=scrim`, []string{`a b\'c`, "a b'c"}},
		{"keyword none", "host=db user=scrim", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, p := range dsnPasswords([]byte(c.dsn)) {
				got = append(got, string(p))
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("dsnPasswords = %q, want %q", got, c.want)
			}
		})
	}
}

func TestPEMBundleParts(t *testing.T) {
	a, b := leak.Generate(leak.KindPrivateKey).Value(), leak.Generate(leak.KindPrivateKey).Value()
	parts := derivedParts("identity.issuer.signing-keys", secret.FromString(a+"\n"+b+"\n"))
	var got []string
	for _, p := range parts {
		_ = p.Expose(func(x []byte) error { got = append(got, string(x)); return nil })
		p.Wipe()
	}
	if !slices.Equal(got, []string{a, b}) {
		t.Errorf("bundle parts: got %d, want the two keys", len(got))
	}
	if n := len(derivedParts("tool-proxy.ca.key", secret.FromString(a))); n != 0 {
		t.Errorf("a single key yields %d extra parts", n)
	}
}

// TestCredentialFileRotation: a rewritten credential file replaces the
// value, the previous one stays until the next change, and changed()
// reports the rewrite so the daemon rebuilds the snapshot.
func TestCredentialFileRotation(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	write := func(v string, mod time.Time) {
		t.Helper()
		if err := os.WriteFile(tok, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(tok, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	gen := func() string { return leak.Generate(leak.KindJWT).Value() }
	v1, v2, v3 := gen(), gen(), gen()
	now := time.Now()
	write(v1, now.Add(-3*time.Minute))
	path := filepath.Join(dir, "scrim.yaml")
	doc := "apiVersion: " + config.APIVersion + "\nkind: Config\nidentity:\n  kubernetes:\n    enabled: true\n    token-file: " + tok + "\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{path}, SystemDir: dir,
		Environ: []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_STATE_HOME=" + dir}})
	if err != nil {
		t.Fatal(err)
	}
	src := newScrimCredentials(func() *config.Config { return cfg })
	defer src.close()
	if !src.changed() {
		t.Error("an unread file is not reported as changed")
	}
	if got := sourceValues(t, src); !slices.Equal(got, []string{v1}) {
		t.Fatalf("first read: %d values", len(got))
	}
	if src.changed() {
		t.Error("an unchanged file is reported as changed")
	}
	write(v2, now.Add(-2*time.Minute))
	if !src.changed() {
		t.Error("a rewritten file is not reported as changed")
	}
	if got := sourceValues(t, src); !slices.Equal(got, []string{v2, v1}) {
		t.Fatalf("after rotation: %d values", len(got))
	}
	write(v3, now.Add(-time.Minute))
	if got := sourceValues(t, src); !slices.Equal(got, []string{v3, v2}) {
		t.Fatalf("after a second rotation: %d values", len(got))
	}
}
