// SPDX-License-Identifier: AGPL-3.0-only

package projectscan

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func gen(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sk_" + hex.EncodeToString(b)
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func plain(f Finding) string {
	var s string
	_ = f.Value.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

// found maps "file#key" to the values found there.
func found(r *Result) map[string][]string {
	out := map[string][]string{}
	for _, f := range r.Findings {
		out[f.Name()] = append(out[f.Name()], plain(f))
	}
	return out
}

func TestScanFindsSecretsInProjectFiles(t *testing.T) {
	dir := t.TempDir()
	v := map[string]string{}
	for _, k := range []string{"openai", "stripe", "db", "tf", "app", "json", "npm", "url", "camel", "aws"} {
		v[k] = gen(t)
	}
	write(t, dir, ".env", "# comment\nexport OPENAI_API_KEY="+v["openai"]+"\nDEBUG=true\nPORT=8080\nEMPTY=\nREF={{scrim:bao://kv/a#b}}\nPH=SCRIM_STRIPE\nINTERP=${OTHER_TOKEN_VALUE}\n")
	write(t, dir, ".env.local", "STRIPE_SECRET_KEY=\""+v["stripe"]+"\" # live\n")
	write(t, dir, ".env.example", "OPENAI_API_KEY=sk-example-not-a-secret-123\n")
	write(t, dir, "infra/prod.tfvars", "db_password = \""+v["tf"]+"\"\nregion = \"eu-west-1\"\n")
	write(t, dir, "config/app.yaml", "database:\n  host: db.internal\n  password: "+v["db"]+"\n  password_file: /run/secrets/db\n")
	write(t, dir, "src/main/resources/application.properties", "spring.datasource.password="+v["app"]+"\n")
	write(t, dir, "appsettings.json", "{\n  \"ApiKey\": \""+v["json"]+"\",\n  \"Timeout\": 30\n}\n")
	write(t, dir, ".npmrc", "//registry.npmjs.org/:_authToken="+v["npm"]+"\n")
	write(t, dir, "compose.yaml", "services:\n  app:\n    environment:\n      DATABASE_URL: postgres://app:"+v["url"]+"@db:5432/app\n      clientSecret: "+v["camel"]+"\n")
	write(t, dir, "secrets.toml", "aws_access_key_id = \""+v["aws"]+"\"\n")
	// Not project files, or skipped directories.
	write(t, dir, "main.go", "const apiKey = \""+gen(t)+"\"\n")
	write(t, dir, "node_modules/x/.env", "TOKEN="+gen(t)+"\n")
	write(t, dir, ".git/config/x.yaml", "token: "+gen(t)+"\n")

	r, err := Scan(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Wipe()
	got := found(r)
	want := map[string]string{
		".env#OPENAI_API_KEY":           v["openai"],
		".env.local#STRIPE_SECRET_KEY":  v["stripe"],
		"infra/prod.tfvars#db_password": v["tf"],
		"config/app.yaml#password":      v["db"],
		"src/main/resources/application.properties#spring.datasource.password": v["app"],
		"appsettings.json#ApiKey":                 v["json"],
		".npmrc#//registry.npmjs.org/:_authToken": v["npm"],
		"compose.yaml#DATABASE_URL.password":      v["url"],
		"compose.yaml#clientSecret":               v["camel"],
		"secrets.toml#aws_access_key_id":          v["aws"],
	}
	for k, val := range want {
		if !slices.Contains(got[k], val) {
			t.Errorf("%s: not found (found %d values there)", k, len(got[k]))
		}
	}
	if len(got) != len(want) {
		names := make([]string, 0, len(got))
		for k := range got {
			names = append(names, k)
		}
		slices.Sort(names)
		t.Errorf("found %d names, want %d: %v", len(got), len(want), names)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.String(), plain(f)) {
			t.Errorf("String() of %s holds its value", f.Name())
		}
	}
}

func TestScanDecodesEscapedValues(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", `PRIVATE_KEY="-----BEGIN KEY-----\nabc123def456\n-----END KEY-----"`+"\n")
	r, err := Scan(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Wipe()
	got := found(r)[".env#PRIVATE_KEY"]
	if !slices.Contains(got, `-----BEGIN KEY-----\nabc123def456\n-----END KEY-----`) ||
		!slices.Contains(got, "-----BEGIN KEY-----\nabc123def456\n-----END KEY-----") {
		t.Fatalf("want the raw and the decoded form, got %d values", len(got))
	}
	if n := len(r.Movable()); n != 1 {
		t.Errorf("%d movable findings, want 1", n)
	}
}

func TestSameDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_TOKEN="+gen(t)+"\n")
	a, _ := Scan(dir, Options{})
	b, _ := Scan(dir, Options{})
	if !a.Same(b) {
		t.Fatal("two scans of the same files differ")
	}
	write(t, dir, ".env", "API_TOKEN="+gen(t)+"\n")
	c, _ := Scan(dir, Options{})
	if a.Same(c) {
		t.Fatal("a changed value is not detected")
	}
	write(t, dir, "sub/.env", "OTHER_TOKEN="+gen(t)+"\n")
	d, _ := Scan(dir, Options{})
	if c.Same(d) {
		t.Fatal("a new file is not detected")
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	key := gen(t)
	write(t, dir, ".env", "A=1\nOPENAI_API_KEY=\""+key+"\" # prod\nB=2\n")
	if err := os.Chmod(filepath.Join(dir, ".env"), 0o640); err != nil {
		t.Fatal(err)
	}
	r, err := Scan(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Wipe()
	m := r.Movable()
	if len(m) != 1 {
		t.Fatalf("%d findings, want 1", len(m))
	}
	if err := Replace(dir, m[0], "{{scrim:bao://kv/agents/openai#value}}"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if want := "A=1\nOPENAI_API_KEY=\"{{scrim:bao://kv/agents/openai#value}}\" # prod\nB=2\n"; string(b) != want {
		t.Fatalf("file is\n%s\nwant\n%s", b, want)
	}
	st, _ := os.Stat(filepath.Join(dir, ".env"))
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o640 { // Windows keeps no mode bits
		t.Errorf("mode %v, want 0640", st.Mode().Perm())
	}
	// A second replace finds the value gone and refuses.
	if err := Replace(dir, m[0], "x"); !errors.Is(err, ErrChanged) {
		t.Fatalf("replace of a changed file: %v, want ErrChanged", err)
	}
	if r2, _ := Scan(dir, Options{}); len(r2.Findings) != 0 {
		t.Errorf("the reference is found as a secret again")
	}
}

func TestSecretKey(t *testing.T) {
	for k, want := range map[string]bool{
		"GITHUB_TOKEN": true, "apiKey": true, "db.password": true, "AWS_ACCESS_KEY_ID": true, "client-secret": true,
		"SENTRY_DSN": true, "PASSWORD_FILE": false, "TOKEN_URL": false, "KEY_PREFIX": false, "MONKEY": false,
		"SECRET_NAME": false, "author": false,
	} {
		if got := SecretKey(k); got != want {
			t.Errorf("SecretKey(%q) = %v, want %v", k, got, want)
		}
	}
}
