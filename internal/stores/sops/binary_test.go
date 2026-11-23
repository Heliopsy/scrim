// SPDX-License-Identifier: AGPL-3.0-only

package sops

// Cross-checks against the real sops binary: files sops encrypts decrypt
// here to the same fields, and files this package's test encryptor writes
// decrypt with sops. Skipped when sops is not on PATH, unless
// SCRIM_TEST_SOPS=1 (CI) turns that into a failure.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

type sopsBin struct {
	path, dir, keyFile string
}

func findSops(t *testing.T, id *age.X25519Identity) sopsBin {
	t.Helper()
	p, err := exec.LookPath("sops")
	if err != nil {
		if os.Getenv("SCRIM_TEST_SOPS") == "1" {
			t.Fatalf("sops not found and SCRIM_TEST_SOPS=1: %v", err)
		}
		t.Skip("sops binary not on PATH; set SCRIM_TEST_SOPS=1 to require it")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "test-only-age-key.txt")
	if err := os.WriteFile(key, []byte("# test-only throwaway key\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An empty config keeps sops from looking for .sops.yaml further up.
	if err := os.WriteFile(filepath.Join(dir, "empty.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return sopsBin{path: p, dir: dir, keyFile: key}
}

// run runs sops with a clean environment: its own HOME, no ambient keys.
func (s sopsBin) run(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), s.path, append([]string{"--disable-version-check"}, args...)...)
	cmd.Dir = s.dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + s.dir, "XDG_CONFIG_HOME=" + s.dir, "SOPS_AGE_KEY_FILE=" + s.keyFile}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("sops %s: %v\n%s", args[0], err, errb.String())
	}
	return out.Bytes()
}

func TestSopsBinaryFilesDecrypt(t *testing.T) {
	id := identity(t)
	s := findSops(t, id)
	pw, tok0, tok1, odd, uni, multi, env1, env2, ini1, ini2, ini3, js1, js2, js3 :=
		gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t), gen(t)
	cases := []struct {
		name, file, plain string
		config            string
		want              map[string]string
	}{
		{
			name: "yaml", file: "app.yaml",
			plain: "# a comment that sops encrypts\ndb:\n  password: " + pw + "\n  port: 5432\n  ratio: 1.50\n  on: true\n  off: false\n" +
				"  empty: \"\"\n  nothing: null\n  host_unencrypted: localhost\n  when: 2001-12-14T21:59:43Z\n  day_unencrypted: 2001-12-14\n" +
				"list:\n  - " + tok0 + "  # trailing comment\n  - k: " + tok1 + "\n    n: 7\n\"a/b~c\": " + odd + "\nunicode: \"é 日本 " + uni + "\"\n" +
				"multi: |\n  line one\n  line two " + multi + "\n",
			want: map[string]string{
				"db/password": pw, "db/port": "5432", "db/ratio": "1.5", "db/on": "true", "db/off": "false",
				"db/when": "2001-12-14T21:59:43Z", "list/0": tok0, "list/1/k": tok1, "list/1/n": "7",
				"a~1b~0c": odd, "unicode": "é 日本 " + uni, "multi": "line one\nline two " + multi + "\n",
			},
		},
		{
			name: "yaml mac-only encrypted-regex", file: "rules.yaml",
			config: "creation_rules:\n  - age: RECIPIENT\n    mac_only_encrypted: true\n    encrypted_regex: '^(password|token)$'\n",
			plain:  "db:\n  password: " + pw + "\n  user: admin\n  port: 5432\ntoken: " + tok0 + "\nplain: text\n",
			want:   map[string]string{"db/password": pw, "token": tok0},
		},
		{
			name: "json", file: "app.json",
			plain: `{"a":{"b":"` + js1 + `","n":1,"f":2.5,"t":true,"z":null,"arr":[1,"` + js2 + `"]},"top":"` + js3 + `","x_unencrypted":"plain","big":12345678901234567890}`,
			want:  map[string]string{"a/b": js1, "a/n": "1", "a/f": "2.5", "a/t": "true", "a/arr/0": "1", "a/arr/1": js2, "top": js3, "big": "12345678901234567000"},
		},
		{
			name: "dotenv", file: "app.env",
			plain: "API_TOKEN=" + env1 + "\n# comment\nMULTI=one\\ntwo " + env2 + "\nSPACES=two words\nNAME_unencrypted=plain\n",
			want:  map[string]string{"API_TOKEN": env1, "MULTI": "one\ntwo " + env2, "SPACES": "two words"},
		},
		{
			name: "ini", file: "app.ini",
			plain: "top = " + ini1 + "\n[database]\npassword = " + ini2 + "\nport = 5432\nuser_unencrypted = admin\n; comment\n[other]\nkey: " + ini3 + "\n",
			want:  map[string]string{"DEFAULT/top": ini1, "database/password": ini2, "database/port": "5432", "other/key": ini3},
		},
		{
			name: "binary", file: "cert.bin",
			plain: "-----BEGIN TEST-ONLY-----\n" + multi + "\n\x00\x01\xff",
			want:  map[string]string{"data": "-----BEGIN TEST-ONLY-----\n" + multi + "\n\x00\x01\xff"},
		},
	}
	a, root := newAdapter(t, Config{}, id)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := filepath.Join(s.dir, c.file)
			if err := os.WriteFile(src, []byte(c.plain), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--config", filepath.Join(s.dir, "empty.yaml"), "encrypt", "--age", id.Recipient().String(), src}
			if c.config != "" {
				cfg := filepath.Join(s.dir, "rules-config.yaml")
				if err := os.WriteFile(cfg, []byte(strings.ReplaceAll(c.config, "RECIPIENT", id.Recipient().String())), 0o600); err != nil {
					t.Fatal(err)
				}
				args = []string{"--config", cfg, "encrypt", src}
			}
			enc := s.run(t, args...)
			for _, w := range c.want {
				if len(w) > 8 && bytes.Contains(enc, []byte(w)) {
					t.Fatal("sops left a value in clear")
				}
			}
			put(t, root, c.file, enc)
			equalFields(t, c.name, readAll(t, a, c.file), c.want)

			// Any edit sops did not make is refused.
			tampered := bytes.Replace(enc, []byte("lastmodified"), []byte("lastmodifiee"), 1)
			put(t, root, "tampered-"+c.file, tampered)
			if s, err := a.Read(t.Context(), ref("tampered-"+c.file)); err == nil {
				s.Wipe()
				t.Error("a file with a renamed lastmodified was read")
			}
		})
	}
}

func TestSopsBinaryDecryptsOurFiles(t *testing.T) {
	id := identity(t)
	s := findSops(t, id)
	for _, f := range []Format{FormatYAML, FormatJSON, FormatDotenv, FormatINI} {
		for _, o := range []encOptions{{}, {rule: "encrypted_regex", ruleValue: "^(password|token)$", macOnly: true}} {
			t.Run(string(f)+" "+o.rule, func(t *testing.T) {
				o.recipients = []*age.X25519Recipient{id.Recipient()}
				var doc *node
				values := []string{gen(t), gen(t)}
				switch f {
				case FormatYAML, FormatJSON:
					doc, _ = nested(t)
					doc.set("password", &node{kind: kindLeaf, str: true, text: values[0]})
					doc.set("token", &node{kind: kindLeaf, str: true, text: values[1]})
				case FormatDotenv:
					doc = flatDoc(map[string]string{"password": values[0], "token": values[1]})
				case FormatINI:
					doc = newMap()
					doc.set("DEFAULT", newMap())
					doc.set("app", flatDoc(map[string]string{"password": values[0], "token": values[1]}))
				}
				name := "ours." + map[Format]string{FormatYAML: "yaml", FormatJSON: "json", FormatDotenv: "env", FormatINI: "ini"}[f]
				p := filepath.Join(s.dir, name)
				if err := os.WriteFile(p, encryptFile(t, f, doc, o), 0o600); err != nil {
					t.Fatal(err)
				}
				out := s.run(t, "--config", filepath.Join(s.dir, "empty.yaml"), "decrypt", p)
				for _, v := range values {
					if !bytes.Contains(out, []byte(v)) {
						t.Errorf("sops output lacks a generated value")
					}
				}
			})
		}
	}
}
