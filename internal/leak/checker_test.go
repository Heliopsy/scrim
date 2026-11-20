// SPDX-License-Identifier: AGPL-3.0-only

package leak

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func body(t *testing.T, s string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": s}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Spec scenario: a base64url form of a seeded secret inserted into an
// outbound fixture is reported.
func TestBase64URLInFixture(t *testing.T) {
	for _, s := range GenerateSet() {
		for off := range 3 {
			enc := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", off) + s.Value()))
			got := NewChecker([]Seed{s}).Check(Capture{Seq: 7, Body: body(t, "log line: token="+enc+" end")})
			if len(got) == 0 {
				t.Fatalf("%s at offset %d: not found", s, off)
			}
			f := got[0]
			if f.Request != 7 || f.Location != "body:messages[0].content" || !strings.Contains(strings.Join(f.Encodings, " "), "base64@") {
				t.Errorf("%s: finding %+v", s, f)
			}
		}
	}
}

func TestHeaderQueryAndGzipBody(t *testing.T) {
	s := Generate(KindGitHubToken)
	c := NewChecker([]Seed{s})
	if f := c.Check(Capture{Header: http.Header{"X-Trace": {s.Value()}}}); len(f) != 1 || f[0].Location != "header:X-Trace" {
		t.Errorf("header: %+v", f)
	}
	if f := c.Check(Capture{RawQuery: "a=1&t=" + strings.ReplaceAll(s.Value(), "_", "%5F")}); len(f) != 1 || f[0].Location != "query" {
		t.Errorf("query: %+v", f)
	}
}

func TestPartialThresholds(t *testing.T) {
	// 39 bytes, 8 of them a public prefix: a fragment counts from 20 bytes
	// (half, rounded up) with at least 8 outside the prefix.
	s := NewSeed("t", KindAPIKey, "sk-test-Q7v2LmZ9xK4pR1sT8wY3nB6cD0fG5hJ", "sk-test-")
	c := NewChecker([]Seed{s})
	v := s.Value()
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"whole", v, true},
		{"first 21 bytes", v[:21], true},
		{"last 20 bytes", v[len(v)-20:], true},
		{"last 16 bytes", v[len(v)-16:], false},
		{"prefix and 3 bytes", v[:11], false},
		{"6 secret bytes", v[8:14], false},
		{"prefix alone", "sk-test-placeholder", false},
	}
	for _, tc := range cases {
		if got := len(c.CheckText(1, "out: "+tc.text)) > 0; got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
	// A long value: one 64-byte line of a private key is a leak (cap 24).
	pk := Generate(KindPrivateKey)
	line := strings.Split(pk.Value(), "\n")[2]
	if len(NewChecker([]Seed{pk}).CheckText(1, line)) == 0 {
		t.Error("one private key line not reported")
	}
	if len(NewChecker([]Seed{pk}).CheckText(1, "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")) != 0 {
		t.Error("PEM armour alone reported as a leak")
	}
}

// The checker must stay quiet on traffic that holds no seed: placeholders,
// random base64 and hex blobs, prose and code.
func TestNoFalsePositives(t *testing.T) {
	seeds := GenerateSet()
	c := NewChecker(seeds)
	var b strings.Builder
	for i := range 200 {
		blob := make([]byte, 96)
		_, _ = rand.Read(blob)
		fmt.Fprintf(&b, "line %d ⟦scrim:leak-github-token:%s⟧ %s %s\n", i, hex.EncodeToString(blob[:8]), base64.StdEncoding.EncodeToString(blob), hex.EncodeToString(blob[:32]))
		b.WriteString("func main() { fmt.Println(\"hello, world\") } // alfa bravo charlie delta echo foxtrot\n")
		b.WriteString("-----BEGIN PRIVATE KEY-----\nAKIA sk-test- ghp_ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\n")
	}
	if got := c.Check(Capture{Body: body(t, b.String())}); len(got) != 0 {
		t.Fatalf("false positives: %+v", got)
	}
}

// Findings and seeds never print the value, whatever the formatter.
func TestNothingPrintsTheValue(t *testing.T) {
	s := Generate(KindPassword)
	f := NewChecker([]Seed{s}).CheckText(1, "pw="+s.Value())
	if len(f) == 0 {
		t.Fatal("not found")
	}
	var logs strings.Builder
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "seed", s, "finding", f)
	js, _ := json.Marshal(map[string]any{"seed": s, "findings": f})
	out := strings.Join([]string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v", s, f, s), logs.String(), string(js)}, "\n")
	for _, form := range []string{s.Value(), strings.ReplaceAll(s.Value(), `"`, `\"`)} {
		if strings.Contains(out, form) {
			t.Fatal("seed value printed")
		}
	}
	if !strings.Contains(out, s.Hash()) {
		t.Error("hash not printed")
	}
}

func TestSeedFileRoundTrip(t *testing.T) {
	p := t.TempDir() + "/seeds.json"
	in := GenerateSet()
	if err := WriteSeedFile(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadSeedFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d seeds", len(out))
	}
	for i := range in {
		if out[i].Value() != in[i].Value() || out[i].Name != in[i].Name {
			t.Errorf("seed %d differs", i)
		}
	}
}

func FuzzChecker(f *testing.F) {
	s := Generate(KindAPIKey)
	c := NewChecker([]Seed{s})
	f.Add([]byte(`{"a":"b"}`))
	f.Add([]byte("\x1f\x8b\x08 %41%42 \\x41 &#65; 0x41 alfa bravo"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = c.Check(Capture{Body: b})
		// Inserting the value anywhere is always found.
		mid := len(b) / 2
		withValue := append(append(append([]byte{}, b[:mid]...), []byte(" "+s.Value()+" ")...), b[mid:]...)
		if len(c.Check(Capture{Body: withValue})) == 0 {
			t.Fatal("inserted value not found")
		}
	})
}
