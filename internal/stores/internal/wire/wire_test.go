// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/heliopsy/scrim/internal/secret"
)

func plain(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	if err := v.Expose(func(b []byte) error { s = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

var samples = []string{
	"",
	"plain",
	`quote" backslash\ slash/`,
	"newline\n cr\r tab\t bell\x07 nul\x00",
	"unicode é 日本 🔑   ",
	"<html>&'",
	strings.Repeat("x", 4096),
}

func TestUnquoteMatchesEncodingJSON(t *testing.T) {
	for _, s := range samples {
		q, _ := json.Marshal(s)
		got, err := Unquote(q)
		if err != nil {
			t.Fatalf("Unquote(%s): %v", q, err)
		}
		if string(got) != s {
			t.Errorf("Unquote(%s) = %q, want %q", q, got, s)
		}
	}
}

func TestUnquoteEscapes(t *testing.T) {
	cases := map[string]string{
		`"é日"`:               "é日",
		`"🔑"`:                "🔑",
		`"\ud83d"`:           string(utf8.RuneError),
		`"\ud83dx"`:          string(utf8.RuneError) + "x",
		`"\/\b\f\n\r\t\"\\"`: "/\b\f\n\r\t\"\\",
		`"ABC"`:              "ABC",
	}
	for in, want := range cases {
		got, err := Unquote([]byte(in))
		if err != nil {
			t.Fatalf("Unquote(%s): %v", in, err)
		}
		if string(got) != want {
			t.Errorf("Unquote(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestUnquoteRejectsMalformed(t *testing.T) {
	for _, in := range []string{``, `"`, `abc`, `"\x"`, `"\u12"`, `"\u12zz"`, `"tail\"`, "\"ctl\x01\""} {
		if _, err := Unquote([]byte(in)); err == nil {
			t.Errorf("Unquote(%q) succeeded", in)
		}
	}
}

func TestAppendQuotedRoundTrips(t *testing.T) {
	for _, s := range samples {
		q, err := AppendQuoted(nil, []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		var back string
		if err := json.Unmarshal(q, &back); err != nil {
			t.Fatalf("encoding/json rejects %s: %v", q, err)
		}
		if back != s {
			t.Errorf("round trip of %q gave %q", s, back)
		}
	}
	if _, err := AppendQuoted(nil, []byte{0xff, 0xfe}); err == nil {
		t.Errorf("invalid UTF-8 was accepted")
	}
}

func TestRawValue(t *testing.T) {
	cases := map[string]string{`"a\nb"`: "a\nb", `42`: "42", `true`: "true", ` {"k":1} `: `{"k":1}`}
	for in, want := range cases {
		v, err := Raw(in).Value()
		if err != nil {
			t.Fatalf("Raw(%s).Value: %v", in, err)
		}
		if got := plain(t, v); got != want {
			t.Errorf("Raw(%s).Value = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{`null`, ``, `{`} {
		if _, err := Raw(in).Value(); err == nil {
			t.Errorf("Raw(%q).Value succeeded", in)
		}
	}
}

func TestRawNeverPrints(t *testing.T) {
	r := Raw(`"s3cr3t-value"`)
	for _, s := range []string{fmt.Sprint(r), fmt.Sprintf("%v %s %q %x %+v", r, r, r, r, r), r.String()} {
		if strings.Contains(s, "s3cr3t") {
			t.Errorf("Raw printed its content: %s", s)
		}
	}
	type wrapper struct{ Data map[string]Raw }
	var w wrapper
	if err := json.Unmarshal([]byte(`{"Data":{"k":"s3cr3t-value"}}`), &w); err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("%+v", w); strings.Contains(s, "s3cr3t") {
		t.Errorf("decoded struct printed a value: %s", s)
	}
	w.Data["k"].Wipe()
	if strings.Contains(string(w.Data["k"]), "s3cr3t") {
		t.Errorf("Wipe left the value")
	}
}

func TestSafeDetail(t *testing.T) {
	v := secret.FromString("tok-123456789")
	if got := SafeDetail("bad value tok-123456789 given", v); strings.Contains(got, "tok-") {
		t.Errorf("SafeDetail kept the value: %q", got)
	}
	if got := SafeDetail("permission denied\n\tby policy", v); got != "permission denied  by policy" {
		t.Errorf("SafeDetail = %q", got)
	}
	long := strings.Repeat("é", 300)
	got := SafeDetail(long)
	if !utf8.ValidString(got) || len(got) > maxDetail+3 {
		t.Errorf("SafeDetail did not cap cleanly: %d bytes", len(got))
	}
}

func TestReadBodyLimit(t *testing.T) {
	if _, err := ReadBody(strings.NewReader(strings.Repeat("x", MaxBody+1))); err != ErrBodyTooLarge {
		t.Errorf("ReadBody over the limit: %v", err)
	}
	b, err := ReadBody(strings.NewReader("ok"))
	if err != nil || string(b) != "ok" {
		t.Errorf("ReadBody = %q, %v", b, err)
	}
}

func TestAppendValueAndBody(t *testing.T) {
	v := secret.FromString(`a"b`)
	out, err := AppendValue([]byte(`{"v":`), v)
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '}')
	b := NewBody(out)
	if b.Len() != len(`{"v":"a\"b"}`) {
		t.Errorf("body = %s", out)
	}
	b.Wipe()
	for _, c := range out {
		if c != 0 {
			t.Fatalf("Wipe left bytes")
		}
	}
}
