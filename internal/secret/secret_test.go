// SPDX-License-Identifier: AGPL-3.0-only

package secret_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
)

// generated returns a random value and its plain form, so no fixture holds a
// literal secret.
func generated(t *testing.T) (secret.Value, string) {
	t.Helper()
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	plain := "tok_" + hex.EncodeToString(raw)
	return secret.FromString(plain), plain
}

func assertNoLeak(t *testing.T, out, plain string) {
	t.Helper()
	for _, enc := range []string{
		plain,
		hex.EncodeToString([]byte(plain)),
		base64.StdEncoding.EncodeToString([]byte(plain)),
		plain[4:12],
	} {
		if strings.Contains(out, enc) {
			t.Fatalf("output leaks the value (or an encoding of it): %q", out)
		}
	}
	if !strings.Contains(out, secret.Marker) {
		t.Fatalf("output lacks the redaction marker: %q", out)
	}
}

func TestFmtVerbs(t *testing.T) {
	v, plain := generated(t)
	type wrapper struct {
		Name  string
		Token secret.Value
	}
	w := wrapper{Name: "github", Token: v}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10.3s"} {
		t.Run(format, func(t *testing.T) {
			assertNoLeak(t, fmt.Sprintf(format, v), plain)
			assertNoLeak(t, fmt.Sprintf(format, w), plain)
			assertNoLeak(t, fmt.Sprintf(format, &w), plain)
			assertNoLeak(t, fmt.Sprintf(format, []secret.Value{v}), plain)
		})
	}
	assertNoLeak(t, fmt.Sprint(v), plain)
	assertNoLeak(t, fmt.Sprintln(map[string]secret.Value{"k": v}), plain)
}

func TestErrorsWrapping(t *testing.T) {
	v, plain := generated(t)
	base := errors.New("store rejected write")
	err := fmt.Errorf("write %v: %w", v, base)
	err = fmt.Errorf("outer: %w", err)
	assertNoLeak(t, err.Error(), plain)
	if !errors.Is(err, base) {
		t.Fatal("wrapping lost the cause")
	}
}

func TestSlog(t *testing.T) {
	v, plain := generated(t)
	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(h(&buf))
			log.Info("loaded", "value", v, slog.Any("any", v), slog.Group("g", "inner", v))
			log.Info("struct", "s", struct{ V secret.Value }{v})
			assertNoLeak(t, buf.String(), plain)
		})
	}
}

func TestEncoders(t *testing.T) {
	v, plain := generated(t)
	j, err := json.Marshal(map[string]any{"v": v, "p": &v, "list": []secret.Value{v}})
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, string(j), plain)

	k, err := json.Marshal(map[secret.Value]int{v: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, string(k), plain)

	var g bytes.Buffer
	if err := gob.NewEncoder(&g).Encode(struct{ V secret.Value }{v}); err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, g.String(), plain)

	var back secret.Value
	if err := json.Unmarshal([]byte(`"x"`), &back); err == nil {
		t.Fatal("decoding a Value from JSON must fail")
	}
}

func TestExposeAndWipe(t *testing.T) {
	v, plain := generated(t)
	cp := v
	var got string
	if err := v.Expose(func(b []byte) error { got = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatal("Expose returned the wrong bytes")
	}
	if v.Len() != len(plain) {
		t.Fatalf("Len = %d, want %d", v.Len(), len(plain))
	}

	var held []byte
	_ = v.Expose(func(b []byte) error { held = b; return nil })
	cp.Wipe()
	if !v.Wiped() || !v.IsZero() {
		t.Fatal("wiping a copy must wipe the shared buffer")
	}
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("Wipe did not zero the backing bytes")
	}
	if err := v.Expose(func([]byte) error { return nil }); !errors.Is(err, secret.ErrWiped) {
		t.Fatalf("Expose after Wipe = %v, want ErrWiped", err)
	}
	v.Wipe() // idempotent
	var zero secret.Value
	zero.Wipe()
	if zero.Len() != 0 || fmt.Sprint(zero) != secret.Marker {
		t.Fatal("zero Value must be empty and still redact")
	}
}

func TestAdoptAndEqual(t *testing.T) {
	b := []byte("generated-" + hex.EncodeToString([]byte{1, 2, 3}))
	keep := append([]byte(nil), b...)
	v := secret.Adopt(b)
	if !v.Equal(secret.New(keep)) || !v.Equal(v) { //nolint:gocritic // comparing a value with itself is the case under test
		t.Fatal("Equal failed for equal content")
	}
	if v.Equal(secret.FromString("other")) {
		t.Fatal("Equal true for different content")
	}
	v.Wipe()
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("Adopt must wipe the adopted slice")
	}
}

// An unexported field is printed by reflection without calling its methods.
// The value sits behind a pointer, so fmt shows an address, never the bytes.
func TestUnexportedField(t *testing.T) {
	v, plain := generated(t)
	type hidden struct{ token secret.Value }
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		out := fmt.Sprintf(format, hidden{v})
		if strings.Contains(out, plain) || strings.Contains(out, hex.EncodeToString([]byte(plain))) {
			t.Fatalf("%s leaks through an unexported field: %q", format, out)
		}
	}
}
