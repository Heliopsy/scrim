// SPDX-License-Identifier: AGPL-3.0-only

package options

import (
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

func TestNestedDottedAndStringForms(t *testing.T) {
	d := New("s", map[string]any{
		"address":     "http://x",
		"watch":       map[string]any{"interval": "5s"},
		"tls.ca-file": "/ca.pem",
		"enabled":     "true",
		"count":       float64(3),
		"size":        "2MiB",
		"list":        []any{"a", "b"},
		"csv":         "a, b,,c",
	})
	if d.String("address", "") != "http://x" || d.Duration("watch.interval", 0) != 5*time.Second ||
		d.String("tls.ca-file", "") != "/ca.pem" || !d.Bool("enabled", false) || d.Int("count", 0) != 3 ||
		d.Size("size", 0) != 2<<20 || len(d.Strings("list")) != 2 || len(d.Strings("csv")) != 3 {
		t.Fatal("decoded values wrong")
	}
	if d.String("missing", "def") != "def" {
		t.Error("default not applied")
	}
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownKeysAndTypeErrors(t *testing.T) {
	d := New("bao", map[string]any{"adress": "x", "timeout": "soon", "auth": map[string]any{"methd": "token"}})
	d.String("address", "")
	d.Duration("timeout", 0)
	d.String("auth.method", "")
	err := d.Finish()
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"unknown option adress (did you mean address?)", "unknown option auth.methd (did you mean auth.method?)", "option timeout must be a duration"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "soon") {
		t.Error("error quotes a value")
	}
}

func TestDuplicateAcrossForms(t *testing.T) {
	d := New("s", map[string]any{"watch": map[string]any{"interval": "1s"}, "watch.interval": "2s"})
	d.Duration("watch.interval", 0)
	if err := d.Finish(); err == nil || !strings.Contains(err.Error(), "set twice") {
		t.Errorf("duplicate: %v", err)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"10": 10, "1KiB": 1024, "1 MiB": 1 << 20, "2MB": 2e6, "3B": 3} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "x", "-1", "1TB"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) accepted", in)
		}
	}
}

func TestSecretRef(t *testing.T) {
	d := New("s", map[string]any{
		"a": config.SecretRef("env:A"),
		"b": "file:/run/b",
		"c": 3,
	})
	if got := d.SecretRef("a"); got != "env:A" {
		t.Errorf("a = %q", got)
	}
	if got := d.SecretRef("b"); got != "file:/run/b" {
		t.Errorf("b = %q", got)
	}
	if got := d.SecretRef("unset"); got != "" {
		t.Errorf("unset = %q", got)
	}
	_ = d.SecretRef("c")
	if err := d.Finish(); err == nil || !strings.Contains(err.Error(), "option c must be a secret reference") {
		t.Errorf("Finish = %v", err)
	}
}
