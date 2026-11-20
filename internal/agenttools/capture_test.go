// SPDX-License-Identifier: AGPL-3.0-only

package agenttools_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	at "github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/secret"
)

func exposed(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	if err := v.Expose(func(b []byte) error { s = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

const captureJSON = `{"id": 7, "token": "cap-test-3c2b1a09f8e7", "data": [{"key": "k0"}, {"key": "k1", "n": 42}], "odd key": "v", "obj": {}}`

func TestExtract(t *testing.T) {
	for _, tc := range []struct {
		x    at.Extraction
		out  string
		want string
	}{
		{at.Extraction{}, "  whole-test-value \n", "whole-test-value"},
		{at.Extraction{JSONPath: ".token"}, captureJSON, "cap-test-3c2b1a09f8e7"},
		{at.Extraction{JSONPath: "token"}, captureJSON, "cap-test-3c2b1a09f8e7"},
		{at.Extraction{JSONPath: ".data[1].key"}, captureJSON, "k1"},
		{at.Extraction{JSONPath: ".data[1].n"}, captureJSON, "42"},
		{at.Extraction{JSONPath: `["odd key"]`}, captureJSON, "v"},
		{at.Extraction{JSONPath: "."}, `"bare-string"`, "bare-string"},
		{at.Extraction{Pattern: `token=(\S+)`}, "id=1\ntoken=pat-test-value\n", "pat-test-value"},
		{at.Extraction{Pattern: `ghp_[A-Za-z0-9]+`}, "created ghp_TESTabc123 ok", "ghp_TESTabc123"},
	} {
		v, err := tc.x.Extract([]byte(tc.out))
		if err != nil {
			t.Fatalf("%+v: %v", tc.x, err)
		}
		if got := exposed(t, v); got != tc.want {
			t.Errorf("%+v: got %d bytes, want %q", tc.x, len(got), tc.want)
		}
	}
}

// TestExtractErrorsNeverQuoteTheOutput covers "Extraction finds nothing".
func TestExtractErrorsNeverQuoteTheOutput(t *testing.T) {
	for _, tc := range []struct {
		x   at.Extraction
		out string
	}{
		{at.Extraction{JSONPath: ".missing"}, captureJSON},
		{at.Extraction{JSONPath: ".data[5]"}, captureJSON},
		{at.Extraction{JSONPath: ".token.deeper"}, captureJSON},
		{at.Extraction{JSONPath: ".obj"}, captureJSON},
		{at.Extraction{JSONPath: ".data.key"}, captureJSON},
		{at.Extraction{JSONPath: ".token"}, "not json cap-test-3c2b1a09f8e7"},
		{at.Extraction{Pattern: `nomatch=(\d+)`}, captureJSON},
		{at.Extraction{}, "   \n"},
		{at.Extraction{Pattern: `token": "()`}, captureJSON},
	} {
		_, err := tc.x.Extract([]byte(tc.out))
		if code(t, err) != at.CodeInvalid {
			t.Fatalf("%+v: %v", tc.x, err)
		}
		agenttoolstest.AssertNoValues(t, "extract error", []byte(err.Error()), []byte("cap-test-3c2b1a09f8e7"), []byte("k1"))
	}
	for _, bad := range []at.Extraction{
		{JSONPath: ".a", Pattern: "b"}, {JSONPath: ".."}, {JSONPath: ".a["}, {JSONPath: ".a[-1]"}, {JSONPath: `.a["x]`},
		{Pattern: "("}, {Pattern: strings.Repeat("a", 1025)}, {JSONPath: "a b"},
	} {
		if err := bad.Check(); code(t, err) != at.CodeInvalid {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestRunCaptureWithholdsOutput(t *testing.T) {
	sh := func(script string) []string { return []string{"sh", "-c", script} }
	v, exit, err := at.RunCapture(ctx, at.CaptureInput{Ref: "bao://kv/agents/t", Command: sh(`printf '%s' '` + captureJSON + `'`), JSONPath: ".token"})
	if err != nil || exit != 0 {
		t.Fatalf("exit %d: %v", exit, err)
	}
	if exposed(t, v) != "cap-test-3c2b1a09f8e7" {
		t.Fatal("wrong value captured")
	}

	_, exit, err = at.RunCapture(ctx, at.CaptureInput{Ref: "bao://kv/agents/t",
		Command: sh(`echo cap-test-3c2b1a09f8e7; echo cap-test-3c2b1a09f8e7 >&2; exit 3`)})
	if exit != 3 || code(t, err) != at.CodeInvalid || !strings.Contains(err.Error(), "status 3") {
		t.Fatalf("exit %d: %v", exit, err)
	}
	agenttoolstest.AssertNoValues(t, "failed command error", []byte(err.Error()), []byte("cap-test-3c2b1a09f8e7"))

	_, _, err = at.RunCapture(ctx, at.CaptureInput{Ref: "bao://kv/agents/t", Command: sh(`echo cap-test-3c2b1a09f8e7`), JSONPath: ".token"})
	agenttoolstest.AssertNoValues(t, "non-JSON error", []byte(err.Error()), []byte("cap-test-3c2b1a09f8e7"))

	_, _, err = at.RunCapture(ctx, at.CaptureInput{Ref: "bao://kv/agents/t", Command: sh(`sleep 5`), TimeoutSeconds: 1})
	if code(t, err) != at.CodeInvalid || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("timeout: %v", err)
	}
	_, _, err = at.RunCapture(ctx, at.CaptureInput{Ref: "bao://kv/agents/t", Command: []string{"scrim-no-such-command-xyz"}})
	if code(t, err) != at.CodeInvalid || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing command: %v", err)
	}
	_, _, err = at.RunCapture(ctx, at.CaptureInput{Ref: "bao://kv/agents/t", Command: sh(`head -c 1100000 /dev/zero | tr '\0' a`)})
	if code(t, err) != at.CodeInvalid || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("huge output: %v", err)
	}
	for _, bad := range []at.CaptureInput{
		{Ref: "bao://kv/agents/t"},
		{Ref: "bao://kv/agents/t", Command: []string{""}},
		{Ref: "", Command: []string{"true"}},
		{Ref: "bao://kv/agents/t", Command: []string{"true"}, TimeoutSeconds: 601},
		{Ref: "bao://kv/agents/t", Command: []string{"true"}, JSONPath: ".a", Pattern: "b"},
	} {
		if err := at.CheckCapture(bad); code(t, err) != at.CodeInvalid {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestReadValue(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		keep     bool
	}{
		{"value-1\n", "value-1", false},
		{"value-2\r\n", "value-2", false},
		{"value-3", "value-3", false},
		{"value-4\n\n", "value-4\n", false},
		{"value-5\n", "value-5\n", true},
		{"multi\nline\n", "multi\nline", false},
	} {
		v, err := at.ReadValue(iotest.OneByteReader(strings.NewReader(tc.in)), tc.keep)
		if err != nil {
			t.Fatal(err)
		}
		if got := exposed(t, v); got != tc.want {
			t.Errorf("ReadValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	big := bytes.Repeat([]byte("v"), at.MaxValueSize+1)
	if _, err := at.ReadValue(bytes.NewReader(big), false); code(t, err) != at.CodeInvalid {
		t.Fatalf("too big: %v", err)
	}
	exact := append(bytes.Repeat([]byte("v"), at.MaxValueSize), '\n')
	if v, err := at.ReadValue(bytes.NewReader(exact), false); err != nil || v.Len() != at.MaxValueSize {
		t.Fatalf("max size: %v", err)
	}
	for _, empty := range []string{"", "\n", "\r\n"} {
		if _, err := at.ReadValue(strings.NewReader(empty), false); code(t, err) != at.CodeInvalid {
			t.Errorf("empty %q accepted", empty)
		}
	}
	_, err := at.ReadValue(iotest.ErrReader(errors.New("boom secret-ish")), false)
	if code(t, err) != at.CodeInvalid || strings.Contains(err.Error(), "boom") {
		t.Fatalf("read error: %v", err)
	}
}
