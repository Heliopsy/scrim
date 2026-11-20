// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
)

// testValue is generated test data, not a real secret.
const testValue = "sk-test-0123456789abcdef/+?&=\"q\""

func TestValueScrubberEncodings(t *testing.T) {
	vs := NewValueScrubber(secret.FromString(testValue))
	defer vs.Wipe()

	inputs := map[string]string{
		"raw":      testValue,
		"json":     `sk-test-0123456789abcdef/+?&=\"q\"`,
		"json-raw": `sk-test-0123456789abcdef/+?&=\"q\"`,
		"query":    url.QueryEscape(testValue),
		"path":     url.PathEscape(testValue),
		"hex":      hex.EncodeToString([]byte(testValue)),
		"HEX":      strings.ToUpper(hex.EncodeToString([]byte(testValue))),
		"b64":      base64.StdEncoding.EncodeToString([]byte(testValue)),
		"b64url":   base64.RawURLEncoding.EncodeToString([]byte(testValue)),
	}
	// A value embedded at every alignment inside a longer base64 blob.
	for _, p := range []string{"", "x", "xy"} {
		inputs["b64 after "+p] = base64.StdEncoding.EncodeToString([]byte(p + testValue + "tail"))
	}
	for name, in := range inputs {
		out := vs.Scrub("before " + in + " after")
		if !strings.Contains(out, secret.Marker) || strings.Contains(out, in) {
			t.Errorf("%s: not scrubbed: %s", name, out)
		}
	}
	if out := vs.Scrub("nothing here"); out != "nothing here" {
		t.Errorf("scrubbed clean text: %s", out)
	}
	vs.Wipe()
	if out := vs.Scrub(testValue); out != testValue {
		t.Error("a wiped scrubber still matches")
	}
}

func TestScrubberSlotSwap(t *testing.T) {
	var slot ScrubberSlot
	if got := slot.Scrub("a " + testValue); got != "a "+testValue {
		t.Fatalf("empty slot changed text: %s", got)
	}
	slot.Set(NewValueScrubber(secret.FromString(testValue)))
	if got := slot.Scrub("a " + testValue); got != "a "+secret.Marker {
		t.Fatalf("got %s", got)
	}
	slot.Set(nil)
	if got := slot.Scrub(testValue); got != testValue {
		t.Fatalf("cleared slot changed text: %s", got)
	}
	var nilSlot *ScrubberSlot
	if nilSlot.Scrub("x") != "x" {
		t.Fatal("nil slot changed text")
	}
}
