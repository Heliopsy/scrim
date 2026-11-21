// SPDX-License-Identifier: AGPL-3.0-only

package placeholder

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
)

type shapeVector struct {
	KeyVersion  int     `json:"key_version"`
	KeyHex      string  `json:"key_hex"`
	Slug        string  `json:"slug"`
	Value       string  `json:"value"`
	Placeholder *string `json:"placeholder"`
}

// The data plane writes testdata/shaped.json from scrim-redact; both
// implementations must agree on every vector.
func TestShapedMatchesDataPlaneVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/shaped.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []shapeVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 20 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		kb, err := hex.DecodeString(v.KeyHex)
		if err != nil {
			t.Fatal(err)
		}
		k := Key{Version: v.KeyVersion, Key: secret.New(kb)}
		got, err := Shaped(k, v.Slug, secret.FromString(v.Value))
		switch {
		case v.Placeholder == nil:
			if !errors.Is(err, ErrNoShape) {
				t.Errorf("%s (key %d): want no shape, got %q, %v", v.Slug, v.KeyVersion, got, err)
			}
		case err != nil:
			t.Errorf("%s (key %d): %v", v.Slug, v.KeyVersion, err)
		case got != *v.Placeholder:
			t.Errorf("%s (key %d): got %q, want %q", v.Slug, v.KeyVersion, got, *v.Placeholder)
		}
	}
}

func TestShapedGitHubChecksumNeverValidates(t *testing.T) {
	k := Key{Version: 1, Key: secret.FromString("0123456789abcdef0123456789abcdef")}
	for i := range 500 {
		v := "ghp_" + strings.Repeat("0", 30) + strings.Repeat(string(rune('a'+i%26)), 6)
		got, err := Shaped(k, "gh", secret.FromString(v))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(got, "ghp_") || len(got) != len(v) {
			t.Fatalf("shape lost: %q", got)
		}
		if githubChecksumValid("ghp_", []byte(got[4:])) {
			t.Fatalf("placeholder %q carries a valid checksum", got)
		}
	}
}
