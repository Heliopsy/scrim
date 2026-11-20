// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// runConformance runs the shared suite, then checkFidelity. Infisical trims
// surrounding whitespace from every value, so the adapter refuses such
// writes rather than store a changed value; Unstorable tells the suite.
func runConformance(t *testing.T, f storetest.Factory) {
	t.Helper()
	storetest.Run(t, func(tb storetest.TB) storetest.Harness {
		h := f(tb)
		h.Unstorable = trimmedByInfisical
		return h
	})
	t.Run("FidelityExtra", func(t *testing.T) {
		h := storetest.Prepare(t, f)
		checkFidelity(t, h.Adapter, h.Scheme, h.Prefix)
	})
}

func checkFidelity(t *testing.T, a stores.Adapter, scheme, prefix string) {
	r := randID(6)
	ok := []string{
		`quote"` + r + `"and\backslash\\`,
		"line one " + r + "\nline two\r\nline three\ttab",
		"unicode é 日本 🔑    " + r,
		"<html>&amp;'single' {{template}} ${VAR} $(cmd) `tick` " + r,
		"=" + r + "=#;not a comment",
		"-----BEGIN KEY-----\n" + r + "\n-----END KEY-----\n",
	}
	for i, p := range ok {
		ref := stores.Ref{Scheme: scheme, Path: fmt.Sprintf("%s/fidelity-%d", prefix, i)}
		if _, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString(p)}, stores.WriteOptions{}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		s, err := a.Read(t.Context(), ref)
		if err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
		if v, _ := s.Field(Field); plain(t, v) != p {
			t.Errorf("value %d did not round-trip byte for byte", i)
		}
		s.Wipe()
	}
	for i, p := range []string{" leading " + r, "trailing " + r + " ", "two newlines " + r + "\n\n", "\ufeffbom " + r} {
		ref := stores.Ref{Scheme: scheme, Path: fmt.Sprintf("%s/trimmed-%d", prefix, i)}
		_, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString(p)}, stores.WriteOptions{})
		if !errors.Is(err, stores.ErrUnsupported) {
			t.Errorf("Write of a value Infisical would trim (%d): %v, want ErrUnsupported", i, err)
		}
		if err != nil && strings.Contains(fmt.Sprintf("%v %+v", err, err), r) {
			t.Errorf("refusal carries the value")
		}
		if _, err := a.Read(t.Context(), ref); !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("a refused value was stored (%d): %v", i, err)
		}
	}
}

func trimmedByInfisical(p string) bool { return !storable(secret.FromString(p)) }
