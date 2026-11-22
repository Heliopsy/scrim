// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"reflect"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// TestKubeTokensAreRedactedUntilTheyExpire: a verified service account
// token is in the redaction set with no reference (redaction only), once
// however often it is verified, and leaves the set when it expires. A token
// without an expiry stays kubeTokenTTL after its last verification.
func TestKubeTokensAreRedactedUntilTheyExpire(t *testing.T) {
	now := time.Now()
	changes := 0
	k := newSessionTokens(kubeTokenStore, func() { changes++ })
	k.now = func() time.Time { return now }
	tok, forever := seed(t, "eyJ-tok-"), seed(t, "eyJ-noexp-")
	k.addKube([]byte(tok), now.Add(time.Hour))
	k.addKube([]byte(tok), now.Add(time.Hour))
	k.addKube([]byte(forever), time.Time{})
	held := func() map[string]refresh.Source {
		out := map[string]refresh.Source{}
		k.EachValue(func(s refresh.Source, v secret.Value) {
			_ = v.Expose(func(b []byte) error { out[string(b)] = s; return nil })
		})
		return out
	}
	h := held()
	if len(h) != 2 || !h[tok].Ref.IsZero() || changes != 2 || k.Store() != "scrim-kubernetes" {
		t.Fatalf("held %d values, %d changes", len(h), changes)
	}
	now = now.Add(time.Hour + time.Second)
	if !k.prune() {
		t.Fatal("nothing expired")
	}
	if h := held(); len(h) != 1 || !reflect.DeepEqual(h[forever], refresh.Source{}) {
		t.Fatalf("after expiry held %d values", len(h))
	}
	now = now.Add(kubeTokenTTL)
	k.prune()
	if len(held()) != 0 {
		t.Fatal("a token without expiry outlived kubeTokenTTL")
	}
	k.close()
}
