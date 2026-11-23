// SPDX-License-Identifier: AGPL-3.0-only

package agentcache

import (
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}

func TestCache(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(copyValue, secret.Value.Wipe)
	c.SetNow(func() time.Time { return now })
	a := secret.FromString("cred-a")
	c.Put("agent-a", "s1", a, 30*time.Minute)
	got, ok := c.Get("agent-a")
	if !ok || !got.Equal(secret.FromString("cred-a")) {
		t.Fatal("fresh credential not returned")
	}
	got.Wipe()
	if _, ok := c.Get("agent-b"); ok {
		t.Fatal("another key's credential returned")
	}
	now = now.Add(20 * time.Minute)
	if _, ok := c.Get("agent-a"); ok {
		t.Fatal("credential used past two thirds of its life")
	}
	b := secret.FromString("cred-b")
	c.Put("agent-b", "s2", b, 0)
	c.ForgetSession("s2")
	if _, ok := c.Get("agent-b"); ok || !b.Wiped() {
		t.Fatal("ForgetSession kept or did not wipe the session's credential")
	}
	c.Close()
	if !a.Wiped() || c.Len() != 0 {
		t.Fatal("Close did not wipe")
	}
}

func TestCacheBounded(t *testing.T) {
	c := New(copyValue, secret.Value.Wipe)
	for i := range MaxEntries + 5 {
		c.Put(string(rune('a'+i%26))+time.Duration(i).String(), "", secret.FromString("x"), time.Hour)
	}
	if c.Len() > MaxEntries {
		t.Fatalf("cache holds %d entries", c.Len())
	}
}
