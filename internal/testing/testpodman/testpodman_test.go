// SPDX-License-Identifier: AGPL-3.0-only

package testpodman

import (
	"os"
	"slices"
	"testing"
)

func TestRunGetsLabelAndLifetime(t *testing.T) {
	got := withRunFlags([]string{"run", "-d", "--rm", "img"})
	want := []string{"run", "--label", Label + "=1", "--timeout", "7200", "-d", "--rm", "img"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if got := withRunFlags([]string{"rm", "-f", "x"}); !slices.Equal(got, []string{"rm", "-f", "x"}) {
		t.Fatalf("%q", got)
	}
}

// The environment is the one the binary started with, not a later HOME.
func TestCommandKeepsTheOriginalHome(t *testing.T) {
	orig := os.Getenv("HOME")
	t.Setenv("HOME", t.TempDir())
	c := Command("ps")
	if !slices.Contains(c.Env, "HOME="+orig) {
		t.Fatalf("HOME not kept: %v", c.Env)
	}
}
