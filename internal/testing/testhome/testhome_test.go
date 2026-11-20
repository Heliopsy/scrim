// SPDX-License-Identifier: AGPL-3.0-only

package testhome

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(Run(m)) }

func TestRunIsolates(t *testing.T) {
	home, _ := os.UserHomeDir()
	for _, k := range Vars {
		if v := os.Getenv(k); v == "" || v != home {
			t.Fatalf("%s = %q, home = %q", k, v, home)
		}
	}
	if !strings.HasPrefix(home, os.TempDir()) {
		t.Fatalf("home %s is not a temporary directory", home)
	}
}

func TestCheckRefusesRealHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/home/someone/.local/state")
	if err := Check("/home/someone"); err == nil {
		t.Fatal("a state directory inside the real home passed")
	}
	t.Setenv("XDG_STATE_HOME", "")
	if err := Check("/home/someone"); err == nil {
		t.Fatal("an unset variable passed")
	}
}

func TestEnviron(t *testing.T) {
	env := Environ(t, "X=1")
	if len(env) != len(Vars)+1 || env[len(env)-1] != "X=1" {
		t.Fatalf("Environ = %v", env)
	}
}
