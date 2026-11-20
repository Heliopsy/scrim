// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/config"
)

func newEnv(environ ...string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return &Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Environ: environ, Registry: config.Default}, &out, &errb
}

// Every exported method of Commands must be a command constructor, so a
// typo in a signature cannot silently drop a command.
func TestCommandMethods(t *testing.T) {
	typ := reflect.TypeFor[Commands]()
	for i := range typ.NumMethod() {
		if m := typ.Method(i); m.Type != commandType {
			t.Errorf("Commands.%s has type %s, want func(*Env) *cobra.Command", m.Name, m.Type)
		}
	}
}

func TestSpecCommandsExist(t *testing.T) {
	e, _, _ := newEnv()
	root := NewRoot(e)
	names := map[string]*cobra.Command{}
	for _, c := range root.Commands() {
		if names[c.Name()] != nil {
			t.Errorf("duplicate command %s", c.Name())
		}
		names[c.Name()] = c
	}
	for _, want := range []string{"run", "proxy", "config", "status", "doctor", "secret", "approve", "mcp", "catalog", "version"} {
		if names[want] == nil {
			t.Errorf("missing command %s", want)
		}
	}
}

func TestVersion(t *testing.T) {
	e, out, _ := newEnv()
	if code := Run(context.Background(), e, []string{"version"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "scrim ") {
		t.Fatalf("output %q", out.String())
	}
}

func TestStubsSayNotImplemented(t *testing.T) {
	for _, name := range []string{"run", "proxy", "status", "doctor", "secret", "approve", "mcp", "catalog"} {
		e, _, errb := newEnv()
		if code := Run(context.Background(), e, []string{name, "--anything"}); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
		if !strings.Contains(errb.String(), "not implemented yet") || !strings.Contains(errb.String(), "scrim "+name) {
			t.Errorf("%s: stderr %q", name, errb.String())
		}
	}
}

func TestGlobalFlagsAndEnv(t *testing.T) {
	e, _, _ := newEnv("SCRIM_LOG_LEVEL=warn")
	root := NewRoot(e)
	if root.PersistentFlags().Lookup("log-level") == nil || root.PersistentFlags().Lookup("config") == nil {
		t.Fatal("global flags missing")
	}
	if err := root.PersistentFlags().Parse([]string{"--log-level", "debug"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.Config()
	if err != nil {
		t.Fatal(err)
	}
	if ent, _ := cfg.Entry("log.level"); ent.Value != "debug" || ent.Source.Kind != config.SourceFlag {
		t.Fatalf("log.level = %v from %v", ent.Value, ent.Source)
	}
}

func TestAppIsBuiltOnceAndClosed(t *testing.T) {
	e, _, _ := newEnv()
	NewRoot(e)
	a, err := e.App(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := e.App(context.Background())
	if a != b {
		t.Fatal("App built twice")
	}
}
