// SPDX-License-Identifier: AGPL-3.0-only

// Package cli is the scrim command line.
//
// Each area adds its top-level command in its own file as a method on
// [Commands]:
//
//	// internal/cli/secret.go
//	func (Commands) Secret(e *Env) *cobra.Command { ... }
//
// [NewRoot] finds every exported method of Commands with that signature by
// reflection, so adding a command never edits a shared list and parallel
// changes do not conflict. There is no init-time registration. A method
// with any other signature fails TestCommandMethods.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"sync"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/config"
)

// Commands is the receiver every top-level command hangs off. It has no
// state; per-invocation state lives in [Env].
type Commands struct{}

// Env is what a command gets: its streams, the environment and lazy access
// to the configuration and the composition root.
type Env struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Environ []string
	// Registry is the settings registry; flags are bound from it.
	Registry *config.Registry

	root    *cobra.Command
	cfgOnce sync.Once
	cfg     *config.Config
	cfgErr  error
	app     *app.App
}

// Config returns the effective configuration, loaded once after flags are
// parsed: defaults, profile, config files, SCRIM_* environment, then flags.
func (e *Env) Config() (*config.Config, error) {
	e.cfgOnce.Do(func() {
		e.cfg, e.cfgErr = config.Build(e.ConfigOptions())
	})
	return e.cfg, e.cfgErr
}

// ConfigOptions says where this invocation reads configuration from, for
// [config.Build] and [config.NewManager].
func (e *Env) ConfigOptions() config.Options {
	var paths []string
	if p, _ := e.root.PersistentFlags().GetString("config"); p != "" {
		paths = []string{p}
	}
	environ := e.Environ
	if environ == nil {
		environ = []string{}
	}
	return config.Options{Registry: e.Registry, ConfigPaths: paths, Environ: environ, Flags: e.root.PersistentFlags()}
}

// App builds the composition root once. The root command closes it.
func (e *Env) App(ctx context.Context) (*app.App, error) {
	if e.app != nil {
		return e.app, nil
	}
	if _, err := e.Config(); err != nil {
		return nil, err
	}
	a, err := app.New(ctx, e.ConfigOptions(), e.Stderr)
	if err != nil {
		return nil, err
	}
	e.app = a
	return a, nil
}

// ErrNotImplemented is returned by commands the spec names but no code
// implements yet.
var ErrNotImplemented = errors.New("not implemented yet")

var commandType = reflect.TypeFor[func(Commands, *Env) *cobra.Command]()

// NewRoot builds the command tree for e.
func NewRoot(e *Env) *cobra.Command {
	root := &cobra.Command{
		Use:           "scrim",
		Short:         "Keeps secret values away from LLM providers while AI agents keep working",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(e.Stdin)
	root.SetOut(e.Stdout)
	root.SetErr(e.Stderr)
	root.CompletionOptions.HiddenDefaultCmd = true
	// --config is read by the file loader; the flag is declared here so
	// every command accepts it. SCRIM_CONFIG is its environment form.
	root.PersistentFlags().String("config", "", "config file (default: first of $XDG_CONFIG_HOME/scrim/config.yaml, ~/.config/scrim/config.yaml, /etc/scrim/config.yaml)")
	e.Registry.BindFlags(root.PersistentFlags())
	e.root = root

	for _, c := range commands(e) {
		root.AddCommand(c)
	}
	return root
}

// commands returns every area's command, sorted by name.
func commands(e *Env) []*cobra.Command {
	v := reflect.ValueOf(Commands{})
	t := v.Type()
	var out []*cobra.Command
	for i := range t.NumMethod() {
		m := t.Method(i)
		if m.Type != commandType {
			continue
		}
		res := m.Func.Call([]reflect.Value{v, reflect.ValueOf(e)})
		if c, _ := res[0].Interface().(*cobra.Command); c != nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Main runs the CLI and returns the process exit code.
func Main(ctx context.Context, args []string) int {
	e := &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Environ: os.Environ(), Registry: config.Default}
	return Run(ctx, e, args)
}

// Run executes args against e and returns the exit code: 0 on success, 1 on
// error. Errors are printed once, to e.Stderr.
func Run(ctx context.Context, e *Env, args []string) int {
	root := NewRoot(e)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if e.app != nil {
		if cerr := e.app.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(e.Stderr, "scrim:", err)
		return 1
	}
	return 0
}

// stub returns a placeholder command that fails with ErrNotImplemented and
// names the task that implements it.
func stub(use, short, task string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short + " (not implemented yet)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("%s: %w (tasks.md %s)", cmd.CommandPath(), ErrNotImplemented, task)
		},
	}
}
