// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/edge"
	"github.com/heliopsy/scrim/internal/obs"
)

// Injection points for tests: the trust store tools and the OS whose
// stores are used.
var (
	caRunner    ca.Runner = ca.ExecRunner{}
	caGOOS                = runtime.GOOS
	caSysRoots  []string
	caNow       func() time.Time
	errNoScope  = errors.New("choose --user (per-user trust stores)")
	errSystemCA = errors.New("--system is not supported here; `scrim install --system` adds the CA to the system trust store " +
		"(update-ca-certificates or update-ca-trust) and `scrim uninstall --system` removes it. Elsewhere, add the bundle from " +
		"`scrim ca export` with your OS tool (`security add-trusted-cert -d` on macOS)")
)

// CA manages the tool proxy's interception CA
// (specs/credential-injection "Interception certificate authority",
// specs/interception "CA trust installation").
func (Commands) CA(e *Env) *cobra.Command {
	c := &cobra.Command{
		Use:   "ca",
		Short: "Export, rotate and install the tool proxy's interception CA",
		Long: "The tool proxy signs certificates for the hosts it intercepts with scrim's own CA. Its private key stays in " +
			"the CA directory (tool-proxy.ca.dir); these commands only ever print or install the public certificates.\n\n" +
			"With --edge, export and rotate act on the edge CA instead (edge.ca.*): the separate, name-constrained CA that " +
			"issues only the edge listener's certificate, which the edge forwarders trust. It is never installed into a " +
			"trust store.\n\n" +
			"Every command works without a running daemon. The CA is generated on first use, as the daemon would.",
	}
	c.AddCommand(caExport(e), caRotate(e), caInstall(e), caUninstall(e))
	return c
}

func caExport(e *Env) *cobra.Command {
	var (
		out    string
		edgeCA bool
	)
	c := &cobra.Command{
		Use:   "export",
		Short: "Print the PEM certificates clients must trust (current CA, and the previous one during an overlap)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := openAnyCA(cmd, e, true, edgeCA)
			if err != nil {
				return err
			}
			defer m.Close()
			bundle := m.TrustBundlePEM()
			if out == "" {
				_, err := fmt.Fprint(cmd.OutOrStdout(), bundle)
				return err
			}
			if err := os.WriteFile(out, []byte(bundle), 0o644); err != nil { // #nosec G306 -- public certificates
				return err
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d certificate(s) to %s\n", len(m.Certificates()), out)
			return err
		},
	}
	c.Flags().StringVar(&out, "out", "", "write the bundle to this file instead of stdout")
	c.Flags().BoolVar(&edgeCA, "edge", false, "the edge CA (edge.ca.*), for the edge forwarders' edge-forwarder.ca-file")
	return c
}

func caRotate(e *Env) *cobra.Command {
	var edgeCA bool
	c := &cobra.Command{
		Use:   "rotate",
		Short: "Make a new CA current; the previous one stays trusted for tool-proxy.ca.overlap",
		Long: "Generates a new CA generation and makes it current. The previous generation stays trusted through a cross " +
			"certificate until tool-proxy.ca.overlap ends. A running daemon picks the change up from the CA directory. " +
			"An operator-supplied CA (tool-proxy.ca.cert-file) is never rotated by scrim.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := openAnyCA(cmd, e, false, edgeCA)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.Rotate(cmd.Context()); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			for _, c := range m.Certificates() {
				if c.Current {
					_, _ = fmt.Fprintf(w, "current:  %s, expires %s, sha256 %s\n", c.ID, c.NotAfter.UTC().Format(time.RFC3339), ca.Fingerprint(c.PEM))
				} else {
					_, _ = fmt.Fprintf(w, "previous: %s, trusted until the overlap ends\n", c.ID)
				}
			}
			for _, g := range m.Generations() {
				if !g.Current {
					_, _ = fmt.Fprintf(w, "overlap ends %s\n", g.OverlapUntil.UTC().Format(time.RFC3339))
				}
				g.Key.Wipe()
			}
			if edgeCA {
				_, err = fmt.Fprintln(w, "Give the edge forwarders the bundle from `scrim ca export --edge` before the overlap ends.")
				return err
			}
			_, err = fmt.Fprintln(w, "Run `scrim ca install --user` again to trust the new CA in the per-user trust stores before the overlap ends.")
			return err
		},
	}
	c.Flags().BoolVar(&edgeCA, "edge", false, "rotate the edge CA (edge.ca.*) instead; a running daemon picks it up from edge.ca.dir")
	return c
}

type caScope struct{ user, system, dryRun bool }

func (s *caScope) bind(c *cobra.Command) {
	c.Flags().BoolVar(&s.user, "user", false, "use the per-user trust stores")
	c.Flags().BoolVar(&s.system, "system", false, "use the system trust store (done by scrim install --system)")
	c.Flags().BoolVar(&s.dryRun, "dry-run", false, "show the changes without making them")
}

func (s *caScope) check() error {
	switch {
	case s.system:
		return errSystemCA
	case !s.user:
		return errNoScope
	}
	return nil
}

func caInstall(e *Env) *cobra.Command {
	var scope caScope
	c := &cobra.Command{
		Use:   "install --user",
		Short: "Trust the CA in the per-user trust stores and write bundle files for runtimes with their own trust",
		Long: "Shows each change before making it and records it in the trust manifest in the CA directory, so " +
			"`scrim ca uninstall --user` reverts exactly those changes.\n\n" +
			"macOS: the login keychain (security add-trusted-cert; macOS asks to confirm).\n" +
			"Linux: the NSS database ~/.pki/nssdb (Chromium-based browsers) when it exists and certutil is installed.\n" +
			"Everywhere: $XDG_DATA_HOME/scrim/scrim-ca.pem for NODE_EXTRA_CA_CERTS and ca-bundle.pem (system roots plus " +
			"the scrim CA) for SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE and GIT_SSL_CAINFO.\n\n" +
			"Run it again after a rotation to add the new CA; entries of generations no longer in use are removed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := scope.check(); err != nil {
				return err
			}
			m, err := openCA(cmd, e, true)
			if err != nil {
				return err
			}
			defer m.Close()
			in, err := installer(e, cmd, m.Dir(), scope.dryRun)
			if err != nil {
				return err
			}
			return in.Install(cmd.Context(), m.Certificates())
		},
	}
	scope.bind(c)
	return c
}

func caUninstall(e *Env) *cobra.Command {
	var scope caScope
	c := &cobra.Command{
		Use:   "uninstall --user",
		Short: "Revert every trust change `scrim ca install --user` recorded",
		Long: "Reverts each change listed in the trust manifest. A change that cannot be reverted stays listed and is " +
			"reported with the manual step to undo it; the command then exits 1.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := scope.check(); err != nil {
				return err
			}
			in, err := installer(e, cmd, "", scope.dryRun)
			if err != nil {
				return err
			}
			return in.Uninstall(cmd.Context())
		},
	}
	scope.bind(c)
	return c
}

// installer builds the trust installer for this user. dir is the CA
// directory; empty means the configured or default one.
func installer(e *Env, cmd *cobra.Command, dir string, dryRun bool) (*ca.Installer, error) {
	getenv := e.getenv
	if dir == "" {
		cfg, err := e.Config()
		if err != nil {
			return nil, err
		}
		if dir = ca.DirSetting.Get(cfg); dir == "" {
			if dir, err = ca.DefaultDir(getenv); err != nil {
				return nil, err
			}
		}
	}
	home := getenv("HOME")
	if home == "" || !filepath.IsAbs(home) {
		return nil, errors.New("ca: $HOME is not set")
	}
	data, err := ca.DefaultDataDir(getenv)
	if err != nil {
		return nil, err
	}
	return &ca.Installer{Dir: dir, Home: home, DataDir: data, GOOS: caGOOS, Runner: caRunner,
		Out: cmd.OutOrStdout(), SystemRoots: caSysRoots, DryRun: dryRun, Now: caNow}, nil
}

// openCA opens the CA as the daemon would. An operator-supplied CA's key is
// only resolved when publicOnly is false.
func openCA(cmd *cobra.Command, e *Env, publicOnly bool) (*ca.Manager, error) {
	cfg, err := e.Config()
	if !publicOnly && err == nil {
		cfg, err = e.resolvedConfig(cmd.Context(), ca.KeySetting.Name())
	}
	if err != nil {
		return nil, err
	}
	log, err := caLogger(e, cfg)
	if err != nil {
		return nil, err
	}
	// The directory comes from the configuration (tool-proxy.ca.dir) or
	// from this process's XDG_STATE_HOME / HOME.
	return ca.OpenWith(cmd.Context(), cfg, log, ca.Options{Getenv: e.getenv, PublicOnly: publicOnly, Now: caNow})
}

// openAnyCA opens the interception CA, or the edge CA with edge.
func openAnyCA(cmd *cobra.Command, e *Env, publicOnly, edgeCA bool) (*ca.Manager, error) {
	if !edgeCA {
		return openCA(cmd, e, publicOnly)
	}
	cfg, err := e.Config()
	if !publicOnly && err == nil {
		cfg, err = e.resolvedConfig(cmd.Context(), ca.EdgeKeySetting.Name())
	}
	if err != nil {
		return nil, err
	}
	log, err := caLogger(e, cfg)
	if err != nil {
		return nil, err
	}
	names := edge.ServerNames.Get(cfg)
	if len(names) == 0 {
		return nil, fmt.Errorf("the edge CA is constrained to %s; set it as the central scrim has it", edge.ServerNames.Name())
	}
	return ca.OpenEdge(cmd.Context(), cfg, log, names, ca.Options{Getenv: e.getenv, PublicOnly: publicOnly, Now: caNow})
}

func caLogger(e *Env, cfg *config.Config) (*slog.Logger, error) {
	l, err := obs.LoggerFromConfig(e.Stderr, cfg, nil)
	if err != nil {
		return nil, err
	}
	return obs.WithComponent(l, "ca"), nil
}

// getenv reads the invocation's environment (Env.Environ), not the
// process's, so tests never reach the real home directory.
func (e *Env) getenv(name string) string {
	v := ""
	for _, kv := range e.Environ {
		if k, val, ok := strings.Cut(kv, "="); ok && k == name {
			v = val
		}
	}
	return v
}
