// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/daemon"
	"github.com/heliopsy/scrim/internal/dataplane"
	"github.com/heliopsy/scrim/internal/fsview"
	"github.com/heliopsy/scrim/internal/install"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/postgres"
	"github.com/heliopsy/scrim/internal/state/sqlite"
	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
	"github.com/heliopsy/scrim/internal/version"
)

// Status reports what scrim protects and what is degraded
// (specs/observability "Status command").
func (Commands) Status(e *Env) *cobra.Command {
	var out outputFlags
	c := &cobra.Command{
		Use:   "status",
		Short: "Report protections, interception, stores, state and weakened settings",
		Long: "Report the version, active interception modes and protections, providers, stores with their health, " +
			"the state backend, audit sinks, the data plane, degraded components and every weakened setting in effect.\n\n" +
			"Exits 0 whenever the report could be produced; use `scrim doctor` for a pass or fail answer.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := out.format()
			if err != nil {
				return err
			}
			src, closeFn, err := statusSources(cmd.Context(), e)
			if err != nil {
				return err
			}
			defer closeFn()
			r := status.Collect(cmd.Context(), src)
			if format == "json" {
				return status.WriteJSON(cmd.OutOrStdout(), r)
			}
			return status.WriteHuman(cmd.OutOrStdout(), r)
		},
	}
	out.bind(c)
	return c
}

// outputFlags is the -o/--output and --json pair shared by status, doctor
// and audit.
type outputFlags struct {
	output string
	json   bool
}

func (o *outputFlags) bind(c *cobra.Command) {
	c.Flags().StringVarP(&o.output, "output", "o", "text", "output format: text or json")
	c.Flags().BoolVar(&o.json, "json", false, "shorthand for --output json")
}

func (o *outputFlags) format() (string, error) {
	if o.json {
		return "json", nil
	}
	switch o.output {
	case "text", "json":
		return o.output, nil
	}
	return "", fmt.Errorf("--output %q is not one of text, json", o.output)
}

// statusSources gathers what this process can see: the effective
// configuration, the state backend and the configured stores. A SQLite file
// held by a running scrim is reported as in use, not as a failure. The data
// plane is checked by starting it once (dataplane.Probe), unless a daemon
// answers on the admin API: then interception modes, protections, providers
// and the data plane come from it. Without a daemon they show as not
// reported, never as healthy.
func statusSources(ctx context.Context, e *Env) (status.Sources, func(), error) {
	cfg, err := e.Config()
	if err != nil {
		return status.Sources{}, nil, err
	}
	m, err := config.NewManager(e.ConfigOptions(), nil)
	if err != nil {
		return status.Sources{}, nil, err
	}
	src := status.Sources{Version: version.String(), Config: m}
	src.DataPlane = dataplane.Probe{
		Path:    dataplane.PathSetting.Get(cfg),
		Options: dataplane.StartOptions{Mlock: dataplane.MlockSetting.Get(cfg)},
		Timeout: dataplane.StartTimeout.Get(cfg),
	}
	// A running daemon reports what it actually serves: interception modes
	// from its bound listeners and open sessions, protections, providers
	// and its data plane, and its stores with the values each redact
	// target holds. Without one, the data plane is probed once.
	var external []status.AuditSink
	if info, err := daemon.Connect(ctx, cfg); err == nil {
		external = info.AuditSinks
		src.Runtime = info.StatusRuntime()
		src.DataPlane = staticDataPlane(info.StatusDataPlane())
		src.Stores = staticStores(info.Stores)
	}
	src.RunView = runViewStatus(ctx, cfg)
	src.Service = installedService(ctx, cfg)
	src.RunView.ReadableOwn = readableOwnFiles(cfg, src.Service)
	src.EBPF = ebpfSource{e}
	src.AgentModes = installedAgentModes(cfg)
	stateCfg := cfg
	if src.Service != nil && src.Service.System && installEUID() == 0 {
		// Root asks about the system service: report its state, and never
		// create a state database under /root.
		o := e.ConfigOptions()
		o.Environ = append(slices.Clone(o.Environ), "XDG_STATE_HOME="+filepath.Join(installRoot, "/var/lib"),
			"HOME="+filepath.Join(installRoot, install.SystemStateDir))
		if c, err := config.Build(o); err == nil {
			stateCfg = c
		}
	}
	st, closeFn := openStateForStatus(ctx, stateCfg)
	src.State = st
	src.Audit = status.DBAuditSink{State: st, External: external}
	return src, closeFn, nil
}

// runViewProbe checks the namespace filesystem view; tests replace it.
var runViewProbe = func(ctx context.Context) fsview.Availability {
	exe, err := os.Executable()
	if err != nil {
		return fsview.Availability{Reason: err.Error()}
	}
	return fsview.Probe(ctx, exe)
}

// runViewStatus reports the filesystem view scrim run gives sessions on
// this host: what run.fs-view resolves to, and its gaps.
func runViewStatus(ctx context.Context, cfg *config.Config) *status.RunView {
	req := fsview.Setting.Get(cfg)
	v := &status.RunView{Requested: req}
	var avail fsview.Availability
	if req == fsview.ModeAuto || req == fsview.ModeNamespace {
		avail = runViewProbe(ctx)
	}
	mode, fallback, err := fsview.Resolve(req, avail)
	if err != nil {
		v.Mode, v.Fallback = status.RunViewRefused, avail.Reason
		return v
	}
	v.Mode, v.Fallback, v.Gaps = mode, fallback, fsview.Gaps(mode)
	return v
}

// readableOwnFiles lists scrim's own secret files in cfg that this user can
// read: file: reference targets, key-material settings and store fields,
// and the state directory unless the system service is installed (its state
// is under /var/lib/scrim). Config files are left out: they hold
// references, and a literal secret in one has its own warning. Root reads
// everything and runs no agents, so it gets no list.
func readableOwnFiles(cfg *config.Config, svc *status.Service) []string {
	if installEUID() == 0 {
		return nil
	}
	var own []fsview.OwnPath
	for _, p := range cfg.OwnPaths() {
		switch {
		case p.Origin == config.OwnOriginConfigFile:
		case p.Origin == config.OwnOriginStateDir && svc != nil && svc.System:
		default:
			own = append(own, fsview.OwnPath{Path: p.Path, Origin: p.Origin})
		}
	}
	var out []string
	for _, p := range fsview.Readable(own) {
		out = append(out, p.Path+" ("+p.Origin+")")
	}
	return out
}

// installedService reports the service `scrim install` set up: the system
// install first, then this user's, with systemctl's view of the unit.
func installedService(ctx context.Context, cfg *config.Config) *status.Service {
	paths := []string{filepath.Join(installRoot, install.SystemManifest)}
	if dir, err := cfg.StateDir(); err == nil {
		paths = append(paths, filepath.Join(dir, install.ManifestName))
	}
	for _, p := range paths {
		mf, found, err := install.ReadManifest(p)
		if err != nil || !found {
			continue
		}
		args := []string{"show", "--property=ActiveState", "--value", install.UnitName}
		if !mf.System {
			args = append([]string{"--user"}, args...)
		}
		active := "unknown"
		if out, err := installRunner.Run(ctx, "systemctl", args...); err == nil {
			if a := strings.TrimSpace(string(out)); a != "" {
				active = a
			}
		}
		return &status.Service{Mode: string(mf.Mode), System: mf.System, Unit: install.UnitName, Active: active, Manifest: p}
	}
	return nil
}

// installedAgentModes reports the agent-side modes `scrim install` set up:
// the machine's managed agent settings and this user's agent hooks.
func installedAgentModes(cfg *config.Config) []status.AgentMode {
	paths := []string{filepath.Join(installRoot, install.ManagedManifest)}
	if dir, err := cfg.StateDir(); err == nil {
		paths = append(paths, filepath.Join(dir, install.HooksManifestName))
	}
	var out []status.AgentMode
	for _, p := range paths {
		st, found, err := install.ReadAgentMode(p, installRoot)
		if err != nil || !found {
			continue
		}
		m := status.AgentMode{Mode: string(st.Mode), Agents: st.Agents, Files: st.Files, Changed: st.Changed, Manifest: p}
		switch st.Mode {
		case install.ModeHooks:
			m.Coverage, m.Covers, m.NotCovered = status.CoveragePartial, install.HooksCovers, install.HooksNotCovered
		case install.ModeManaged:
			m.Coverage, m.Covers, m.NotCovered = status.CoverageAddOn, install.ManagedCovers, install.ManagedNotCovered
		default:
			continue
		}
		out = append(out, m)
	}
	return out
}

// openStateForStatus opens the state backend for a report. A SQLite file is
// opened read-only, without the process lock, so status never stops a scrim
// starting at the same moment from opening it, and a missing file is
// reported, not created. PostgreSQL is opened in read-only sessions and
// never migrated: its schema version is reported against this binary's.
func openStateForStatus(ctx context.Context, cfg *config.Config) (status.StateOf, func()) {
	name := state.BackendSetting.Get(cfg)
	switch name {
	case sqlite.Name:
		return openSQLiteForStatus(ctx, cfg)
	case postgres.Name:
		return openPostgresForStatus(ctx, cfg)
	}
	s, err := state.Open(ctx, cfg)
	if err != nil {
		return status.StateOf{Name: name, Err: err}, func() {}
	}
	if err := s.Migrate(ctx); err != nil {
		_ = s.Close()
		return status.StateOf{Name: name, Err: err}, func() {}
	}
	return status.StateOf{Store: s}, func() { _ = s.Close() }
}

// openPostgresForStatus connects with default_transaction_read_only=on and
// takes no advisory lock, so status runs no DDL, writes nothing, works for a
// role without DDL rights and never races daemons migrating the shared
// database during a rolling upgrade.
func openPostgresForStatus(ctx context.Context, cfg *config.Config) (status.StateOf, func()) {
	expected, err := postgres.LatestSchema()
	if err != nil {
		return status.StateOf{Name: postgres.Name, Err: err}, func() {}
	}
	// The CLI builds its configuration without stores: a DSN given as a
	// store reference is read from its store here.
	cfg, done, err := storeconfig.Resolved(ctx, cfg, stores.DefaultRegistry, postgres.DSNSetting.Name())
	if err != nil {
		return status.StateOf{Name: postgres.Name, Err: err}, func() {}
	}
	done()
	dsn, ok := cfg.Secret(postgres.DSNSetting)
	if !ok {
		return status.StateOf{Name: postgres.Name,
			Err: errors.New("state: state.backend is postgres but state.postgres.dsn is not set or not resolved")}, func() {}
	}
	s, err := postgres.OpenReadOnly(ctx, dsn, postgres.Options{ConnectTimeout: postgres.ConnectTimeoutSetting.Get(cfg)})
	if err != nil {
		return status.StateOf{Name: postgres.Name, Err: err}, func() {}
	}
	return status.StateOf{Store: s, Expected: expected}, func() { _ = s.Close() }
}

func openSQLiteForStatus(ctx context.Context, cfg *config.Config) (status.StateOf, func()) {
	path, err := sqlite.PathFor(cfg)
	if err != nil {
		return status.StateOf{Name: sqlite.Name, Err: err}, func() {}
	}
	s, err := sqlite.OpenReadOnly(ctx, path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return status.StateOf{Name: sqlite.Name, Location: path, Info: "not created yet; scrim creates it when it first starts"}, func() {}
	case err != nil:
		return status.StateOf{Name: sqlite.Name, Location: path, Err: err}, func() {}
	}
	var info string
	if pid := sqlite.Holder(s.Path()); pid > 0 {
		info = fmt.Sprintf("%s is in use by scrim process %d", s.Path(), pid)
	}
	return status.StateOf{Store: s, Info: info}, func() { _ = s.Close() }
}

// staticStores is store health already collected by the daemon.
type staticStores []status.Store

func (s staticStores) StoreHealth(context.Context) []status.Store { return s }

// staticDataPlane is a data plane status already collected.
type staticDataPlane status.DataPlane

func (s staticDataPlane) DataPlaneStatus(context.Context) status.DataPlane {
	return status.DataPlane(s)
}

// writeOut writes v as JSON or through human.
func writeOut(w io.Writer, format string, v any, human func(io.Writer) error) error {
	if format == "json" {
		return status.WriteJSON(w, v)
	}
	return human(w)
}
