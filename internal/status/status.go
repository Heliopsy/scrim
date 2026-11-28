// SPDX-License-Identifier: AGPL-3.0-only

// Package status assembles what `scrim status` and `scrim doctor` report:
// active protections, interception modes, providers, stores and their
// health, the state backend, audit sinks, the data plane, degraded
// components and every weakened setting in effect.
//
// The facts come from small provider interfaces implemented by the packages
// that own them (stores, config, data plane supervisor, interception). This
// package only gathers, derives and renders them, so it is tested with fakes
// and golden files. Nothing here ever holds a secret value: every field is a
// name, a reference, a count, a time or a health flag.
package status

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/netproxy"
)

// Protection is one safeguard and whether it is active.
type Protection struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Detail string `json:"detail,omitempty"`
}

// Provider is a configured model provider route.
type Provider struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
}

// Store is one configured secret store's health and freshness.
type Store struct {
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Reachable   bool      `json:"reachable"`
	LastRefresh time.Time `json:"last_refresh,omitzero"`
	Values      int       `json:"values"`
	Degraded    bool      `json:"degraded"`
	Reason      string    `json:"reason,omitempty"`
	// Targets is how many values each configured redact target holds. A
	// target with 0 values protects nothing and marks the store degraded.
	Targets []StoreTarget `json:"targets,omitempty"`
}

// StoreTarget is one redact target of a store and its value count.
type StoreTarget struct {
	Target string `json:"target"`
	Values int    `json:"values"`
}

// State describes the state backend.
type State struct {
	Backend       string `json:"backend"`
	Location      string `json:"location,omitempty"`
	SchemaVersion int    `json:"schema_version"`
	Healthy       bool   `json:"healthy"`
	Detail        string `json:"detail,omitempty"`
}

// AuditSink is one audit sink and its backpressure state.
type AuditSink struct {
	Name     string `json:"name"`
	Policy   string `json:"policy"`
	Degraded bool   `json:"degraded"`
	Dropped  uint64 `json:"dropped"`
	Detail   string `json:"detail,omitempty"`
}

// DataPlane is the Rust data plane child process as the supervisor sees it.
type DataPlane struct {
	Running bool          `json:"running"`
	PID     int           `json:"pid,omitempty"`
	Version string        `json:"version,omitempty"`
	Uptime  time.Duration `json:"-"`
	// UptimeSeconds mirrors Uptime for the JSON form.
	UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
	Healthy       bool   `json:"healthy"`
	Detail        string `json:"detail,omitempty"`
}

// Weakened is one weakening setting in effect.
type Weakened struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

// Component is one degraded part of scrim, derived from the rest.
type Component struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Report is the full `scrim status` answer.
type Report struct {
	Version      string       `json:"version"`
	Profile      string       `json:"profile,omitempty"`
	Interception []string     `json:"interception_modes"`
	Protections  []Protection `json:"protections"`
	Providers    []Provider   `json:"providers"`
	Stores       []Store      `json:"stores"`
	State        State        `json:"state"`
	Audit        []AuditSink  `json:"audit_sinks"`
	DataPlane    DataPlane    `json:"data_plane"`
	Degraded     []Component  `json:"degraded"`
	Weakened     []Weakened   `json:"weakened_protections"`
	// Config is the configuration manager's view: files, version, last
	// reload and settings waiting for a restart.
	Config *config.Status `json:"config,omitempty"`
	// Service is the service `scrim install` set up, when there is one.
	Service *Service `json:"service,omitempty"`
	// EBPF is the eBPF transparent mode, when it is configured or attached.
	EBPF *EBPF `json:"ebpf,omitempty"`
	// AgentModes are the agent-side modes `scrim install` set up: agent
	// hooks and managed agent settings.
	AgentModes []AgentMode `json:"agent_modes,omitempty"`
	// Coverage is "partial" when agent hooks are the only interception: no
	// listener of scrim's carries the agent's traffic.
	Coverage string `json:"coverage,omitempty"`
	// RunView is the filesystem view `scrim run` gives its sessions on
	// this host.
	RunView *RunView `json:"run_fs_view,omitempty"`
	// RunNetwork is the agent network `scrim run` gives its sessions on
	// this host (run.network).
	RunNetwork *RunNetwork `json:"run_network,omitempty"`
	// UpstreamProxy is where scrim's own outbound connections go: the
	// upstream proxy as scheme://host:port (never its credentials),
	// "direct", or why the configured one cannot be used.
	UpstreamProxy string `json:"upstream_proxy,omitempty"`
}

// RunView is the session filesystem view of `scrim run` on this host
// (specs/credential-injection, "Filesystem view fallback without
// namespaces").
type RunView struct {
	// Requested is run.fs-view.
	Requested string `json:"requested"`
	// Mode is the view sessions get: namespace, home or off; "refused"
	// when run.fs-view is namespace and the host has none, so scrim run
	// refuses to start agents.
	Mode string `json:"mode"`
	// Fallback is why the namespace view is unavailable, when auto falls
	// back to the home mirror (or namespace refuses).
	Fallback string `json:"fallback,omitempty"`
	// Gaps are what the view does not cover.
	Gaps []string `json:"gaps,omitempty"`
	// ReadableOwn are scrim's own secret files (file: reference targets,
	// key and state directories; "path (origin)") that this user, the user
	// agents run as, can read: scrim runs as that user.
	ReadableOwn []string `json:"readable_own_files,omitempty"`
}

// RunNetwork is the agent network of `scrim run` on this host
// (specs/interception, "Proxy-only agent network").
type RunNetwork struct {
	// Requested is run.network: open or proxy-only.
	Requested string `json:"requested"`
	// Available reports whether this host can give an agent a network
	// namespace of its own, which proxy-only needs.
	Available bool `json:"available"`
	// Reason is why it cannot.
	Reason string `json:"reason,omitempty"`
	// Gaps are what the mode does not stop.
	Gaps []string `json:"gaps,omitempty"`
}

// Refused reports whether scrim run refuses to start agents: proxy-only on
// a host without the namespace.
func (n *RunNetwork) Refused() bool { return n != nil && n.Requested == "proxy-only" && !n.Available }

// RunViewRefused is RunView.Mode when scrim run refuses to start agents.
const RunViewRefused = "refused"

// Agent-side modes and their coverage.
const (
	AgentModeHooks   = "hooks"
	AgentModeManaged = "managed-settings"

	CoveragePartial = "partial"
	CoverageAddOn   = "enforcement add-on"
)

// AgentMode is one agent-side mode and what it does and does not cover.
type AgentMode struct {
	// Mode is hooks or managed-settings.
	Mode   string   `json:"mode"`
	Agents []string `json:"agents"`
	// Coverage is partial (hooks) or enforcement add-on (managed settings).
	Coverage   string   `json:"coverage"`
	Covers     []string `json:"covers"`
	NotCovered []string `json:"not_covered"`
	// Files are the agent configuration files the mode changed.
	Files []string `json:"files"`
	// Changed lists files that are missing or no longer hold what install
	// wrote; the mode is then not in force as installed.
	Changed  []string `json:"changed,omitempty"`
	Manifest string   `json:"manifest"`
}

// EBPF is the eBPF transparent mode on this host
// (specs/interception "Transparent mode with eBPF").
type EBPF struct {
	// Configured is interception.ebpf.cgroups.
	Configured []string `json:"configured"`
	Port       int      `json:"port"`
	// Problem is why the mode cannot work on this host at all.
	Problem string       `json:"problem,omitempty"`
	Cgroups []EBPFCgroup `json:"cgroups"`
	// Listener says whether anything accepts on 127.0.0.1:Port.
	Listener   string `json:"listener"`
	ListenerUp bool   `json:"listener_up"`
}

// EBPFCgroup is one covered control group. Only State "active" was
// confirmed with the kernel; "unverified" rests on the loader's record;
// "stale" is confirmed but with another scrim's programs.
type EBPFCgroup struct {
	Cgroup     string    `json:"cgroup"`
	State      string    `json:"state"`
	Detail     string    `json:"detail"`
	AttachedAt time.Time `json:"attached_at,omitzero"`
	// Fix is the command that attaches it again, when that is the fix.
	Fix string `json:"fix,omitempty"`
}

// ActiveCgroups lists the control groups confirmed active.
func (e *EBPF) ActiveCgroups() []string {
	var out []string
	for _, c := range e.Cgroups {
		if c.State == "active" {
			out = append(out, c.Cgroup)
		}
	}
	return out
}

// EBPFSource reports the eBPF transparent mode; nil when it is off.
type EBPFSource interface {
	EBPFStatus() *EBPF
}

// Service describes an installed scrim service.
type Service struct {
	// Mode is user, system or quadlet; System is true for a system-wide one.
	Mode   string `json:"mode"`
	System bool   `json:"system"`
	Unit   string `json:"unit"`
	// Active is systemctl's ActiveState answer (active, inactive, failed,
	// ...), or "unknown" when systemctl could not be asked.
	Active string `json:"active"`
	// Manifest is the install manifest that lists every change made.
	Manifest string `json:"manifest"`
}

// OK reports whether nothing is degraded and nothing weakened.
func (r Report) OK() bool { return len(r.Degraded) == 0 && len(r.Weakened) == 0 }

// StoreSource reports every configured store's health.
type StoreSource interface {
	StoreHealth(ctx context.Context) []Store
}

// WeakeningSource lists the weakening settings in effect.
type WeakeningSource interface {
	Weakened() []Weakened
}

// DataPlaneSource reports the data plane's state.
type DataPlaneSource interface {
	DataPlaneStatus(ctx context.Context) DataPlane
}

// StateSource reports the state backend.
type StateSource interface {
	StateStatus(ctx context.Context) State
}

// AuditSource reports the audit sinks.
type AuditSource interface {
	AuditSinks(ctx context.Context) []AuditSink
}

// RuntimeSource reports what the running configuration enables: profile,
// interception modes, providers and protections.
type RuntimeSource interface {
	Profile() string
	InterceptionModes() []string
	Providers() []Provider
	Protections() []Protection
}

// ConfigSource is the configuration manager.
type ConfigSource interface {
	Status() config.Status
}

// Sources is everything [Collect] reads. A nil source contributes nothing,
// except that a nil DataPlane or State is reported as unknown and degraded:
// status never claims health it could not check.
type Sources struct {
	Version   string
	Runtime   RuntimeSource
	Stores    StoreSource
	Weakening WeakeningSource
	DataPlane DataPlaneSource
	State     StateSource
	Audit     AuditSource
	// Config, when set, supplies the profile and, unless Weakening is
	// set, the weakened settings.
	Config ConfigSource
	// Service is the installed service, if any.
	Service *Service
	// EBPF is the eBPF transparent mode, read from this host.
	EBPF EBPFSource
	// AgentModes are the installed agent-side modes.
	AgentModes []AgentMode
	// RunView is scrim run's filesystem view on this host, if checked.
	RunView *RunView
	// RunNetwork is scrim run's agent network on this host, if checked.
	RunNetwork *RunNetwork
}

// Collect gathers a report and derives the degraded list.
func Collect(ctx context.Context, src Sources) Report {
	r := Report{
		Version:      src.Version,
		Interception: []string{},
		Protections:  []Protection{},
		Providers:    []Provider{},
		Stores:       []Store{},
		Audit:        []AuditSink{},
		Degraded:     []Component{},
		Weakened:     []Weakened{},
	}
	if src.Runtime != nil {
		r.Profile = src.Runtime.Profile()
		r.Interception = append(r.Interception, src.Runtime.InterceptionModes()...)
		r.Protections = append(r.Protections, src.Runtime.Protections()...)
		r.Providers = append(r.Providers, src.Runtime.Providers()...)
	}
	if src.Stores != nil {
		r.Stores = append(r.Stores, src.Stores.StoreHealth(ctx)...)
	}
	if src.Config != nil {
		cs := src.Config.Status()
		r.Config = &cs
		if cur, ok := src.Config.(interface{ Current() *config.Config }); ok && cur.Current() != nil {
			r.UpstreamProxy = upstreamProxy(cur.Current())
		}
		if r.Profile == "" {
			r.Profile = cs.Profile
		}
		if src.Weakening == nil {
			for _, w := range cs.Weakened {
				r.Weakened = append(r.Weakened, Weakened(w))
			}
		}
	}
	if src.Weakening != nil {
		r.Weakened = append(r.Weakened, src.Weakening.Weakened()...)
	}
	if src.Audit != nil {
		r.Audit = append(r.Audit, src.Audit.AuditSinks(ctx)...)
	}
	if src.State != nil {
		r.State = src.State.StateStatus(ctx)
	} else {
		r.State = State{Backend: "unknown", Detail: "state backend not reported"}
	}
	if src.DataPlane != nil {
		r.DataPlane = src.DataPlane.DataPlaneStatus(ctx)
		r.DataPlane.UptimeSeconds = int64(r.DataPlane.Uptime / time.Second)
	} else {
		r.DataPlane = DataPlane{Detail: "data plane not reported"}
	}

	r.AgentModes = append(r.AgentModes, src.AgentModes...)
	if hooksOnly(r) {
		r.Coverage = CoveragePartial
	}
	for _, m := range r.AgentModes {
		r.Interception = append(r.Interception, m.Mode+" ("+m.Coverage+"): "+strings.Join(m.Agents, ", "))
	}

	sort.Strings(r.Interception)
	sort.Slice(r.Protections, func(i, j int) bool { return r.Protections[i].Name < r.Protections[j].Name })
	sort.Slice(r.Providers, func(i, j int) bool { return r.Providers[i].Name < r.Providers[j].Name })
	sort.Slice(r.Stores, func(i, j int) bool { return r.Stores[i].Name < r.Stores[j].Name })
	sort.Slice(r.Audit, func(i, j int) bool { return r.Audit[i].Name < r.Audit[j].Name })
	sort.Slice(r.Weakened, func(i, j int) bool { return r.Weakened[i].Key < r.Weakened[j].Key })

	r.Service = src.Service
	if src.EBPF != nil {
		r.EBPF = src.EBPF.EBPFStatus()
	}
	addEBPF(&r)
	r.RunView = src.RunView
	r.RunNetwork = src.RunNetwork
	r.Degraded = derive(r)
	return r
}

// carriers are interception modes that put an agent's model traffic on
// scrim: a wrapped session, or redirection the agent cannot skip. A bound
// base-URL or forward-proxy listener alone says nothing about whether an
// agent uses it.
var carriers = []string{"wrapper", "transparent", "kubernetes"}

// hooksOnly reports agent hooks installed with nothing that routes the
// agents' model traffic through scrim: no wrapped session, no enforcing
// interception and no managed settings in force pinning the endpoint.
func hooksOnly(r Report) bool {
	hooks := false
	for _, m := range r.AgentModes {
		switch {
		case m.Mode == AgentModeHooks:
			hooks = true
		case m.Mode == AgentModeManaged && len(m.Changed) == 0:
			return false
		}
	}
	if !hooks {
		return false
	}
	for _, m := range r.Interception {
		for _, c := range carriers {
			if strings.HasPrefix(m, c) {
				return false
			}
		}
	}
	return true
}

func derive(r Report) []Component {
	out := []Component{}
	if r.Service != nil && r.Service.Active != "active" {
		out = append(out, Component{Name: "service:" + r.Service.Unit, Reason: "installed but " + r.Service.Active})
	}
	for _, m := range r.AgentModes {
		if len(m.Changed) > 0 {
			out = append(out, Component{Name: "agent-mode:" + m.Mode, Reason: "changed or removed since install: " + strings.Join(m.Changed, ", ")})
		}
	}
	if v := r.RunView; v != nil && v.Mode == RunViewRefused {
		out = append(out, Component{Name: "run-fs-view", Reason: "run.fs-view is namespace and this host has none, so scrim run refuses to start agents: " + v.Fallback})
	}
	if n := r.RunNetwork; n.Refused() {
		out = append(out, Component{Name: "run-network", Reason: "run.network is proxy-only and this host cannot create the agent's network namespace, so scrim run refuses to start agents: " + n.Reason})
	}
	if !r.DataPlane.Running || !r.DataPlane.Healthy {
		out = append(out, Component{Name: "data-plane", Reason: orDefault(r.DataPlane.Detail, "not running or unhealthy")})
	}
	if !r.State.Healthy {
		out = append(out, Component{Name: "state:" + r.State.Backend, Reason: orDefault(r.State.Detail, "unhealthy")})
	}
	for _, s := range r.Stores {
		if s.Degraded || !s.Reachable {
			out = append(out, Component{Name: "store:" + s.Name, Reason: orDefault(s.Reason, "unreachable")})
		}
	}
	for _, a := range r.Audit {
		if a.Degraded {
			out = append(out, Component{Name: "audit:" + a.Name, Reason: orDefault(a.Detail, "degraded")})
		}
	}
	if r.Config != nil && r.Config.LastReload != nil && !r.Config.LastReload.Applied {
		out = append(out, Component{Name: "config", Reason: "last reload rejected; the previous configuration stays in effect"})
	}
	for _, p := range r.Protections {
		if !p.Active {
			out = append(out, Component{Name: "protection:" + p.Name, Reason: "inactive"})
		}
	}
	if e := r.EBPF; e != nil {
		if e.Problem != "" {
			out = append(out, Component{Name: "ebpf", Reason: e.Problem})
		}
		for _, c := range e.Cgroups {
			if c.State != "active" {
				out = append(out, Component{Name: "ebpf:" + c.Cgroup, Reason: c.Detail})
			}
		}
		if len(e.Cgroups) > 0 && !e.ListenerUp {
			out = append(out, Component{Name: "ebpf-listener", Reason: e.Listener})
		}
	}
	return out
}

// egressProtection is the protection the eBPF mode turns on.
const egressProtection = "direct egress blocked"

// addEBPF lists the control groups confirmed active as an interception mode
// and as the direct egress protection. Ones only the loader's record names
// are not: status never claims what it could not check.
func addEBPF(r *Report) {
	if r.EBPF == nil {
		return
	}
	active := r.EBPF.ActiveCgroups()
	if len(active) == 0 {
		return
	}
	r.Interception = append(r.Interception, fmt.Sprintf("ebpf cgroup %s (TCP 80 and 443 to 127.0.0.1:%d and [::1]:%d)",
		strings.Join(active, ", "), r.EBPF.Port, r.EBPF.Port))
	sort.Strings(r.Interception)
	p := Protection{Name: egressProtection, Active: true,
		Detail: "for the control groups " + strings.Join(active, ", ") + " (eBPF cgroup hooks); other processes can still reach providers directly"}
	for i := range r.Protections {
		if r.Protections[i].Name == egressProtection {
			if !r.Protections[i].Active {
				r.Protections[i] = p
			}
			return
		}
	}
	r.Protections = append(r.Protections, p)
	sort.Slice(r.Protections, func(i, j int) bool { return r.Protections[i].Name < r.Protections[j].Name })
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// upstreamProxy names cfg's upstream proxy without credentials.
func upstreamProxy(cfg *config.Config) string {
	p, err := netproxy.Resolve(cfg)
	if err != nil {
		return "unusable: " + err.Error()
	}
	p.Wipe()
	return p.String()
}
