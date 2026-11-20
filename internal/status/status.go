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
	"sort"
	"time"

	"github.com/heliopsy/scrim/internal/config"
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

	sort.Strings(r.Interception)
	sort.Slice(r.Protections, func(i, j int) bool { return r.Protections[i].Name < r.Protections[j].Name })
	sort.Slice(r.Providers, func(i, j int) bool { return r.Providers[i].Name < r.Providers[j].Name })
	sort.Slice(r.Stores, func(i, j int) bool { return r.Stores[i].Name < r.Stores[j].Name })
	sort.Slice(r.Audit, func(i, j int) bool { return r.Audit[i].Name < r.Audit[j].Name })
	sort.Slice(r.Weakened, func(i, j int) bool { return r.Weakened[i].Key < r.Weakened[j].Key })

	r.Degraded = derive(r)
	return r
}

func derive(r Report) []Component {
	out := []Component{}
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
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
