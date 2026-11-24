// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/fsperm"
	"github.com/heliopsy/scrim/internal/fsperm/fspermtest"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

type fakeRuntime struct {
	profile string
	modes   []string
	prov    []Provider
	prot    []Protection
}

func (f fakeRuntime) Profile() string             { return f.profile }
func (f fakeRuntime) InterceptionModes() []string { return f.modes }
func (f fakeRuntime) Providers() []Provider       { return f.prov }
func (f fakeRuntime) Protections() []Protection   { return f.prot }

type fakeConfig config.Status

func (f fakeConfig) Status() config.Status { return config.Status(f) }

type fakeStores []Store

func (f fakeStores) StoreHealth(context.Context) []Store { return f }

type fakeWeak []Weakened

func (f fakeWeak) Weakened() []Weakened { return f }

type fakeDP DataPlane

func (f fakeDP) DataPlaneStatus(context.Context) DataPlane { return DataPlane(f) }

type fakeState State

func (f fakeState) StateStatus(context.Context) State { return State(f) }

type fakeEBPF EBPF

func (f fakeEBPF) EBPFStatus() *EBPF { e := EBPF(f); return &e }

type fakeAudit []AuditSink

func (f fakeAudit) AuditSinks(context.Context) []AuditSink { return f }

var refreshed = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)

func protections(redactorActive bool) []Protection {
	return []Protection{
		{Name: "redaction", Active: redactorActive, Detail: "known-value matcher over 42 values"},
		{Name: "guard", Active: true, Detail: "independent outbound check"},
		{Name: "unknown-field-redaction", Active: true},
		{Name: "credential-injection", Active: true, Detail: "3 host-bound credentials"},
	}
}

// fixtures are the setups the golden files cover.
func fixtures() map[string]Sources {
	return map[string]Sources{
		"healthy": {
			Version: "0.1.0",
			Runtime: fakeRuntime{
				profile: "laptop",
				modes:   []string{"wrapper", "base-url"},
				prov:    []Provider{{Name: "anthropic", Upstream: "https://api.anthropic.com"}},
				prot:    protections(true),
			},
			Stores: fakeStores{{Name: "bao", Kind: "openbao", Reachable: true, LastRefresh: refreshed, Values: 42}},
			Config: fakeConfig{Version: 3, Profile: "laptop", Files: []string{"/home/u/.config/scrim/config.yaml"},
				LoadedAt: refreshed, Weakened: []config.WeakenedSetting{},
				LastReload: &config.ReloadResult{At: refreshed, Trigger: "file", Applied: true, Version: 3}},
			DataPlane: fakeDP{Running: true, PID: 4242, Version: "0.1.0", Uptime: 3*time.Hour + 2*time.Minute, Healthy: true},
			State:     fakeState{Backend: "sqlite", Location: "/home/u/.local/state/scrim/state.db", SchemaVersion: 1, Healthy: true},
			Audit:     fakeAudit{{Name: "db", Policy: "block"}},
		},
		"degraded": {
			Version: "0.1.0",
			Runtime: fakeRuntime{
				profile: "server",
				modes:   []string{"transparent-nftables", "forward-proxy"},
				prov: []Provider{
					{Name: "openai", Upstream: "https://api.openai.com"},
					{Name: "anthropic", Upstream: "http://127.0.0.1:8787 (caveman)"},
				},
				prot: protections(false),
			},
			Stores: fakeStores{
				{Name: "vw", Kind: "vaultwarden", Reachable: false, LastRefresh: refreshed, Values: 7, Degraded: true,
					Reason: "unreachable for 12m, staleness limit 5m"},
				{Name: "bao", Kind: "openbao", Reachable: true, LastRefresh: refreshed, Values: 42},
				{Name: "inf", Kind: "infisical", Reachable: true, Values: 0, Degraded: true, Reason: "never loaded"},
			},
			Weakening: fakeWeak{
				{Key: "state.sqlite.allow-network-filesystem", Value: "true", Source: "env SCRIM_STATE_SQLITE_ALLOW_NETWORK_FILESYSTEM",
					Description: "Allows the SQLite state file on a network filesystem, where locking is unreliable."},
				{Key: "redaction.allow-unknown-fields", Value: "true", Source: "file /etc/scrim/scrim.yaml",
					Description: "Forwards unknown provider request fields without redaction."},
			},
			Config: fakeConfig{Version: 2, Profile: "server", Files: []string{"/etc/scrim/scrim.yaml"}, LoadedAt: refreshed,
				PendingRestart: []string{"state.backend"},
				Warnings:       []string{"stores.vw.token (file /etc/scrim/scrim.yaml): literal secret in the config file"},
				LastReload: &config.ReloadResult{At: refreshed, Trigger: "SIGHUP", Applied: false, Version: 2,
					Problems: []string{"policy.default: maybe is not one of allow, ask, deny"}}},
			DataPlane: fakeDP{Running: false, Detail: "exited with signal 9 at 09:31:02, restarting"},
			State: fakeState{Backend: "postgres", Location: "postgres://scrim@db.internal/scrim", SchemaVersion: 1,
				Healthy: false, Detail: "connection refused"},
			Audit: fakeAudit{
				{Name: "kafka", Policy: "drop", Degraded: true, Dropped: 17, Detail: "broker unreachable"},
				{Name: "db", Policy: "block"},
			},
		},
		"empty": {Version: "0.1.0"},
		// The eBPF mode confirmed on one control group, the daemon's own
		// egress protection inactive: status turns it on for that group.
		"ebpf-active": {
			Version: "0.1.0",
			Runtime: fakeRuntime{modes: []string{"transparent 127.0.0.1:9792"},
				prot: []Protection{{Name: "direct egress blocked", Active: false, Detail: "no enforcing interception mode"}}},
			DataPlane: fakeDP{Running: true, PID: 7, Healthy: true},
			State:     fakeState{Backend: "memory", Healthy: true},
			EBPF: fakeEBPF{Configured: []string{"agents.slice"}, Port: 9792, ListenerUp: true, Listener: "127.0.0.1:9792 accepts connections",
				Cgroups: []EBPFCgroup{{Cgroup: "agents.slice", State: "active", AttachedAt: refreshed,
					Detail: "TCP 80 and 443 redirected to 127.0.0.1:9792 and [::1]:9792, direct and QUIC egress denied (verified with the kernel)"}}},
		},
		// Configured but never attached, a recorded group this process
		// cannot confirm, and nothing listening.
		"ebpf-missing": {
			Version:   "0.1.0",
			DataPlane: fakeDP{Running: true, PID: 7, Healthy: true},
			State:     fakeState{Backend: "memory", Healthy: true},
			EBPF: fakeEBPF{Configured: []string{"agents.slice"}, Port: 9792,
				Listener: "nothing accepts connections on 127.0.0.1:9792: redirected connections fail (they never go direct)",
				Cgroups: []EBPFCgroup{
					{Cgroup: "agents.slice", State: "not-attached", Detail: "not attached: run `sudo scrim ebpf attach`; attaching needs root, or CAP_BPF and CAP_NET_ADMIN, and this process lacks CAP_BPF and CAP_NET_ADMIN"},
					{Cgroup: "ci.slice", State: "unverified", AttachedAt: refreshed, Detail: "attached according to the loader's record (/run/scrim-ebpf/attachments.json); confirming it with the kernel needs CAP_NET_ADMIN: run `sudo scrim status`"},
				}},
		},
		// Agent hooks as the only interception, next to managed settings
		// whose Codex file was edited since install.
		"hooks-only": {
			Version:   "0.1.0",
			DataPlane: fakeDP{Running: true, PID: 4242, Version: "0.1.0", Healthy: true},
			State:     fakeState{Backend: "sqlite", SchemaVersion: 1, Healthy: true},
			AgentModes: []AgentMode{
				{Mode: AgentModeHooks, Agents: []string{"claude", "codex"}, Coverage: CoveragePartial,
					Covers:     []string{"tool results"},
					NotCovered: []string{"model requests", "model replies", "network egress"},
					Files:      []string{"/home/u/.claude/settings.json", "/home/u/.codex/hooks.json"},
					Manifest:   "/home/u/.local/state/scrim/agent-hooks.json"},
				{Mode: AgentModeManaged, Agents: []string{"claude", "codex"}, Coverage: CoverageAddOn,
					Covers:     []string{"endpoint pinned"},
					NotCovered: []string{"processes the agent starts"},
					Files:      []string{"/etc/claude-code/managed-settings.d/90-scrim.json", "/etc/codex/requirements.toml"},
					Changed:    []string{"/etc/codex/requirements.toml"},
					Manifest:   "/etc/scrim/managed-settings.json"},
			},
		},
		// scrim run on a host without user namespaces: the home mirror.
		"run-fs-view-fallback": {
			Version:   "0.1.0",
			DataPlane: fakeDP{Running: true, PID: 7, Healthy: true},
			State:     fakeState{Backend: "memory", Healthy: true},
			RunView: &RunView{Requested: "auto", Mode: "home", Fallback: "darwin has no user or mount namespaces",
				Gaps: []string{"tools that find the home directory through the password database instead of HOME (ssh) read the real files"}},
		},
		// run.fs-view: namespace on a host without user namespaces.
		"run-fs-view-refused": {
			Version:   "0.1.0",
			DataPlane: fakeDP{Running: true, PID: 7, Healthy: true},
			State:     fakeState{Backend: "memory", Healthy: true},
			RunView:   &RunView{Requested: "namespace", Mode: RunViewRefused, Fallback: "creating a user namespace is not allowed: operation not permitted"},
		},
		// Weakened settings taken from the configuration manager.
		"config-weakened": {
			Version: "0.1.0",
			Config: fakeConfig{Version: 1, Profile: "ci", LoadedAt: refreshed, Weakened: []config.WeakenedSetting{{
				Key: "policy.default", Value: "allow", Source: "env:SCRIM_POLICY_DEFAULT",
				Description: "Decision when no rule matches.",
			}}},
			DataPlane: fakeDP{Running: true, PID: 7, Healthy: true},
			State:     fakeState{Backend: "memory", Healthy: true},
		},
	}
}

func TestStatusGolden(t *testing.T) {
	for name, src := range fixtures() {
		t.Run(name, func(t *testing.T) {
			r := Collect(context.Background(), src)
			var human, js bytes.Buffer
			if err := WriteHuman(&human, r); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(&js, r); err != nil {
				t.Fatal(err)
			}
			golden(t, "status-"+name+".txt", human.Bytes())
			golden(t, "status-"+name+".json", js.Bytes())

			d := Diagnose(context.Background(), time.Second, ReportChecks(r)...)
			var dh, dj bytes.Buffer
			if err := WriteDiagnosis(&dh, d); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(&dj, d); err != nil {
				t.Fatal(err)
			}
			golden(t, "doctor-"+name+".txt", dh.Bytes())
			golden(t, "doctor-"+name+".json", dj.Bytes())
		})
	}
}

func TestWeakenedInDedicatedJSONField(t *testing.T) {
	r := Collect(context.Background(), fixtures()["degraded"])
	var js bytes.Buffer
	_ = WriteJSON(&js, r)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(js.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	var weak []Weakened
	if err := json.Unmarshal(m["weakened_protections"], &weak); err != nil || len(weak) != 2 {
		t.Fatalf("weakened_protections = %s, %v", m["weakened_protections"], err)
	}
	var human bytes.Buffer
	_ = WriteHuman(&human, r)
	section := human.String()[strings.Index(human.String(), "Weakened protections"):] //nolint:gocritic // WriteHuman always writes this heading
	if !strings.Contains(section, "state.sqlite.allow-network-filesystem") {
		t.Fatalf("weakened setting not listed under weakened protections:\n%s", section)
	}
}

func TestDegradedDerivation(t *testing.T) {
	r := Collect(context.Background(), fixtures()["degraded"])
	got := map[string]bool{}
	for _, c := range r.Degraded {
		got[c.Name] = true
	}
	for _, want := range []string{"data-plane", "state:postgres", "store:vw", "store:inf", "audit:kafka", "protection:redaction", "config"} {
		if !got[want] {
			t.Errorf("degraded lacks %s: %v", want, r.Degraded)
		}
	}
	if got["store:bao"] || got["audit:db"] {
		t.Errorf("healthy components reported degraded: %v", r.Degraded)
	}
	if r.OK() {
		t.Error("degraded report is OK")
	}
	if !Collect(context.Background(), fixtures()["healthy"]).OK() {
		t.Error("healthy report is not OK")
	}
	// Missing sources never read as healthy.
	if e := Collect(context.Background(), Sources{}); e.OK() {
		t.Error("a report with no data plane or state source is OK")
	}
}

func TestDoctorExitSignal(t *testing.T) {
	d := Diagnose(context.Background(), time.Second, ReportChecks(Collect(context.Background(), fixtures()["degraded"]))...)
	if d.OK() || d.Failed == 0 {
		t.Fatalf("degraded setup passed doctor: %+v", d)
	}
	h := Diagnose(context.Background(), time.Second, ReportChecks(Collect(context.Background(), fixtures()["healthy"]))...)
	if !h.OK() || h.Warned != 0 {
		t.Fatalf("healthy setup failed doctor: %+v", h)
	}
}

func TestDoctorCheckTimeoutAndCA(t *testing.T) {
	hang := Check{Name: "hang", Run: func(ctx context.Context) []Finding { <-ctx.Done(); time.Sleep(time.Millisecond); return nil }}
	// A CA-trust check as the interception package would contribute it.
	ca := Check{Name: "ca-trust:python", Run: func(context.Context) []Finding {
		return []Finding{{Outcome: Fail, Message: "python (certifi) does not trust the scrim CA",
			Fix: "scrim ca install --runtime python"}}
	}}
	d := Diagnose(context.Background(), 20*time.Millisecond, hang, ca)
	if d.Failed != 2 {
		t.Fatalf("failed = %d, want 2: %+v", d.Failed, d)
	}
	var out bytes.Buffer
	_ = WriteDiagnosis(&out, d)
	if !strings.Contains(out.String(), "fix: scrim ca install --runtime python") {
		t.Fatalf("doctor output lacks the fix:\n%s", out.String())
	}
}

func TestStateLocationCheck(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scrim")
	if fs := StateLocationCheck(filepath.Join(dir, "state.db")).Run(context.Background()); len(fs) != 1 || fs[0].Outcome != Warn {
		t.Fatalf("missing dir: %+v", fs)
	}
	if err := os.Mkdir(dir, 0o755); err != nil { // #nosec G301 -- testing the check
		t.Fatal(err)
	}
	db := filepath.Join(dir, "state.db")
	if err := os.WriteFile(db, nil, 0o644); err != nil { // #nosec G306 -- testing the check
		t.Fatal(err)
	}
	fspermtest.Open(t, dir)
	fspermtest.Open(t, db)
	dirFix, fileFix := "chmod 0700", "chmod 0600"
	if runtime.GOOS == "windows" {
		dirFix, fileFix = "icacls", "icacls"
	}
	fs := StateLocationCheck(db).Run(context.Background())
	if len(fs) != 2 || fs[0].Outcome != Fail || !strings.Contains(fs[0].Fix, dirFix) ||
		!strings.Contains(fs[1].Fix, fileFix) {
		t.Fatalf("open perms: %+v", fs)
	}
	if runtime.GOOS == "windows" {
		_ = fsperm.Restrict(dir)
		_ = fsperm.Restrict(db)
	} else {
		_ = os.Chmod(dir, 0o700)
		_ = os.Chmod(db, 0o600)
	}
	if fs := StateLocationCheck(db).Run(context.Background()); len(fs) != 0 {
		t.Fatalf("private perms: %+v", fs)
	}
}

func TestWeakenedFromConfigManager(t *testing.T) {
	r := Collect(context.Background(), fixtures()["config-weakened"])
	if len(r.Weakened) != 1 || r.Weakened[0].Key != "policy.default" || r.Profile != "ci" {
		t.Fatalf("report = %+v", r)
	}
}

// TestEmptyRedactTargetIsReported: a target with 0 values is printed as
// empty, the store is degraded and doctor warns that it protects nothing.
func TestEmptyRedactTargetIsReported(t *testing.T) {
	r := Collect(context.Background(), Sources{Stores: fakeStores{{
		Name: "local", Kind: "env", Reachable: true, Degraded: true, Reason: "redact target local://X_* holds no values",
		Targets: []StoreTarget{{Target: "local://X_*", Values: 0}, {Target: "local://Y", Values: 1}},
	}}})
	var human bytes.Buffer
	if err := WriteHuman(&human, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human.String(), "redact local://X_*") || !strings.Contains(human.String(), "EMPTY") {
		t.Fatalf("human output:\n%s", human.String())
	}
	if !slices.ContainsFunc(r.Degraded, func(c Component) bool { return c.Name == "store:local" }) {
		t.Fatalf("degraded = %+v", r.Degraded)
	}
	var found bool
	for _, c := range ReportChecks(r) {
		if c.Name != "store:local" {
			continue
		}
		for _, f := range c.Run(context.Background()) {
			found = found || (f.Outcome == Warn && strings.Contains(f.Message, "local://X_* holds 0 values"))
		}
	}
	if !found {
		t.Fatal("doctor does not warn about the empty target")
	}
}

// TestHooksOnlyIsPartial is the interception spec scenario "Status in
// hooks-only mode": status reports protection as partial and lists what is
// not covered; doctor warns.
func TestHooksOnlyIsPartial(t *testing.T) {
	src := fixtures()["hooks-only"]
	src.AgentModes = src.AgentModes[:1]
	r := Collect(context.Background(), src)
	if r.Coverage != CoveragePartial {
		t.Fatalf("coverage = %q", r.Coverage)
	}
	var human bytes.Buffer
	if err := WriteHuman(&human, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"protection: PARTIAL", "not covered: model replies", "not covered: network egress"} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("status lacks %q:\n%s", want, human.String())
		}
	}
	d := Diagnose(context.Background(), time.Second, ReportChecks(r)...)
	found := false
	for _, f := range d.Findings {
		if f.Check == "agent-mode:hooks" && f.Outcome == Warn && strings.Contains(f.Message, "partial") {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor findings = %+v", d.Findings)
	}
	// A bound listener alone does not carry an agent's traffic.
	src.Runtime = fakeRuntime{modes: []string{"base-url http://127.0.0.1:9790", "forward-proxy http://127.0.0.1:9791"}}
	if r := Collect(context.Background(), src); r.Coverage != CoveragePartial {
		t.Fatalf("coverage with listeners only = %q", r.Coverage)
	}
	// A wrapped session does: hooks are an extra.
	src.Runtime = fakeRuntime{modes: []string{"wrapper (1 scrim run session(s))"}}
	if r := Collect(context.Background(), src); r.Coverage != "" {
		t.Fatalf("coverage with the wrapper = %q", r.Coverage)
	}
}
