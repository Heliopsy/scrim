// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestEBPFOnlyVerifiedCounts: a control group confirmed with the kernel adds
// an interception mode and turns the direct egress protection on; one that
// only the loader's record names, or that is not attached, does neither and
// is reported degraded (specs/interception "Loader not available").
func TestEBPFOnlyVerifiedCounts(t *testing.T) {
	active := Collect(context.Background(), fixtures()["ebpf-active"])
	if !slices.ContainsFunc(active.Interception, func(m string) bool { return strings.HasPrefix(m, "ebpf cgroup agents.slice") }) {
		t.Errorf("interception = %v", active.Interception)
	}
	if i := slices.IndexFunc(active.Protections, func(p Protection) bool { return p.Name == egressProtection }); i < 0 ||
		!active.Protections[i].Active || !strings.Contains(active.Protections[i].Detail, "agents.slice") {
		t.Errorf("protections = %+v", active.Protections)
	}
	if !active.OK() {
		t.Errorf("degraded = %+v", active.Degraded)
	}

	missing := Collect(context.Background(), fixtures()["ebpf-missing"])
	for _, m := range missing.Interception {
		if strings.Contains(m, "ebpf") {
			t.Errorf("unconfirmed eBPF reported as a mode: %v", missing.Interception)
		}
	}
	if slices.ContainsFunc(missing.Protections, func(p Protection) bool { return p.Name == egressProtection && p.Active }) {
		t.Errorf("unconfirmed eBPF blocks egress: %+v", missing.Protections)
	}
	var names []string
	for _, c := range missing.Degraded {
		names = append(names, c.Name)
	}
	for _, want := range []string{"ebpf:agents.slice", "ebpf:ci.slice", "ebpf-listener"} {
		if !slices.Contains(names, want) {
			t.Errorf("degraded lacks %s: %v", want, names)
		}
	}
	d := Diagnose(context.Background(), time.Second, ReportChecks(missing)...)
	var msgs []string
	for _, f := range d.Findings {
		if f.Check == "ebpf" {
			msgs = append(msgs, string(f.Outcome)+" "+f.Message)
		}
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"fail agents.slice: not attached", "CAP_BPF and CAP_NET_ADMIN", "warn ci.slice", "fail nothing accepts"} {
		if !strings.Contains(joined, want) {
			t.Errorf("doctor ebpf findings lack %q:\n%s", want, joined)
		}
	}
	if d.OK() {
		t.Error("doctor passes with an unattached control group")
	}
}

func TestEBPFProblem(t *testing.T) {
	r := Collect(context.Background(), Sources{EBPF: fakeEBPF{Configured: []string{"a.slice"}, Problem: "no cgroup v2 hierarchy",
		Cgroups: []EBPFCgroup{{Cgroup: "a.slice", State: "not-attached", Detail: "not attached"}}}})
	if !slices.ContainsFunc(r.Degraded, func(c Component) bool { return c.Name == "ebpf" }) {
		t.Fatalf("degraded = %+v", r.Degraded)
	}
	d := Diagnose(context.Background(), time.Second, ReportChecks(r)...)
	if !slices.ContainsFunc(d.Findings, func(f Finding) bool { return f.Check == "ebpf" && f.Outcome == Fail }) {
		t.Fatalf("findings = %+v", d.Findings)
	}
}
