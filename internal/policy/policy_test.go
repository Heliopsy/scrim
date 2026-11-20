// SPDX-License-Identifier: AGPL-3.0-only

package policy_test

import (
	"context"
	"testing"

	"github.com/heliopsy/scrim/internal/policy"
)

func TestZeroDecisionDenies(t *testing.T) {
	var d policy.Decision
	if d.Allowed() || d.Effect != policy.Deny {
		t.Fatal("zero decision must deny")
	}
}

func TestEffectText(t *testing.T) {
	for _, e := range []policy.Effect{policy.Allow, policy.Deny, policy.Ask} {
		b, _ := e.MarshalText()
		var back policy.Effect
		if err := back.UnmarshalText(b); err != nil || back != e {
			t.Fatalf("round trip %v", e)
		}
	}
	if _, err := policy.ParseEffect("permit"); err == nil {
		t.Fatal("unknown effect accepted")
	}
}

func TestCombine(t *testing.T) {
	allow := policy.Decision{Effect: policy.Allow, Rule: "a"}
	ask := policy.Decision{Effect: policy.Ask, Rule: "b"}
	deny := policy.Decision{Effect: policy.Deny, Rule: "c"}
	cases := []struct {
		in   []policy.Decision
		want string
	}{
		{[]policy.Decision{allow, ask}, "b"},
		{[]policy.Decision{ask, allow, deny}, "c"},
		{[]policy.Decision{allow, {Effect: policy.Allow, Rule: "a2"}}, "a"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := policy.Combine(c.in...); got.Rule != c.want {
			t.Errorf("Combine(%v) = %q, want %q", c.in, got.Rule, c.want)
		}
	}
}

func TestRules(t *testing.T) {
	ctx := context.Background()
	eng := policy.Rules{
		List: []policy.Rule{
			{Name: "gh-api", Effect: policy.Allow, Match: func(r policy.Request) bool { return r.Host == "api.github.com" }},
			{Name: "gh-push", Effect: policy.Ask, Match: func(r policy.Request) bool { return r.Host == "api.github.com" && r.Method == "POST" }},
		},
		Default: policy.Static{Effect: policy.Deny},
	}
	d, _ := eng.Decide(ctx, policy.Request{Host: "api.github.com", Method: "GET"})
	if d.Effect != policy.Allow || d.Rule != "gh-api" {
		t.Fatalf("GET: %+v", d)
	}
	d, _ = eng.Decide(ctx, policy.Request{Host: "api.github.com", Method: "POST"})
	if d.Effect != policy.Ask || d.Rule != "gh-push" {
		t.Fatalf("POST: %+v", d)
	}
	d, _ = eng.Decide(ctx, policy.Request{Host: "evil.example"})
	if d.Effect != policy.Deny || d.Rule != "default" || d.Reason == "" {
		t.Fatalf("unmatched: %+v", d)
	}
}

func TestBreakGlass(t *testing.T) {
	on := true
	eng := policy.BreakGlass{Engine: policy.Static{Effect: policy.Allow}, Active: func() bool { return on }}
	if d, _ := eng.Decide(context.Background(), policy.Request{}); d.Effect != policy.Deny || d.Rule != "break-glass" {
		t.Fatalf("break-glass on: %+v", d)
	}
	on = false
	if d, _ := eng.Decide(context.Background(), policy.Request{}); d.Effect != policy.Allow {
		t.Fatalf("break-glass off: %+v", d)
	}
}
