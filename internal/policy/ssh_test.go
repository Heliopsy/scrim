// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

func sshRules(t *testing.T, yaml string) *RuleSet {
	t.Helper()
	c, err := Parse([]byte(yaml), false)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestSSHAttributes(t *testing.T) {
	rs := sshRules(t, `default: deny
rules:
  - name: git-login
    decision: allow
    when: op == "ssh.sign" && ssh.kind == "userauth" && ssh.user == "git" && ssh.host_key == "SHA256:host"
  - name: commit-signing
    decision: ask
    when: op == "ssh.sign" && ssh.kind == "sshsig" && ssh.namespace == "git" && ssh.key.startsWith("SHA256:")
`)
	agent := Agent{ID: "dev", Kind: IdentitySession}
	ref := stores.MustParseRef("mem://ssh/deploy")
	for _, tc := range []struct {
		name string
		ssh  SSHRequest
		want Effect
	}{
		{"login", SSHRequest{Kind: SSHKindUserauth, User: "git", Key: "SHA256:k", HostKey: "SHA256:host"}, Allow},
		{"other user", SSHRequest{Kind: SSHKindUserauth, User: "root", Key: "SHA256:k", HostKey: "SHA256:host"}, Deny},
		{"unbound host", SSHRequest{Kind: SSHKindUserauth, User: "git", Key: "SHA256:k"}, Deny},
		{"commit", SSHRequest{Kind: SSHKindSSHSig, Namespace: "git", Key: "SHA256:k"}, Ask},
		{"file signature", SSHRequest{Kind: SSHKindSSHSig, Namespace: "file", Key: "SHA256:k"}, Deny},
	} {
		got := rs.Evaluate(Request{Agent: agent, Action: ActionSign, Ref: ref, SSH: tc.ssh})
		if got.Effect != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.name, got.Effect, got.Rule, tc.want)
		}
	}
	// Other operations see empty ssh fields.
	if got := rs.Evaluate(Request{Agent: agent, Action: ActionInject, Ref: ref}); got.Effect != Deny || !got.Default {
		t.Errorf("inject: %+v", got)
	}
}

func TestSSHRulesStayOffTheDataPlane(t *testing.T) {
	rs := sshRules(t, `rules:
  - name: git-login
    decision: allow
    when: ssh.user == "git"
`)
	snap := rs.Snapshot(1, false)
	if c := snap.Rules[0].Clauses; len(c) != 1 || !c[0].Residual {
		t.Fatalf("a rule on ssh.* must be residual for the data plane, got %+v", c)
	}
}

func TestMayAllow(t *testing.T) {
	agent := Agent{ID: "dev", Kind: IdentitySession}
	deploy := stores.MustParseRef("mem://ssh/deploy")
	other := stores.MustParseRef("mem://ssh/other")
	unknown := []string{"ssh.user", "ssh.kind", "ssh.namespace"}
	list := func(ref stores.Ref, host string) Request {
		return Request{Agent: agent, Action: ActionSign, Ref: ref, Host: host,
			SSH: SSHRequest{Kind: SSHKindList, Key: "SHA256:k"}}
	}
	for _, tc := range []struct {
		name, rules string
		req         Request
		want        bool
	}{
		{"allow on user is possible", `default: deny
rules:
  - {name: a, decision: allow, when: 'op == "ssh.sign" && ssh.user == "git"'}`, list(deploy, ""), true},
		{"ask on kind is possible", `default: deny
rules:
  - {name: a, decision: ask, when: 'op == "ssh.sign" && ssh.kind == "userauth"'}`, list(deploy, ""), true},
		{"known part decides", `default: deny
rules:
  - {name: a, decision: allow, when: 'op == "ssh.sign" && secret.ref == "mem://ssh/deploy" && ssh.user == "git"'}`, list(other, ""), false},
		{"deny on unknown does not hide", `default: allow
rules:
  - {name: d, decision: deny, when: 'ssh.user == "root"'}`, list(deploy, ""), true},
		{"deny on known hides", `default: allow
rules:
  - {name: d, decision: deny, when: 'dest.host != "github.com"'}`, list(deploy, "gitlab.com"), false},
		{"host known at list time", `default: deny
rules:
  - {name: a, decision: allow, when: 'dest.host == "github.com" && ssh.user == "git"'}`, list(deploy, "github.com"), true},
		{"default deny", `default: deny`, list(deploy, ""), false},
		{"error in allow is not a match", `default: deny
rules:
  - {name: a, decision: allow, when: 'agent.labels.team == "x"'}`, list(deploy, ""), false},
	} {
		rs := sshRules(t, tc.rules)
		if got := rs.MayAllow(tc.req, unknown...); got != tc.want {
			t.Errorf("%s: MayAllow = %v, want %v", tc.name, got, tc.want)
		}
	}
	if sshRules(t, "default: allow").MayAllow(list(deploy, ""), "nodot") {
		t.Error("a malformed attribute must not allow")
	}
}
