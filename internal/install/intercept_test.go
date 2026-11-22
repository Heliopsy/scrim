// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// javaHost answers keytool -list for the managed store with the CA's
// fingerprint once update-ca-certificates ran (what Debian's
// ca-certificates-java hook does), and nothing for the JDK's own store.
type javaHost struct {
	*fakeHost
	managed string
	trusted bool
	fp      string
	// imported are the stores keytool -importcert added the CA to.
	imported map[string]bool
}

func (j *javaHost) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := j.fakeHost.Run(ctx, name, args...)
	store := ""
	for i, a := range args {
		if a == "-keystore" && i+1 < len(args) {
			store = args[i+1]
		}
	}
	switch {
	case strings.HasSuffix(name, "keytool") && len(args) > 0 && args[0] == "-importcert":
		j.imported[store] = true
	case strings.HasSuffix(name, "keytool") && len(args) > 0 && args[0] == "-delete":
		delete(j.imported, store)
	case strings.HasSuffix(name, "keytool") && len(args) > 0 && args[0] == "-list" && j.imported[store]:
		return []byte("scrim-ca, 1 Jan 2026, trustedCertEntry,\nCertificate fingerprint (SHA-256): " + j.fp + "\n"), nil
	case name == "update-ca-certificates" && len(args) == 0:
		j.trusted = true
	case name == "update-ca-certificates":
		j.trusted = false
	case strings.HasSuffix(name, "keytool") && len(args) > 0 && args[0] == "-list" && strings.Contains(strings.Join(args, " "), j.managed) && j.trusted:
		return []byte("debian:scrim-ca.pem, 1 Jan 2026, trustedCertEntry,\nCertificate fingerprint (SHA-256): " + j.fp + "\n"), nil
	}
	return out, err
}

func interceptHost(t *testing.T) (*fakeHost, *javaHost) {
	t.Helper()
	h := newFakeHost(t)
	h.tools["nft"] = true
	h.write("etc/passwd", h.read("etc/passwd")+"agent1:x:1001:1001::/home/agent1:/bin/bash\n")
	h.write("etc/hosts", "127.0.0.1 localhost\n::1 localhost") // no trailing newline on purpose
	for _, d := range []string{"etc/ssl/certs/java", "usr/lib/jvm/jdk-21/lib/security", "usr/lib/jvm/jdk-21/bin",
		"usr/lib/jvm/temurin/lib/security", "usr/lib/jvm/temurin/bin", "proc/net"} {
		if err := os.MkdirAll(filepath.Join(h.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.write("etc/ssl/certs/java/cacerts", "managed store")
	if err := os.Symlink(filepath.Join(h.root, "etc/ssl/certs/java/cacerts"), filepath.Join(h.root, "usr/lib/jvm/jdk-21/lib/security/cacerts")); err != nil {
		t.Fatal(err)
	}
	h.write("usr/lib/jvm/temurin/lib/security/cacerts", "own store")
	h.write("usr/lib/jvm/temurin/bin/keytool", "")
	h.write("proc/net/if_inet6", "00000000000000000000000000000001 01 80 10 80       lo\n")
	fp, _, err := fingerprint(fakeProbe{}.caPEM())
	if err != nil {
		t.Fatal(err)
	}
	return h, &javaHost{fakeHost: h, managed: "/etc/ssl/certs/java/cacerts", fp: fp, imported: map[string]bool{}}
}

func (fakeProbe) caPEM() string {
	s, _ := fakeProbe{}.CA(context.Background(), "")
	return s
}

func TestTransparentAndDNSInstallAndUninstallLeaveNoTrace(t *testing.T) {
	h, j := interceptHost(t)
	h.started = func() { _ = os.MkdirAll(filepath.Join(h.root, "var/lib/scrim"), 0o700) }
	before := snapshot(t, h.root)
	var out bytes.Buffer
	in := h.system(t, ModeSystem, &out)
	in.Runner = j
	in.Intercept = Interception{Transparent: true, CoverUsers: []string{"agent1"}, CoverCgroups: []string{"agents.slice"},
		DNS: true, DNSHosts: []string{"api.anthropic.com", "api.openai.com"}}
	if err := in.Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	rules := h.read("etc/scrim/transparent.nft")
	for _, want := range []string{
		"table inet scrim {", "meta skuid 900 return", "ip daddr 127.0.0.0/8 return", "ip6 daddr ::1 return",
		"meta skuid { 1001 } tcp dport { 80, 443 } redirect to :9793",
		`socket cgroupv2 level 1 "agents.slice" tcp dport { 80, 443 } redirect to :9793`,
		"meta skuid { 1001 } tcp dport { 80, 443 } reject with tcp reset", "meta skuid { 1001 } udp dport 443 reject",
		"meta skuid 900 accept",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("rules lack %q:\n%s", want, rules)
		}
	}
	unit := h.read("etc/systemd/system/scrim-transparent.service")
	for _, want := range []string{"ExecStart=/usr/bin/nft -f /etc/scrim/transparent.nft", "ExecStop=-/usr/bin/nft delete table inet scrim",
		"RemainAfterExit=yes", "Wants=agents.slice", "Before=network-pre.target scrim.service"} {
		if !strings.Contains(unit, want) {
			t.Errorf("rules unit lacks %q:\n%s", want, unit)
		}
	}
	drop := h.read("etc/systemd/system/scrim.service.d/interception.conf")
	for _, want := range []string{"Environment=SCRIM_PROXY_TRANSPARENT_LISTEN=127.0.0.1:9793,[::1]:9793",
		"Environment=SCRIM_PROXY_SNI_LISTEN=127.0.83.1:443", "AmbientCapabilities=CAP_NET_BIND_SERVICE"} {
		if !strings.Contains(drop, want) {
			t.Errorf("drop-in lacks %q:\n%s", want, drop)
		}
	}
	hosts := h.read("etc/hosts")
	if !strings.Contains(hosts, "::1 localhost\n"+hostsBegin+"\n127.0.83.1 api.anthropic.com api.openai.com\n"+hostsEnd+"\n") {
		t.Errorf("hosts:\n%s", hosts)
	}
	temurin := filepath.Join(h.root, "usr/lib/jvm/temurin/lib/security/cacerts")
	checkOrder(t, h.calls, []string{
		"systemctl enable --now scrim.service", "update-ca-certificates",
		filepath.Join(h.root, "usr/lib/jvm/temurin/bin/keytool") + " -importcert -noprompt -trustcacerts -alias scrim-ca",
		"systemctl enable --now scrim-transparent.service", "nft list table inet scrim",
	})
	for _, c := range h.calls {
		if strings.Contains(c, "-importcert") && strings.Contains(c, "/etc/ssl/certs/java/cacerts") {
			t.Errorf("imported into the store the trust tool rebuilds: %s", c)
		}
	}
	if !strings.Contains(out.String(), "rebuilt by the system trust tool, trusts the scrim CA") {
		t.Errorf("managed Java store not reported:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "connecting by address bypasses it") {
		t.Errorf("DNS gap not reported:\n%s", out.String())
	}

	// A second install changes nothing and restarts nothing.
	h.calls = nil
	again := h.system(t, ModeSystem, &out)
	again.Runner = j
	again.Executable = in.Executable
	again.Intercept = in.Intercept
	if err := again.Install(context.Background()); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if c := strings.Join(h.calls, "\n"); strings.Contains(c, "restart") || strings.Contains(c, "-importcert") {
		t.Errorf("second install changed things:\n%s", c)
	}

	h.calls = nil
	out.Reset()
	un := h.system(t, "", &out)
	un.Runner = j
	un.Purge = true
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}
	checkOrder(t, h.calls, []string{
		"nft delete table inet scrim", "systemctl disable --now scrim-transparent.service",
		filepath.Join(h.root, "usr/lib/jvm/temurin/bin/keytool") + " -delete -alias scrim-ca -keystore " + temurin,
		"update-ca-certificates --fresh", "systemctl disable --now scrim.service",
	})
	if d := diff(before, snapshot(t, h.root)); len(d) > 0 {
		t.Errorf("uninstall left traces: %v\n%s", d, out.String())
	}
	if h.read("etc/hosts") != "127.0.0.1 localhost\n::1 localhost" {
		t.Errorf("hosts not restored: %q", h.read("etc/hosts"))
	}
}

func TestInterceptionChecks(t *testing.T) {
	h, _ := interceptHost(t)
	cases := []struct {
		name string
		mode Mode
		ic   Interception
		want string
	}{
		{"user unit", ModeUser, Interception{Transparent: true, CoverUsers: []string{"agent1"}}, "need the system service"},
		{"nobody covered", ModeSystem, Interception{Transparent: true}, "at least one --cover-user"},
		{"scrim covered", ModeSystem, Interception{Transparent: true, CoverUsers: []string{"scrim"}}, "back to itself"},
		{"unknown user", ModeSystem, Interception{Transparent: true, CoverUsers: []string{"ghost"}}, "does not exist"},
		{"bad cgroup", ModeSystem, Interception{Transparent: true, CoverCgroups: []string{"../x"}}, "control group path"},
		{"bad host", ModeSystem, Interception{DNS: true, DNSHosts: []string{"api anthropic"}}, "not a host name"},
		{"not loopback", ModeSystem, Interception{DNS: true, DNSHosts: []string{"a.test"}, DNSAddress: "10.0.0.1"}, "loopback"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			in := h.system(t, c.mode, &out)
			in.System = c.mode != ModeUser
			in.Intercept = c.ic
			err := in.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestEditedHostsBlockIsLeftAndReported(t *testing.T) {
	h, j := interceptHost(t)
	var out bytes.Buffer
	in := h.system(t, ModeSystem, &out)
	in.Runner = j
	in.Intercept = Interception{DNS: true, DNSHosts: []string{"api.anthropic.com"}}
	if err := in.Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	h.write("etc/hosts", strings.Replace(h.read("etc/hosts"), "api.anthropic.com", "api.anthropic.com evil.test", 1))
	un := h.system(t, "", &out)
	un.Runner = j
	if err := un.Uninstall(context.Background()); err == nil {
		t.Fatal("uninstall succeeded over an edited hosts block")
	}
	if !strings.Contains(out.String(), "remove the lines from") || !strings.Contains(h.read("etc/hosts"), "evil.test") {
		t.Errorf("edited block not kept and reported:\n%s", out.String())
	}
}

func TestAliasOf(t *testing.T) {
	list := "Keystore type: JKS\n\nYour keystore contains 2 entries\n\nother, 1 Jan 2026, trustedCertEntry,\nCertificate fingerprint (SHA-256): AA:BB\ndebian:scrim-ca.pem, 1 Jan 2026, trustedCertEntry,\nCertificate fingerprint (SHA-256): CC:DD\n"
	if got := aliasOf(list, "CC:DD"); got != "debian:scrim-ca.pem" {
		t.Errorf("alias = %q", got)
	}
	if got := aliasOf(list, "EE:FF"); got != "" {
		t.Errorf("alias = %q", got)
	}
}

// TestRulesParse checks the rule set with nft itself, in a new user and
// network namespace (never the host's rules). Skipped where unshare or nft
// is missing or user namespaces are off.
func TestRulesParse(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
	p := filepath.Join(t.TempDir(), "rules.nft")
	if err := os.WriteFile(p, []byte(Rules(999, []int{1001, 1002}, nil, 9792)), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := exec.Command("unshare", "-rn", nft, "list", "ruleset") // #nosec G204 -- test
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("no user and network namespace for nft: %v: %s", err, out)
	}
	cmd := exec.Command("unshare", "-rn", nft, "-c", "-f", p) // #nosec G204 -- test
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejects the rule set: %v\n%s", err, out)
	}
}
