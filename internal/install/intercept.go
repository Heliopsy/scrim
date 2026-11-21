// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Host-level interception (specs/interception "Transparent mode with
// packet filtering", "DNS override mode", "CA trust installation"): the
// nftables rules of the transparent mode, the /etc/hosts block of the DNS
// override, the drop-in that turns on their listeners, and the Java
// truststores. Each change is shown first and recorded in the manifest like
// the rest of a system install.

// Paths and names of the interception modes.
const (
	// DropInPath turns on the transparent and SNI listeners of the system
	// unit (and lets it bind port 443 for the DNS override).
	DropInPath = "/etc/systemd/system/scrim.service.d/interception.conf"
	// RulesPath is the nftables rule set of the transparent mode.
	RulesPath = "/etc/scrim/transparent.nft"
	// RulesUnit loads the rule set at boot and removes it when stopped. It
	// is independent of scrim.service, so the rules stay (and fail closed)
	// while scrim is stopped.
	RulesUnit     = "scrim-transparent.service"
	RulesUnitPath = "/etc/systemd/system/" + RulesUnit
	// NFTable is the nftables table holding every rule scrim adds.
	NFTable = "inet scrim"
	// HostsPath is the hosts file the DNS override adds its block to.
	HostsPath = "/etc/hosts"
	// DefaultTransparentPort is the port nftables redirects covered
	// connections to, on 127.0.0.1 and ::1.
	DefaultTransparentPort = 9792
	// DefaultDNSAddress is the loopback address provider names resolve to
	// in DNS override mode; the SNI listener binds port 443 on it.
	DefaultDNSAddress = "127.0.83.1"
	// javaStorePass is the JDK's documented default truststore password
	// (keytool's "changeit"). Truststores hold public certificates only.
	javaStorePass = "changeit"
	// JavaAlias names the scrim CA in a Java truststore scrim imports it into.
	JavaAlias = "scrim-ca"

	hostsBegin = "# BEGIN scrim install --dns: provider names resolve to scrim (scrim uninstall --system removes this block)"
	hostsEnd   = "# END scrim install --dns"
)

// Environment variables of the settings the drop-in sets (daemon
// proxy.transparent-listen, proxy.transparent-unrouted, proxy.sni-listen).
const (
	EnvTransparentListen   = "SCRIM_PROXY_TRANSPARENT_LISTEN"
	EnvTransparentUnrouted = "SCRIM_PROXY_TRANSPARENT_UNROUTED"
	EnvSNIListen           = "SCRIM_PROXY_SNI_LISTEN"
)

// Entry kinds of the interception modes.
const (
	// KindNFTable is the nftables table scrim added; reverted with nft
	// delete table.
	KindNFTable = "nftables"
	// KindHosts is the block of lines added to the hosts file; reverted by
	// removing exactly that block.
	KindHosts = "hosts-block"
	// KindJavaTrust is the scrim CA imported into a Java truststore that
	// the system trust tool does not rebuild; reverted with keytool -delete.
	KindJavaTrust = "java-trust"
)

// managedJavaStores are the Java truststores the system trust tools
// rebuild from the system anchors (Debian's ca-certificates-java hook of
// update-ca-certificates, update-ca-trust extract on Fedora and RHEL).
var managedJavaStores = []string{"/etc/ssl/certs/java/cacerts", "/etc/pki/ca-trust/extracted/java/cacerts"}

// Interception selects the host-level modes of a system install.
type Interception struct {
	// Transparent installs the nftables redirect for CoverUsers and
	// CoverCgroups (paths below /sys/fs/cgroup, such as agents.slice).
	Transparent  bool
	CoverUsers   []string
	CoverCgroups []string
	// Port is the transparent listener's port; zero is
	// DefaultTransparentPort.
	Port int
	// BlockUnrouted closes connections to hosts scrim has no route for.
	BlockUnrouted bool
	// DNS adds DNSHosts to the hosts file, resolving to DNSAddress.
	DNS        bool
	DNSHosts   []string
	DNSAddress string
	// JavaHomes are extra JDKs whose truststores get the CA (with
	// Transparent or DNS); JDKs under /usr/lib/jvm are found on their own.
	JavaHomes []string
}

// Active reports whether any host-level mode is selected.
func (i Interception) Active() bool { return i.Transparent || i.DNS }

func (i Interception) port() int {
	if i.Port == 0 {
		return DefaultTransparentPort
	}
	return i.Port
}

func (i Interception) dnsAddress() string {
	if i.DNSAddress == "" {
		return DefaultDNSAddress
	}
	return i.DNSAddress
}

func (in *Installer) checkInterception() error {
	ic := in.Intercept
	if !ic.Active() {
		return nil
	}
	if in.Mode != ModeSystem {
		return errors.New("install: --transparent and --dns need the system service (--system), not a user unit or Quadlet container")
	}
	if ic.Transparent && len(ic.CoverUsers) == 0 && len(ic.CoverCgroups) == 0 {
		return errors.New("install: --transparent needs at least one --cover-user or --cover-cgroup")
	}
	for _, u := range ic.CoverUsers {
		if u == ServiceUser {
			return fmt.Errorf("install: --cover-user %s would redirect scrim's own upstream connections back to itself", u)
		}
		if _, ok, err := in.user(u); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("install: --cover-user %s does not exist", u)
		}
	}
	for _, c := range ic.CoverCgroups {
		if _, err := cgroupPath(c); err != nil {
			return err
		}
	}
	if ic.Port < 0 || ic.Port > 65535 {
		return fmt.Errorf("install: --transparent-port %d is not a port", ic.Port)
	}
	if ic.DNS {
		if len(ic.DNSHosts) == 0 {
			return errors.New("install: --dns has no provider host names to override")
		}
		for _, h := range ic.DNSHosts {
			if !validHostName(h) {
				return fmt.Errorf("install: --dns-host %q is not a host name", h)
			}
		}
		if !strings.HasPrefix(ic.dnsAddress(), "127.") {
			return fmt.Errorf("install: --dns-address %s must be a loopback address (127.0.0.0/8)", ic.dnsAddress())
		}
	}
	return nil
}

func validHostName(h string) bool {
	if h == "" || len(h) > 253 || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// cgroupPath normalises a control group path relative to /sys/fs/cgroup.
func cgroupPath(c string) (string, error) {
	c = strings.Trim(strings.TrimPrefix(c, "/sys/fs/cgroup"), "/")
	if c == "" || strings.Contains(c, "..") || strings.ContainsAny(c, "\"\\ \t\n") {
		return "", fmt.Errorf("install: --cover-cgroup %q must be a control group path such as agents.slice or user.slice/agents.slice", c)
	}
	return c, nil
}

// dropIn is the unit drop-in turning on the listeners of the selected modes.
func (in *Installer) dropIn() string {
	ic := in.Intercept
	var b strings.Builder
	b.WriteString("# Written by scrim install; scrim uninstall --system removes it.\n[Service]\n")
	if ic.Transparent {
		addrs := []string{"127.0.0.1:" + strconv.Itoa(ic.port())}
		if in.ipv6Loopback() {
			addrs = append(addrs, "[::1]:"+strconv.Itoa(ic.port()))
		}
		fmt.Fprintf(&b, "Environment=%s=%s\n", EnvTransparentListen, strings.Join(addrs, ","))
	}
	if ic.BlockUnrouted {
		fmt.Fprintf(&b, "Environment=%s=block\n", EnvTransparentUnrouted)
	}
	if ic.DNS {
		fmt.Fprintf(&b, "Environment=%s=%s:443\n", EnvSNIListen, ic.dnsAddress())
		b.WriteString("# The SNI listener binds port 443; nothing else is allowed.\n" +
			"AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n")
	}
	return b.String()
}

// ipv6Loopback reports whether ::1 exists, so the transparent listener can
// take redirected IPv6 connections. Without it they are refused (nothing
// listens), never passed direct.
func (in *Installer) ipv6Loopback() bool {
	b, err := os.ReadFile(in.path("/proc/net/if_inet6"))
	return err == nil && bytes.Contains(b, []byte("00000000000000000000000000000001"))
}

// writeDropIn writes the drop-in before the service starts or restarts.
func (in *Installer) writeDropIn() error {
	if !in.Intercept.Active() {
		return nil
	}
	p := in.path(DropInPath)
	if err := in.ensureDir(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	_, err := in.unitFile(p, []byte(in.dropIn()), ScopeSystem)
	return err
}

// installInterception runs after the service is ready and the CA is in the
// system trust store.
func (in *Installer) installInterception(ctx context.Context, caPEM string) error {
	ic := in.Intercept
	if !ic.Active() {
		return nil
	}
	if err := in.javaTrust(ctx, caPEM); err != nil {
		return err
	}
	if ic.Transparent {
		if err := in.transparentRules(ctx); err != nil {
			return err
		}
	}
	if ic.DNS {
		return in.hostsBlock()
	}
	return nil
}

// Rules is the nftables rule set: connections of the covered users and
// control groups to ports 80 and 443 go to the transparent listener; any
// such connection that was not redirected, and QUIC (UDP 443), is
// rejected. scrim's own user and loopback destinations (local chained
// upstreams) are never touched.
func Rules(scrimUID int, uids []int, cgroups []string, port int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `#!/usr/sbin/nft -f
# Written by scrim install --transparent; scrim uninstall --system removes it.
# Loaded by %s, which stays independent of scrim.service: while scrim
# is stopped, redirected connections fail instead of going direct.
table %s
delete table %s
table %s {
	chain nat_output {
		type nat hook output priority -100; policy accept;
		meta skuid %d return
		ip daddr 127.0.0.0/8 return
		ip6 daddr ::1 return
`, RulesUnit, NFTable, NFTable, NFTable, scrimUID)
	var matches []string
	if len(uids) > 0 {
		ids := make([]string, len(uids))
		for i, u := range uids {
			ids[i] = strconv.Itoa(u)
		}
		matches = append(matches, "meta skuid { "+strings.Join(ids, ", ")+" }")
	}
	for _, c := range cgroups {
		matches = append(matches, fmt.Sprintf("socket cgroupv2 level %d %q", strings.Count(c, "/")+1, c))
	}
	for _, m := range matches {
		fmt.Fprintf(&b, "\t\t%s tcp dport { 80, 443 } redirect to :%d\n", m, port)
	}
	fmt.Fprintf(&b, `	}
	chain filter_output {
		type filter hook output priority 0; policy accept;
		meta skuid %d accept
		ip daddr 127.0.0.0/8 accept
		ip6 daddr ::1 accept
`, scrimUID)
	for _, m := range matches {
		fmt.Fprintf(&b, "\t\t%s tcp dport { 80, 443 } reject with tcp reset\n", m)
		fmt.Fprintf(&b, "\t\t%s udp dport 443 reject\n", m)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// RulesUnitFile is the oneshot unit that loads the rule set.
func RulesUnitFile(nft string, cgroups []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by scrim install --transparent; scrim uninstall --system removes it.
[Unit]
Description=scrim transparent interception rules (nftables)
Documentation=%s
DefaultDependencies=no
Before=network-pre.target scrim.service
Wants=network-pre.target
`, docURL)
	for _, c := range cgroups {
		// A slice's control group exists once the slice is started; the
		// rules name it, so it must exist when they load.
		if s := filepath.Base(c); strings.HasSuffix(s, ".slice") {
			fmt.Fprintf(&b, "Wants=%s\nAfter=%s\n", s, s)
		}
	}
	fmt.Fprintf(&b, `
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s -f %s
ExecReload=%s -f %s
ExecStop=-%s delete table %s

[Install]
WantedBy=multi-user.target
`, nft, RulesPath, nft, RulesPath, nft, NFTable)
	return b.String()
}

func (in *Installer) transparentRules(ctx context.Context) error {
	ic := in.Intercept
	nft, err := in.Runner.LookPath("nft")
	if err != nil {
		return errors.New("install: --transparent needs nft (the nftables package)")
	}
	scrimUID := -1
	if u, ok, err := in.user(ServiceUser); err != nil {
		return err
	} else if ok {
		scrimUID = u.UID
	} else if !in.DryRun {
		return fmt.Errorf("install: user %s missing", ServiceUser)
	}
	var uids []int
	for _, name := range ic.CoverUsers {
		u, _, err := in.user(name)
		if err != nil {
			return err
		}
		uids = append(uids, u.UID)
	}
	var cgroups []string
	for _, c := range ic.CoverCgroups {
		p, _ := cgroupPath(c)
		if !strings.HasSuffix(p, ".slice") && !exists(in.path(filepath.Join("/sys/fs/cgroup", p))) {
			return fmt.Errorf("install: control group /sys/fs/cgroup/%s does not exist; the rules can only name an existing one (a systemd slice is created at boot)", p)
		}
		cgroups = append(cgroups, p)
	}
	rules := Rules(scrimUID, uids, cgroups, ic.port())
	in.printf("  the transparent mode redirects TCP 80 and 443 of %s to scrim on port %d and rejects their direct and QUIC egress\n",
		describeCover(ic.CoverUsers, cgroups), ic.port())
	changed, err := in.file(fileSpec{path: in.path(RulesPath), content: []byte(rules), mode: 0o644, what: "the nftables rule set"})
	if err != nil {
		return err
	}
	if changed && in.recorded(Entry{Kind: KindService, Target: RulesUnit, Scope: ScopeSystem}) && !in.DryRun {
		in.printf("+ reload %s (the rule set changed)\n", RulesUnit)
		if err := in.systemctl(ctx, ScopeSystem, "reload-or-restart", RulesUnit); err != nil {
			return err
		}
	}
	if _, err := in.unitFile(in.path(RulesUnitPath), []byte(RulesUnitFile(nft, cgroups)), ScopeSystem); err != nil {
		return err
	}
	if err := in.enableUnit(ctx, RulesUnit, "load the nftables rules"); err != nil {
		return err
	}
	e := Entry{Kind: KindNFTable, Target: NFTable}
	if in.recorded(e) {
		return nil
	}
	return in.change("record the nftables table "+NFTable+" (nft list table "+NFTable+")", e, func() error {
		return in.run(ctx, "nft", "list", "table", "inet", "scrim")
	})
}

func describeCover(users, cgroups []string) string {
	var parts []string
	if len(users) > 0 {
		parts = append(parts, "the users "+strings.Join(users, ", "))
	}
	if len(cgroups) > 0 {
		parts = append(parts, "the control groups "+strings.Join(cgroups, ", "))
	}
	return strings.Join(parts, " and ")
}

// enableUnit enables and starts a unit other than scrim.service.
func (in *Installer) enableUnit(ctx context.Context, unit, why string) error {
	e := Entry{Kind: KindService, Target: unit, Scope: ScopeSystem}
	if in.recorded(e) {
		return nil
	}
	in.printf("+ %senable and start %s to %s (systemctl enable --now)\n", in.verb(), unit, why)
	if in.DryRun {
		return nil
	}
	err := in.systemctl(ctx, ScopeSystem, "enable", "--now", unit)
	// Recorded even when starting failed: enable may have linked the unit,
	// and uninstall must disable it again.
	if rerr := in.record(e); err == nil {
		err = rerr
	}
	return err
}

// hostsLines is the block added to the hosts file.
func (in *Installer) hostsLines() string {
	ic := in.Intercept
	return hostsBegin + "\n" + ic.dnsAddress() + " " + strings.Join(ic.DNSHosts, " ") + "\n" + hostsEnd + "\n"
}

func (in *Installer) hostsBlock() error {
	p := in.path(HostsPath)
	cur, err := os.ReadFile(p) // #nosec G304 -- the hosts file under the install root
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("install: %w", err)
	}
	block := in.hostsLines()
	if len(cur) > 0 && !bytes.HasSuffix(cur, []byte("\n")) {
		block = "\n" + block
	}
	e := Entry{Kind: KindHosts, Target: p, SHA256: sum([]byte(block))}
	if i := in.mf.find(e); i >= 0 {
		if bytes.Contains(cur, []byte(hostsBegin)) {
			old := in.mf.Entries[i]
			if old.SHA256 == sum([]byte(in.hostsLines())) || old.SHA256 == sum([]byte("\n"+in.hostsLines())) {
				return nil
			}
			return fmt.Errorf("install: %s already has a scrim block for other names; run scrim uninstall --system first", p)
		}
	} else if bytes.Contains(cur, []byte(hostsBegin)) {
		return fmt.Errorf("install: %s has a scrim block scrim did not record; remove it first", p)
	}
	in.printf("+ %sresolve %s to scrim (%s): add to %s\n", in.verb(), strings.Join(in.Intercept.DNSHosts, ", "), in.Intercept.dnsAddress(), p)
	in.printf("  note: the DNS override covers connections by name only; a client connecting by address bypasses it\n")
	if in.DryRun {
		return nil
	}
	// Written in place: the hosts file is often a bind mount, which a
	// rename would fail on.
	if err := writeInPlace(p, append(cur, block...)); err != nil {
		return err
	}
	return in.record(e)
}

func writeInPlace(p string, b []byte) error {
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(p); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(p, b, mode); err != nil { // #nosec G306 -- keeps the hosts file's mode
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// removeHostsBlock removes exactly the block install added.
func (in *Installer) removeHostsBlock(e Entry) result {
	manual := fmt.Sprintf("remove the lines from %q to %q in %s", hostsBegin, hostsEnd, e.Target)
	cur, err := os.ReadFile(e.Target) // #nosec G304 -- recorded hosts file
	if errors.Is(err, fs.ErrNotExist) {
		return ok()
	}
	if err != nil {
		return fail(err, manual)
	}
	start := bytes.Index(cur, []byte(hostsBegin))
	if start < 0 {
		return ok()
	}
	endMark := bytes.Index(cur[start:], []byte(hostsEnd+"\n"))
	if endMark < 0 {
		return fail(fmt.Errorf("the scrim block in %s was changed; left alone", e.Target), manual)
	}
	end := start + endMark + len(hostsEnd) + 1
	if start > 0 && cur[start-1] == '\n' && sum(cur[start-1:end]) == e.SHA256 {
		start--
	} else if sum(cur[start:end]) != e.SHA256 {
		return fail(fmt.Errorf("the scrim block in %s was changed; left alone", e.Target), manual)
	}
	out := append(slices.Clone(cur[:start]), cur[end:]...)
	if err := writeInPlace(e.Target, out); err != nil {
		return fail(err, manual)
	}
	return ok()
}

// javaStore is one Java truststore and the keytool that edits it.
type javaStore struct {
	path, keytool string
	managed       bool
}

// javaStores finds the Java truststores on the host: the ones the system
// trust tools rebuild, and the cacerts of every JDK under /usr/lib/jvm and
// of JavaHomes, each once (they are often symbolic links to the system one).
func (in *Installer) javaStores() []javaStore {
	var out []javaStore
	seen := map[string]bool{}
	add := func(p, keytool string) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || seen[real] {
			return
		}
		st, err := os.Stat(real)
		if err != nil || !st.Mode().IsRegular() {
			return
		}
		seen[real] = true
		managed := false
		for _, m := range managedJavaStores {
			if real == in.path(m) {
				managed = true
			}
		}
		if keytool == "" || !exists(keytool) {
			keytool = "keytool"
		}
		out = append(out, javaStore{path: real, keytool: keytool, managed: managed})
	}
	for _, m := range managedJavaStores {
		add(in.path(m), "")
	}
	homes := slices.Clone(in.Intercept.JavaHomes)
	if jvms, err := os.ReadDir(in.path("/usr/lib/jvm")); err == nil {
		for _, j := range jvms {
			homes = append(homes, filepath.Join("/usr/lib/jvm", j.Name()))
		}
	}
	for _, h := range homes {
		home := in.path(h)
		for _, rel := range []string{"lib/security/cacerts", "jre/lib/security/cacerts"} {
			add(filepath.Join(home, rel), filepath.Join(home, "bin", "keytool"))
		}
	}
	return out
}

// fingerprint is the keytool form of the SHA-256 fingerprint of the first
// certificate in caPEM, and that certificate as PEM.
func fingerprint(caPEM string) (string, []byte, error) {
	b, _ := pem.Decode([]byte(caPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return "", nil, errors.New("install: the service reported no CA certificate")
	}
	s := sha256.Sum256(b.Bytes)
	parts := make([]string, len(s))
	for i, x := range s {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":"), pem.EncodeToMemory(b), nil
}

func (in *Installer) storeHas(ctx context.Context, s javaStore, fp string) (bool, error) {
	out, err := in.Runner.Run(ctx, s.keytool, "-list", "-keystore", s.path, "-storepass", javaStorePass)
	if err != nil {
		return false, fmt.Errorf("keytool -list -keystore %s: %w", s.path, err)
	}
	return bytes.Contains(out, []byte(fp)), nil
}

// javaTrust makes every Java truststore trust the CA: the ones the system
// trust tool rebuilt are checked, the others get the CA imported (and
// recorded).
func (in *Installer) javaTrust(ctx context.Context, caPEM string) error {
	stores := in.javaStores()
	if len(stores) == 0 {
		in.printf("  no Java truststore found; a JDK installed later trusts scrim once its cacerts holds the CA (keytool -importcert)\n")
		return nil
	}
	if in.DryRun {
		for _, s := range stores {
			if s.managed {
				in.printf("  would check that %s (rebuilt by the system trust tool) trusts the scrim CA\n", s.path)
			} else {
				in.printf("+ would import the scrim CA into the Java truststore %s (keytool -importcert -alias %s)\n", s.path, JavaAlias)
			}
		}
		return nil
	}
	fp, cert, err := fingerprint(caPEM)
	if err != nil {
		return err
	}
	for _, s := range stores {
		has, err := in.storeHas(ctx, s, fp)
		if err != nil {
			return err
		}
		e := Entry{Kind: KindJavaTrust, Target: s.path, Tool: s.keytool, SHA256: sum(cert)}
		switch {
		case has && s.managed:
			in.printf("  the Java truststore %s, rebuilt by the system trust tool, trusts the scrim CA\n", s.path)
			continue
		case has:
			continue
		}
		if err := in.importJava(ctx, s, cert, e); err != nil {
			return err
		}
	}
	return nil
}

func (in *Installer) importJava(ctx context.Context, s javaStore, cert []byte, e Entry) error {
	in.printf("+ import the scrim CA into the Java truststore %s (keytool -importcert -alias %s)\n", s.path, JavaAlias)
	if in.recorded(e) {
		// A previous CA under the same alias: replace it.
		_ = in.run(ctx, s.keytool, "-delete", "-alias", JavaAlias, "-keystore", s.path, "-storepass", javaStorePass)
	}
	tmp, err := os.CreateTemp("", "scrim-ca-*.pem")
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(cert); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("install: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := in.run(ctx, s.keytool, "-importcert", "-noprompt", "-trustcacerts", "-alias", JavaAlias,
		"-file", tmp.Name(), "-keystore", s.path, "-storepass", javaStorePass); err != nil {
		return err
	}
	return in.record(e)
}

// revertJava removes the CA from a truststore scrim imported it into.
func (in *Installer) revertJava(ctx context.Context, e Entry) result {
	manual := fmt.Sprintf("keytool -delete -alias %s -keystore %s -storepass changeit", JavaAlias, e.Target)
	if !exists(e.Target) {
		return ok()
	}
	keytool := e.Tool
	if keytool == "" {
		keytool = "keytool"
	}
	out, err := in.Runner.Run(ctx, keytool, "-list", "-alias", JavaAlias, "-keystore", e.Target, "-storepass", javaStorePass)
	if err != nil && bytes.Contains(out, []byte("does not exist")) {
		return ok()
	}
	return resultOf(in.run(ctx, keytool, "-delete", "-alias", JavaAlias, "-keystore", e.Target, "-storepass", javaStorePass), manual)
}

// checkManagedJava verifies, after the system trust store was rebuilt
// without the CA, that the Java truststores the trust tool manages dropped
// it too; one that kept it gets the entry removed with keytool.
func (in *Installer) checkManagedJava(ctx context.Context, caPEM string) {
	fp, _, err := fingerprint(caPEM)
	if err != nil {
		return
	}
	for _, s := range in.javaStores() {
		if !s.managed {
			continue
		}
		out, err := in.Runner.Run(ctx, s.keytool, "-list", "-keystore", s.path, "-storepass", javaStorePass)
		if err != nil || !bytes.Contains(out, []byte(fp)) {
			continue
		}
		alias := aliasOf(string(out), fp)
		if alias == "" {
			continue
		}
		in.printf("  %s still holds the scrim CA as %s; removing it (keytool -delete)\n", s.path, alias)
		if err := in.run(ctx, s.keytool, "-delete", "-alias", alias, "-keystore", s.path, "-storepass", javaStorePass); err != nil {
			in.printf("  failed: %v\n", err)
		}
	}
}

// aliasOf finds the alias of the entry with fingerprint fp in keytool -list
// output: "alias, date, trustedCertEntry," followed by the fingerprint line.
func aliasOf(list, fp string) string {
	lines := strings.Split(list, "\n")
	for i, l := range lines {
		if strings.Contains(l, fp) && i > 0 {
			prev := lines[i-1]
			if j := strings.Index(prev, ","); j > 0 {
				return strings.TrimSpace(prev[:j])
			}
		}
	}
	return ""
}
