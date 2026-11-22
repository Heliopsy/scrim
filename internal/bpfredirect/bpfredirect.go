// SPDX-License-Identifier: AGPL-3.0-only

// Package bpfredirect is the eBPF variant of the transparent mode
// (specs/interception "Transparent mode with eBPF"): a privileged loader
// attaches the programs in bpf/redirect.c to selected cgroup v2 control
// groups, which rewrites their TCP connections to ports 80 and 443 to scrim's
// transparent listener on loopback and denies their direct and QUIC egress.
// The programs only move traffic; TLS interception happens in the listener,
// routed by server name, so no original-destination lookup is needed.
//
// Attachments are bpf_links pinned under /sys/fs/bpf/scrim, so they outlive
// the loader and scrim itself: while scrim is stopped, redirected
// connections fail instead of going direct. The loader records what it
// attached in a world-readable file under /run, which is how an
// unprivileged `scrim status` knows about them; only a process that may
// query the kernel (CAP_NET_ADMIN) reports a control group as active.
package bpfredirect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Where the loader keeps its state.
const (
	// CgroupRoot is the cgroup v2 mount control group paths are relative to.
	CgroupRoot = "/sys/fs/cgroup"
	// PinRoot holds one directory of pinned links per attachment.
	PinRoot = "/sys/fs/bpf/scrim"
	// RecordPath lists the attachments, readable by every user. It is not
	// under /run/scrim, which systemd removes whenever scrim.service stops.
	RecordPath = "/run/scrim-ebpf/attachments.json"
	// DefaultPort is the transparent listener's default port (the one
	// scrim install --transparent sets on 127.0.0.1 and ::1).
	DefaultPort = 9793
)

// Hooks are the program names in bpf/redirect.c, in attach order.
var Hooks = []string{"connect4", "connect6", "sendmsg4", "sendmsg6", "egress"}

// Settings of the eBPF mode.
var (
	// CgroupsSetting are the control groups the mode should cover.
	CgroupsSetting = config.Register(config.Spec[[]string]{
		Key:     "interception.ebpf.cgroups",
		Default: []string{},
		Description: "Control groups (cgroup v2 paths below /sys/fs/cgroup, such as agents.slice) the eBPF transparent mode covers " +
			"(Linux): `sudo scrim ebpf attach` redirects their TCP connections to ports 80 and 443 to the transparent listener " +
			"and denies their direct and QUIC egress. Status and doctor report each one that is not attached. Empty: the mode is off.",
		Validate: func(cgs []string) error {
			for _, c := range cgs {
				if _, err := CleanCgroup(c); err != nil {
					return err
				}
			}
			return nil
		},
	})
	// PortSetting is the transparent listener port the programs redirect to.
	PortSetting = config.Register(config.Spec[int]{
		Key:     "interception.ebpf.port",
		Default: DefaultPort,
		Description: "Port of the transparent listener on 127.0.0.1 and ::1 that the eBPF transparent mode redirects to. " +
			"It must match the port of proxy.transparent-listen; nothing listening there means covered connections fail, never go direct. " +
			"Unset, status and `scrim ebpf attach` use the port of the boot unit `scrim install --ebpf` installed, if any.",
		Validate: validPort,
	})
)

func validPort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d is not between 1 and 65535", p)
	}
	return nil
}

// CleanCgroup normalises a control group path to its form relative to
// /sys/fs/cgroup (agents.slice, user.slice/agents.slice).
func CleanCgroup(c string) (string, error) {
	c = strings.Trim(strings.TrimPrefix(strings.TrimSpace(c), CgroupRoot), "/")
	if c == "" || slices.Contains(strings.Split(c, "/"), "..") || strings.ContainsAny(c, "\"\\ \t\n") {
		return "", fmt.Errorf("control group %q must be a cgroup v2 path below %s, such as agents.slice", c, CgroupRoot)
	}
	return filepath.Clean(c), nil
}

// Attachment is one control group the loader attached the programs to.
type Attachment struct {
	// Cgroup is relative to /sys/fs/cgroup.
	Cgroup string `json:"cgroup"`
	// CgroupID is the control group's inode number when it was attached;
	// a control group recreated under the same path has a new one and
	// none of the programs.
	CgroupID uint64 `json:"cgroup_id"`
	Port     int    `json:"port"`
	// Programs maps each hook to the kernel's program ID.
	Programs   map[string]uint32 `json:"programs"`
	PinDir     string            `json:"pin_dir"`
	AttachedAt time.Time         `json:"attached_at"`
}

// String names an attachment for messages.
func (a Attachment) String() string {
	return a.Cgroup + " (id " + strconv.FormatUint(a.CgroupID, 10) + ", port " + strconv.Itoa(a.Port) + ")"
}

// Record is the loader's list of attachments.
type Record struct {
	Attachments []Attachment `json:"attachments"`
}

// Find returns the attachment of a control group.
func (r Record) Find(cgroup string) (Attachment, bool) {
	for _, a := range r.Attachments {
		if a.Cgroup == cgroup {
			return a, true
		}
	}
	return Attachment{}, false
}

func (r *Record) put(a Attachment) {
	r.remove(a.Cgroup)
	r.Attachments = append(r.Attachments, a)
	slices.SortFunc(r.Attachments, func(x, y Attachment) int { return strings.Compare(x.Cgroup, y.Cgroup) })
}

func (r *Record) remove(cgroup string) {
	r.Attachments = slices.DeleteFunc(r.Attachments, func(a Attachment) bool { return a.Cgroup == cgroup })
}

// ReadRecord reads the record; a missing file is an empty record.
func ReadRecord(path string) (Record, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the loader's own record
	if errors.Is(err, fs.ErrNotExist) {
		return Record{}, nil
	}
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// writeRecord replaces the record atomically, readable by every user (it
// holds paths, numbers and times only).
func writeRecord(path string, r Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- status of any user reads it
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil { // #nosec G306 -- no secrets, read by status
		return err
	}
	return os.Rename(tmp, path)
}

// Capabilities this package checks for.
const (
	capNetAdmin = 12
	capSysAdmin = 21
	capBPF      = 39
)

// Caps is a process's effective capability set.
type Caps uint64

// Has reports whether capability bit c is set.
func (c Caps) Has(bit int) bool { return c&(1<<bit) != 0 }

// ParseCaps reads CapEff from the text of /proc/<pid>/status.
func ParseCaps(status []byte) (Caps, error) {
	sc := bufio.NewScanner(bytes.NewReader(status))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "CapEff:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				return 0, fmt.Errorf("CapEff %q: %w", v, err)
			}
			return Caps(n), nil
		}
	}
	return 0, errors.New("no CapEff line")
}

// SelfCaps is this process's effective capability set; zero when it cannot
// be read.
func SelfCaps() Caps {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	c, _ := ParseCaps(b)
	return c
}

// MissingToLoad names the capabilities the loader lacks: CAP_BPF and
// CAP_NET_ADMIN, or CAP_SYS_ADMIN, which covers both (and is what kernels
// before 5.8, without CAP_BPF, require).
func (c Caps) MissingToLoad() []string {
	if c.Has(capSysAdmin) {
		return nil
	}
	var m []string
	if !c.Has(capBPF) {
		m = append(m, "CAP_BPF")
	}
	if !c.Has(capNetAdmin) {
		m = append(m, "CAP_NET_ADMIN")
	}
	return m
}

// MissingToQuery names what querying a control group's programs needs.
func (c Caps) MissingToQuery() []string {
	if c.Has(capSysAdmin) || c.Has(capNetAdmin) {
		return nil
	}
	return []string{"CAP_NET_ADMIN"}
}

// PrivilegeError is a loader operation this process may not perform.
type PrivilegeError struct {
	Op      string
	Missing []string
	// Cause is the kernel's refusal, when it refused despite the
	// capabilities (a user namespace, such as a rootless container, has
	// them only inside the namespace).
	Cause error
}

func (e *PrivilegeError) Error() string {
	if len(e.Missing) > 0 {
		return fmt.Sprintf("%s needs root, or CAP_BPF and CAP_NET_ADMIN with write access to %s; this process lacks %s",
			e.Op, PinRoot, strings.Join(e.Missing, " and "))
	}
	return fmt.Sprintf("%s: the kernel refused (%v); loading cgroup programs needs CAP_BPF and CAP_NET_ADMIN in the "+
		"initial user namespace, which a rootless container or other user namespace does not have", e.Op, e.Cause)
}

func (e *PrivilegeError) Unwrap() error { return e.Cause }

// ErrUnsupported is returned where eBPF cgroup programs do not exist.
var ErrUnsupported = errors.New("the eBPF transparent mode needs Linux with cgroup v2")

// State of one covered control group.
type State string

// States. Only Active means verified with the kernel.
const (
	Active      State = "active"
	Unverified  State = "unverified"
	NotAttached State = "not-attached"
	Lost        State = "lost"
)

// CgroupReport is one control group's state.
type CgroupReport struct {
	Cgroup     string    `json:"cgroup"`
	State      State     `json:"state"`
	Detail     string    `json:"detail"`
	AttachedAt time.Time `json:"attached_at,omitzero"`
	Port       int       `json:"port,omitempty"`
}

// Report is what status and doctor show about the mode.
type Report struct {
	// Configured is interception.ebpf.cgroups.
	Configured []string `json:"configured"`
	Port       int      `json:"port"`
	// Problem is why the mode cannot work on this host at all.
	Problem string         `json:"problem,omitempty"`
	Cgroups []CgroupReport `json:"cgroups"`
	// Listener is whether anything accepts connections on 127.0.0.1:Port.
	Listener   string `json:"listener"`
	ListenerUp bool   `json:"listener_up"`
}

// Active reports whether any control group is verified active.
func (r *Report) Active() bool {
	return slices.ContainsFunc(r.Cgroups, func(c CgroupReport) bool { return c.State == Active })
}

// Inspector reads the host for [Inspect]. The zero value inspects the real
// host.
type Inspector struct {
	CgroupRoot string
	RecordPath string
	Caps       func() Caps
	// Query returns the program IDs attached to a control group per hook;
	// nil uses the kernel (BPF_PROG_QUERY).
	Query func(cgroupDir string) (map[string][]uint32, error)
	// Dial checks the listener; nil dials TCP.
	Dial func(addr string) error
}

func (in Inspector) withDefaults() Inspector {
	if in.CgroupRoot == "" {
		in.CgroupRoot = CgroupRoot
	}
	if in.RecordPath == "" {
		in.RecordPath = RecordPath
	}
	if in.Caps == nil {
		in.Caps = SelfCaps
	}
	if in.Query == nil {
		in.Query = queryKernel
	}
	if in.Dial == nil {
		in.Dial = func(addr string) error {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				_ = c.Close()
			}
			return err
		}
	}
	return in
}

// Inspect reports the configured and recorded control groups. It returns
// nil when the mode is neither configured nor attached anywhere.
func Inspect(in Inspector, configured []string, port int) *Report {
	in = in.withDefaults()
	rec, recErr := ReadRecord(in.RecordPath)
	var cgs []string
	for _, c := range configured {
		if cc, err := CleanCgroup(c); err == nil && !slices.Contains(cgs, cc) {
			cgs = append(cgs, cc)
		}
	}
	for _, a := range rec.Attachments {
		if !slices.Contains(cgs, a.Cgroup) {
			cgs = append(cgs, a.Cgroup)
		}
	}
	if len(cgs) == 0 && recErr == nil {
		return nil
	}
	slices.Sort(cgs)
	r := &Report{Configured: slices.Clone(configured), Port: port, Cgroups: []CgroupReport{}}
	if r.Configured == nil {
		r.Configured = []string{}
	}
	if err := supported(in.CgroupRoot); err != nil {
		r.Problem = err.Error()
	} else if recErr != nil {
		r.Problem = "cannot read the loader's record: " + recErr.Error()
	}
	caps := in.Caps()
	for _, c := range cgs {
		r.Cgroups = append(r.Cgroups, in.inspectOne(rec, c, port, caps, r.Problem != ""))
	}
	r.ListenerUp, r.Listener = in.CheckListener(port)
	return r
}

// CheckListener reports whether anything accepts connections on
// 127.0.0.1:port, where the programs send covered connections.
func (in Inspector) CheckListener(port int) (bool, string) {
	in = in.withDefaults()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := in.Dial(addr); err != nil {
		return false, "nothing accepts connections on " + addr + ": redirected connections fail (they never go direct)"
	}
	return true, addr + " accepts connections"
}

func (in Inspector) inspectOne(rec Record, c string, port int, caps Caps, broken bool) CgroupReport {
	cr := CgroupReport{Cgroup: c}
	a, ok := rec.Find(c)
	if broken || !ok {
		cr.State = NotAttached
		cr.Detail = "not attached: run `sudo scrim ebpf attach`"
		if m := caps.MissingToLoad(); len(m) > 0 {
			cr.Detail += "; attaching needs root, or CAP_BPF and CAP_NET_ADMIN, and this process lacks " + strings.Join(m, " and ")
		}
		return cr
	}
	cr.AttachedAt, cr.Port = a.AttachedAt, a.Port
	dir := filepath.Join(in.CgroupRoot, c)
	id, err := cgroupID(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		cr.State, cr.Detail = Lost, "control group "+dir+" no longer exists; its programs went with it"
		return cr
	case err != nil:
		cr.State, cr.Detail = Lost, "cannot read control group "+dir+": "+err.Error()
		return cr
	case id != a.CgroupID:
		cr.State = Lost
		cr.Detail = fmt.Sprintf("control group %s was recreated after the programs were attached (id %d, now %d): run `sudo scrim ebpf attach` again", dir, a.CgroupID, id)
		return cr
	}
	if a.Port != port {
		cr.State = NotAttached
		cr.Detail = fmt.Sprintf("attached for port %d but interception.ebpf.port is %d: run `sudo scrim ebpf attach` to move it", a.Port, port)
		return cr
	}
	if m := caps.MissingToQuery(); len(m) > 0 {
		cr.State = Unverified
		cr.Detail = "attached according to the loader's record (" + in.RecordPath + "); confirming it with the kernel needs " +
			strings.Join(m, " and ") + ": run `sudo scrim status`"
		return cr
	}
	got, err := in.Query(dir)
	if err != nil {
		cr.State, cr.Detail = Unverified, "querying the kernel failed: "+err.Error()
		return cr
	}
	for _, h := range Hooks {
		if !slices.Contains(got[h], a.Programs[h]) {
			cr.State = Lost
			cr.Detail = "the " + h + " program the loader attached is no longer attached: run `sudo scrim ebpf attach`"
			return cr
		}
	}
	cr.State = Active
	cr.Detail = fmt.Sprintf("TCP 80 and 443 redirected to 127.0.0.1:%d and [::1]:%d, direct and QUIC egress denied (verified with the kernel)", port, port)
	return cr
}

// supported checks for a cgroup v2 hierarchy at root.
func supported(root string) error {
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return fmt.Errorf("%w: no cgroup v2 hierarchy at %s", ErrUnsupported, root)
	}
	return nil
}
