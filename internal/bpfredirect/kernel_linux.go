// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bpfredirect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// attachTypes maps each hook to its cgroup attach type.
var attachTypes = map[string]ebpf.AttachType{
	"connect4": ebpf.AttachCGroupInet4Connect,
	"connect6": ebpf.AttachCGroupInet6Connect,
	"sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
	"sendmsg6": ebpf.AttachCGroupUDP6Sendmsg,
	"egress":   ebpf.AttachCGroupInetEgress,
}

// Loader attaches and detaches the programs. The zero value works on the
// real host; tests point the paths elsewhere.
type Loader struct {
	CgroupRoot string
	PinRoot    string
	RecordPath string
	Caps       func() Caps
	Now        func() time.Time
}

func (l Loader) withDefaults() Loader {
	if l.CgroupRoot == "" {
		l.CgroupRoot = CgroupRoot
	}
	if l.PinRoot == "" {
		l.PinRoot = PinRoot
	}
	if l.RecordPath == "" {
		l.RecordPath = RecordPath
	}
	if l.Caps == nil {
		l.Caps = SelfCaps
	}
	if l.Now == nil {
		l.Now = time.Now
	}
	return l
}

// Attach loads the programs with the listener port and attaches them to a
// control group, pinning each link so it stays after this process exits.
// An existing attachment of the same control group is replaced only after
// the new one is in place, so the group is never uncovered in between.
func (l Loader) Attach(cgroup string, port int) (Attachment, error) {
	l = l.withDefaults()
	cg, err := CleanCgroup(cgroup)
	if err != nil {
		return Attachment{}, err
	}
	if err := validPort(port); err != nil {
		return Attachment{}, err
	}
	if err := supported(l.CgroupRoot); err != nil {
		return Attachment{}, err
	}
	if m := l.Caps().MissingToLoad(); len(m) > 0 {
		return Attachment{}, &PrivilegeError{Op: "attaching eBPF programs", Missing: m}
	}
	dir := filepath.Join(l.CgroupRoot, cg)
	id, err := cgroupID(dir)
	if err != nil {
		return Attachment{}, fmt.Errorf("control group %s: %w", dir, err)
	}
	unlock, err := lockRecord(l.RecordPath)
	if err != nil {
		return Attachment{}, err
	}
	defer unlock()
	rec, err := ReadRecord(l.RecordPath)
	if err != nil {
		return Attachment{}, err
	}
	// Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK. Best effort:
	// where raising it is refused, loading reports the real refusal.
	_ = rlimit.RemoveMemlock()
	spec, err := loadRedirect()
	if err != nil {
		return Attachment{}, err
	}
	if err := spec.Variables["redirect_port"].Set(uint16(port)); err != nil { // #nosec G115 -- validPort
		return Attachment{}, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return Attachment{}, refused("loading the eBPF programs", err)
	}
	defer coll.Close()

	a := Attachment{
		Cgroup: cg, CgroupID: id, Port: port, Programs: map[string]uint32{},
		PinDir:     filepath.Join(l.PinRoot, fmt.Sprintf("cg-%d-%d", id, l.Now().UnixNano())),
		AttachedAt: l.Now().UTC().Truncate(time.Second),
	}
	if err := os.MkdirAll(a.PinDir, 0o700); err != nil {
		return Attachment{}, refused("creating "+a.PinDir, err)
	}
	if err := l.attachAll(coll, dir, &a); err != nil {
		_ = os.RemoveAll(a.PinDir)
		return Attachment{}, err
	}
	old, hadOld := rec.Find(cg)
	rec.put(a)
	if err := writeRecord(l.RecordPath, rec); err != nil {
		_ = os.RemoveAll(a.PinDir)
		return Attachment{}, fmt.Errorf("recording the attachment in %s (the programs were detached again): %w", l.RecordPath, err)
	}
	if hadOld && old.PinDir != a.PinDir {
		if err := unpinDir(old.PinDir); err != nil {
			return a, refused("removing the previous attachment "+old.PinDir, err)
		}
		if old.CgroupID == id {
			if err := waitDetached(dir, old.Programs); err != nil {
				return a, err
			}
		}
	}
	return a, nil
}

func (l Loader) attachAll(coll *ebpf.Collection, dir string, a *Attachment) error {
	for _, h := range Hooks {
		prog := coll.Programs["scrim_"+h]
		if prog == nil {
			return fmt.Errorf("program scrim_%s missing from the embedded object", h)
		}
		info, err := prog.Info()
		if err != nil {
			return err
		}
		pid, ok := info.ID()
		if !ok {
			return errors.New("the kernel does not report program IDs (needs Linux 4.13 or later)")
		}
		lk, err := link.AttachCgroup(link.CgroupOptions{Path: dir, Attach: attachTypes[h], Program: prog})
		if err != nil {
			return refused("attaching "+h+" to "+dir, err)
		}
		err = lk.Pin(filepath.Join(a.PinDir, h))
		_ = lk.Close()
		if errors.Is(err, ebpf.ErrNotSupported) {
			return errors.New("the kernel has no BPF links for control groups (needs Linux 5.7 or later), so the programs cannot outlive the loader")
		}
		if err != nil {
			return refused("pinning "+h+" in "+a.PinDir, err)
		}
		a.Programs[h] = uint32(pid)
	}
	return nil
}

// Detach removes a control group's attachment: its pinned links (which
// detaches the programs) and its record entry. Detaching a control group
// that is not attached is not an error.
func (l Loader) Detach(cgroup string) error {
	l = l.withDefaults()
	cg, err := CleanCgroup(cgroup)
	if err != nil {
		return err
	}
	if m := l.Caps().MissingToLoad(); len(m) > 0 {
		return &PrivilegeError{Op: "detaching eBPF programs", Missing: m}
	}
	unlock, err := lockRecord(l.RecordPath)
	if err != nil {
		return err
	}
	defer unlock()
	rec, err := ReadRecord(l.RecordPath)
	if err != nil {
		return err
	}
	dir := filepath.Join(l.CgroupRoot, cg)
	if a, ok := rec.Find(cg); ok {
		if err := unpinDir(a.PinDir); err != nil {
			return refused("removing "+a.PinDir, err)
		}
		if id, err := cgroupID(dir); err == nil && id == a.CgroupID {
			if err := waitDetached(dir, a.Programs); err != nil {
				return err
			}
		}
	}
	// Pins of this control group the record lost track of.
	if id, err := cgroupID(dir); err == nil {
		stale, _ := filepath.Glob(filepath.Join(l.PinRoot, fmt.Sprintf("cg-%d-*", id)))
		for _, d := range stale {
			if err := unpinDir(d); err != nil {
				return refused("removing "+d, err)
			}
		}
	}
	rec.remove(cg)
	return writeRecord(l.RecordPath, rec)
}

// lockRecord serialises loaders, so two attaches cannot lose each other's
// record entries.
func lockRecord(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- status of any user reads the record
		return nil, refused("creating "+filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- next to the record
	if err != nil {
		return nil, refused("locking "+path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil { // #nosec G115 -- an fd
		_ = f.Close()
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return func() { _ = f.Close() }, nil
}

// unpinDir removes a directory of pinned links; removing the last
// reference to a link detaches its program.
func unpinDir(dir string) error {
	err := os.RemoveAll(dir)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// detachTimeout bounds waitDetached. The kernel drops a link whose last pin
// is removed after an RCU grace period, not during the unlink.
const detachTimeout = 10 * time.Second

// waitDetached waits until none of programs is attached to the control
// group any more, so Detach returning means the programs no longer apply.
func waitDetached(dir string, programs map[string]uint32) error {
	deadline := time.Now().Add(detachTimeout)
	for {
		got, err := queryKernel(dir)
		if err != nil {
			return fmt.Errorf("confirming the detach of %s: %w", dir, err)
		}
		left := ""
		for _, h := range Hooks {
			if slices.Contains(got[h], programs[h]) {
				left = h
				break
			}
		}
		if left == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the %s program is still attached to %s %s after its pin was removed", left, dir, detachTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// refused wraps a kernel refusal; EPERM and EACCES become a PrivilegeError.
func refused(op string, err error) error {
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return &PrivilegeError{Op: op, Cause: err}
	}
	return fmt.Errorf("%s: %w", op, err)
}

// cgroupID is a control group's ID: the inode number of its directory.
func cgroupID(dir string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return 0, &os.PathError{Op: "stat", Path: dir, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return 0, fmt.Errorf("%s is not a control group directory", dir)
	}
	return st.Ino, nil
}

// queryKernel lists the programs attached directly to a control group.
func queryKernel(dir string) (map[string][]uint32, error) {
	f, err := os.Open(dir) // #nosec G304 -- a control group directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string][]uint32{}
	for _, h := range Hooks {
		res, err := link.QueryPrograms(link.QueryOptions{Target: int(f.Fd()), Attach: attachTypes[h]}) // #nosec G115 -- an fd
		if err != nil {
			return nil, fmt.Errorf("%s: %w", h, err)
		}
		for _, p := range res.Programs {
			out[h] = append(out[h], uint32(p.ID))
		}
	}
	return out, nil
}
