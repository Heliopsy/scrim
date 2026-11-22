// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bpfredirect

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// fakeHost is a cgroup root in a temporary directory with one control group
// and a loader record for it.
type fakeHost struct {
	in  Inspector
	rec Attachment
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "agents.slice")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := cgroupID(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{
		in: Inspector{
			CgroupRoot: root, RecordPath: filepath.Join(t.TempDir(), "attachments.json"),
			Caps: func() Caps { return 1 << capNetAdmin },
			Dial: func(string) error { return nil },
		},
		rec: Attachment{Cgroup: "agents.slice", CgroupID: id, Port: DefaultPort, Programs: map[string]uint32{},
			AttachedAt: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), Version: "0.5.0", Object: ObjectDigest()},
	}
	attached := map[string][]uint32{}
	for i, hk := range slices.Concat(Hooks, ListenerHooks) {
		h.rec.Programs[hk] = uint32(100 + i)
		attached[hk] = []uint32{7, uint32(100 + i)}
	}
	h.in.Query = func(string) (map[string][]uint32, error) { return attached, nil }
	h.write(t)
	return h
}

func (h *fakeHost) write(t *testing.T) {
	t.Helper()
	if err := writeRecord(h.in.RecordPath, Record{Attachments: []Attachment{h.rec}}); err != nil {
		t.Fatal(err)
	}
}

func (h *fakeHost) one(t *testing.T, configured []string, port int) CgroupReport {
	t.Helper()
	r := Inspect(h.in, configured, port)
	if r == nil || len(r.Cgroups) != 1 {
		t.Fatalf("report %+v", r)
	}
	return r.Cgroups[0]
}

func TestInspectStates(t *testing.T) {
	t.Run("active only when the kernel lists the programs", func(t *testing.T) {
		h := newFakeHost(t)
		if c := h.one(t, []string{"/sys/fs/cgroup/agents.slice"}, DefaultPort); c.State != Active || !strings.Contains(c.Detail, "verified") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("recorded but not configured is still reported", func(t *testing.T) {
		h := newFakeHost(t)
		if c := h.one(t, nil, DefaultPort); c.State != Active {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("unverified without CAP_NET_ADMIN", func(t *testing.T) {
		h := newFakeHost(t)
		h.in.Caps = func() Caps { return 1 << capBPF }
		h.in.Query = func(string) (map[string][]uint32, error) { t.Fatal("queried without the capability"); return nil, nil }
		if c := h.one(t, []string{"agents.slice"}, DefaultPort); c.State != Unverified || !strings.Contains(c.Detail, "CAP_NET_ADMIN") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("lost when a program is gone", func(t *testing.T) {
		h := newFakeHost(t)
		h.in.Query = func(string) (map[string][]uint32, error) { return map[string][]uint32{"connect4": {100}}, nil }
		if c := h.one(t, []string{"agents.slice"}, DefaultPort); c.State != Lost || !strings.Contains(c.Detail, "connect6") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("lost when the getsockopt program left the root control group", func(t *testing.T) {
		h := newFakeHost(t)
		q := h.in.Query
		h.in.Query = func(dir string) (map[string][]uint32, error) {
			got, err := q(dir)
			if dir == h.in.CgroupRoot {
				got = map[string][]uint32{"getsockopt": {7}}
			}
			return got, err
		}
		if c := h.one(t, []string{"agents.slice"}, DefaultPort); c.State != Lost ||
			!strings.Contains(c.Detail, "getsockopt program the loader attached to "+h.in.CgroupRoot) {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("lost when the control group was recreated", func(t *testing.T) {
		h := newFakeHost(t)
		dir := filepath.Join(h.in.CgroupRoot, "agents.slice")
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
		if c := h.one(t, []string{"agents.slice"}, DefaultPort); c.State != Lost || !strings.Contains(c.Detail, "no longer exists") {
			t.Fatalf("%+v", c)
		}
		// A new directory under the same path gets a new inode while the
		// old one is still held, as a recreated control group gets a new ID.
		hold, _ := os.Create(filepath.Join(h.in.CgroupRoot, "hold"))
		defer func() { _ = hold.Close() }()
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if id, _ := cgroupID(dir); id == h.rec.CgroupID {
			t.Skip("the filesystem reused the inode number")
		}
		if c := h.one(t, []string{"agents.slice"}, DefaultPort); c.State != Lost || !strings.Contains(c.Detail, "recreated") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("an attachment made before the newer programs existed is lost, with the fix", func(t *testing.T) {
		h := newFakeHost(t)
		h.rec.Version, h.rec.Object = "", ""
		delete(h.rec.Programs, "sockops")
		delete(h.rec.Programs, "getsockopt")
		h.write(t)
		c := h.one(t, []string{"agents.slice"}, DefaultPort)
		if c.State != Lost || !strings.Contains(c.Detail, "attached by an older scrim without the sockops program") ||
			c.Fix != AttachCommand || !strings.Contains(c.Detail, "run `"+AttachCommand+"`") {
			t.Fatalf("%+v", c)
		}
		// Without the privilege to query, the record alone shows it.
		h.in.Caps = func() Caps { return 0 }
		if c := h.one(t, []string{"agents.slice"}, DefaultPort); c.State != Lost {
			t.Fatalf("unprivileged: %+v", c)
		}
	})
	t.Run("stale when another scrim's programs are attached", func(t *testing.T) {
		h := newFakeHost(t)
		h.rec.Version, h.rec.Object = "0.4.9", strings.Repeat("0", 64)
		h.write(t)
		h.in.AttachCommand = "sudo systemctl reload-or-restart scrim-ebpf"
		r := Inspect(h.in, []string{"agents.slice"}, DefaultPort)
		c := r.Cgroups[0]
		if c.State != Stale || !strings.Contains(c.Detail, "attached by scrim 0.4.9 with programs other than this binary's") ||
			c.Fix != "sudo systemctl reload-or-restart scrim-ebpf" || !strings.Contains(c.Detail, "run `sudo systemctl reload-or-restart scrim-ebpf`") {
			t.Fatalf("%+v", c)
		}
		if r.Active() {
			t.Fatal("a stale control group counts as active")
		}
	})
	t.Run("another port is not this attachment", func(t *testing.T) {
		h := newFakeHost(t)
		if c := h.one(t, []string{"agents.slice"}, 9999); c.State != NotAttached || !strings.Contains(c.Detail, "port 9793") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("configured but never attached names the missing privilege", func(t *testing.T) {
		h := newFakeHost(t)
		h.in.Caps = func() Caps { return 0 }
		r := Inspect(h.in, []string{"agents.slice", "ci.slice"}, DefaultPort)
		if len(r.Cgroups) != 2 || r.Cgroups[1].Cgroup != "ci.slice" || r.Cgroups[1].State != NotAttached ||
			!strings.Contains(r.Cgroups[1].Detail, "lacks CAP_BPF and CAP_NET_ADMIN") {
			t.Fatalf("%+v", r.Cgroups)
		}
		if r.Active() {
			t.Fatal("report with no verified group is active")
		}
	})
}

func TestCurrent(t *testing.T) {
	h := newFakeHost(t)
	if ok, why := h.in.Current("agents.slice", DefaultPort); !ok {
		t.Fatalf("this binary's attachment is not current: %s", why)
	}
	if ok, why := h.in.Current("agents.slice", 9999); ok || !strings.Contains(why, "not-attached") {
		t.Fatalf("other port: %v %s", ok, why)
	}
	if ok, why := h.in.Current("ci.slice", DefaultPort); ok || !strings.Contains(why, "not attached") {
		t.Fatalf("unattached: %v %s", ok, why)
	}
	h.rec.Object = strings.Repeat("0", 64)
	h.write(t)
	if ok, why := h.in.Current("agents.slice", DefaultPort); ok || !strings.HasPrefix(why, "stale: ") || strings.Contains(why, "run `") {
		t.Fatalf("stale: %v %s", ok, why)
	}
	h.rec.Object = ""
	h.write(t)
	if ok, why := h.in.Current("agents.slice", DefaultPort); ok || !strings.Contains(why, "did not record") {
		t.Fatalf("unrecorded object: %v %s", ok, why)
	}
}

func TestObjectDigest(t *testing.T) {
	d := ObjectDigest()
	if len(d) != 64 || d != ObjectDigest() {
		t.Fatalf("digest %q", d)
	}
}

// TestEmbeddedObject checks the committed object without loading it: the
// programs, their attach points, the maps and the port variable the loader
// sets.
func TestEmbeddedObject(t *testing.T) {
	spec, err := loadRedirect()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ebpf.AttachType{}
	for h, at := range attachTypes {
		want["scrim_"+h] = at
	}
	if len(spec.Programs) != len(want) {
		t.Fatalf("programs %v", spec.Programs)
	}
	for name, p := range spec.Programs {
		at, ok := want[name]
		if !ok || p.AttachType != at {
			t.Errorf("%s attaches to %v, want %v", name, p.AttachType, at)
		}
		wantType := map[string]ebpf.ProgramType{
			"scrim_egress": ebpf.CGroupSKB, "scrim_sockops": ebpf.SockOps, "scrim_getsockopt": ebpf.CGroupSockopt,
		}[name]
		if wantType == ebpf.UnspecifiedProgram {
			wantType = ebpf.CGroupSockAddr
		}
		if p.Type != wantType {
			t.Errorf("%s is %v, want %v", name, p.Type, wantType)
		}
	}
	// LRU maps bound the per-connection state: key and value sizes of
	// struct conn_key and struct orig_dst, which have no padding.
	for name, m := range map[string]struct{ key, value, max uint32 }{
		"scrim_pending": {8, 24, 4096},
		"scrim_origdst": {36, 24, 16384},
	} {
		ms := spec.Maps[name]
		if ms == nil || ms.Type != ebpf.LRUHash || ms.KeySize != m.key || ms.ValueSize != m.value ||
			ms.MaxEntries != m.max || ms.Pinning != ebpf.PinNone {
			t.Errorf("map %s: %+v, want an unpinned LRU hash of %d entries, key %d and value %d bytes", name, ms, m.max, m.key, m.value)
		}
	}
	v := spec.Variables["redirect_port"]
	if v == nil || !v.Constant() || v.Size() != 2 {
		t.Fatalf("redirect_port %+v", v)
	}
	if err := v.Set(uint16(12345)); err != nil {
		t.Fatal(err)
	}
}

// TestKernelRefusalIsAPrivilegeError: with the capabilities apparently
// present but no right to load (an unprivileged test run, a rootless
// container), the kernel's EPERM names what is missing.
func TestKernelRefusalIsAPrivilegeError(t *testing.T) {
	if len(SelfCaps().MissingToLoad()) == 0 {
		t.Skip("this process may load BPF programs; the kernel test covers it")
	}
	h := newFakeHost(t)
	l := Loader{CgroupRoot: h.in.CgroupRoot, PinRoot: filepath.Join(t.TempDir(), "pins"), RecordPath: h.in.RecordPath,
		Caps: func() Caps { return 1<<capBPF | 1<<capNetAdmin }}
	_, err := l.Attach("agents.slice", DefaultPort)
	var pe *PrivilegeError
	t.Log(err)
	if !errors.As(err, &pe) || pe.Cause == nil || !strings.Contains(err.Error(), "initial user namespace") {
		t.Fatalf("Attach: %v", err)
	}
}
