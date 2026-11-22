// SPDX-License-Identifier: AGPL-3.0-only

package bpfredirect

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCleanCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"agents.slice":                      "agents.slice",
		"/sys/fs/cgroup/agents.slice/":      "agents.slice",
		"user.slice//agents.slice":          "user.slice/agents.slice",
		" /user.slice/user-1000.slice/x/  ": "user.slice/user-1000.slice/x",
	} {
		if got, err := CleanCgroup(in); err != nil || got != want {
			t.Errorf("CleanCgroup(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "/", "/sys/fs/cgroup", "../etc", "a/../../b", "a b", `a"b`} {
		if _, err := CleanCgroup(bad); err == nil {
			t.Errorf("CleanCgroup(%q) accepted", bad)
		}
	}
}

func TestCaps(t *testing.T) {
	c, err := ParseCaps([]byte("Name:\tx\nCapInh:\t0000000000000000\nCapEff:\t000000c000001000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Has(capNetAdmin) || !c.Has(capBPF) || c.Has(capSysAdmin) {
		t.Fatalf("caps %x", uint64(c))
	}
	if m := c.MissingToLoad(); len(m) != 0 {
		t.Errorf("CAP_BPF+CAP_NET_ADMIN missing %v", m)
	}
	if m := Caps(0).MissingToLoad(); !slices.Equal(m, []string{"CAP_BPF", "CAP_NET_ADMIN"}) {
		t.Errorf("no caps missing %v", m)
	}
	if m := Caps(1 << capSysAdmin).MissingToLoad(); len(m) != 0 {
		t.Errorf("CAP_SYS_ADMIN missing %v", m)
	}
	if m := Caps(1 << capBPF).MissingToQuery(); !slices.Equal(m, []string{"CAP_NET_ADMIN"}) {
		t.Errorf("query with CAP_BPF only: %v", m)
	}
	if _, err := ParseCaps([]byte("Name:\tx\n")); err == nil {
		t.Error("no CapEff accepted")
	}
}

func TestPrivilegeError(t *testing.T) {
	e := &PrivilegeError{Op: "attaching eBPF programs", Missing: []string{"CAP_BPF", "CAP_NET_ADMIN"}}
	if !strings.Contains(e.Error(), "lacks CAP_BPF and CAP_NET_ADMIN") {
		t.Error(e)
	}
	cause := errors.New("operation not permitted")
	e = &PrivilegeError{Op: "loading the eBPF programs", Cause: cause}
	if !errors.Is(e, cause) || !strings.Contains(e.Error(), "initial user namespace") {
		t.Error(e)
	}
}

func TestRecordRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "attachments.json")
	if r, err := ReadRecord(path); err != nil || len(r.Attachments) != 0 {
		t.Fatalf("missing record: %+v %v", r, err)
	}
	var r Record
	r.put(Attachment{Cgroup: "b.slice", CgroupID: 2, Port: 9792})
	r.put(Attachment{Cgroup: "a.slice", CgroupID: 1, Port: 9792})
	r.put(Attachment{Cgroup: "b.slice", CgroupID: 3, Port: 9793})
	if err := writeRecord(path, r); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("record mode %v %v", st.Mode(), err)
	}
	got, err := ReadRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Attachments) != 2 || got.Attachments[0].Cgroup != "a.slice" {
		t.Fatalf("record %+v", got)
	}
	if b, _ := got.Find("b.slice"); b.CgroupID != 3 || b.Port != 9793 {
		t.Fatalf("replaced entry %+v", b)
	}
	got.remove("a.slice")
	if _, ok := got.Find("a.slice"); ok {
		t.Fatal("remove kept the entry")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecord(path); err == nil {
		t.Fatal("corrupt record accepted")
	}
}

func TestInspectOffWhenUnused(t *testing.T) {
	in := Inspector{CgroupRoot: t.TempDir(), RecordPath: filepath.Join(t.TempDir(), "none.json")}
	if r := Inspect(in, nil, DefaultPort); r != nil {
		t.Fatalf("unused mode reported: %+v", r)
	}
}

func TestInspectWithoutCgroupV2(t *testing.T) {
	in := Inspector{
		CgroupRoot: t.TempDir(), RecordPath: filepath.Join(t.TempDir(), "none.json"),
		Caps: func() Caps { return 0 }, Dial: func(string) error { return errors.New("refused") },
	}
	r := Inspect(in, []string{"agents.slice"}, DefaultPort)
	if r == nil || !strings.Contains(r.Problem, "no cgroup v2 hierarchy") || r.Cgroups[0].State != NotAttached {
		t.Fatalf("report %+v", r)
	}
	if r.ListenerUp || !strings.Contains(r.Listener, "never go direct") {
		t.Fatalf("listener %q", r.Listener)
	}
}

func TestLoaderNeedsPrivilege(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "agents.slice"), 0o700); err != nil {
		t.Fatal(err)
	}
	l := Loader{CgroupRoot: root, PinRoot: filepath.Join(t.TempDir(), "pins"), RecordPath: filepath.Join(t.TempDir(), "rec.json"),
		Caps: func() Caps { return 0 }, Now: time.Now}
	_, err := l.Attach("agents.slice", DefaultPort)
	var pe *PrivilegeError
	if errors.Is(err, ErrUnsupported) {
		t.Skip("not Linux")
	}
	if !errors.As(err, &pe) || !slices.Equal(pe.Missing, []string{"CAP_BPF", "CAP_NET_ADMIN"}) {
		t.Fatalf("Attach without privileges: %v", err)
	}
	if err := l.Detach("agents.slice"); !errors.As(err, &pe) {
		t.Fatalf("Detach without privileges: %v", err)
	}
	if _, err := os.Stat(l.RecordPath); !os.IsNotExist(err) {
		t.Fatalf("a refused attach wrote the record: %v", err)
	}
}

func TestLoaderCheck(t *testing.T) {
	root := t.TempDir()
	l := Loader{CgroupRoot: root, Caps: func() Caps { return 1 << capBPF }}
	err := l.Check()
	if err == ErrUnsupported { //nolint:errorlint // the unwrapped error is the non-Linux stub
		t.Skip("not Linux")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Check without cgroup v2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var pe *PrivilegeError
	if err := l.Check(); !errors.As(err, &pe) || !slices.Equal(pe.Missing, []string{"CAP_NET_ADMIN"}) {
		t.Fatalf("Check with CAP_BPF only: %v", err)
	}
	l.Caps = func() Caps { return 1 << capSysAdmin }
	if err := l.Check(); err != nil {
		t.Fatalf("Check with CAP_SYS_ADMIN: %v", err)
	}
}
