// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEndpointsServeTheDaemonsPublicAddresses(t *testing.T) {
	want := Endpoints{Ready: true, BaseURL: "http://127.0.0.1:9790", ForwardProxy: "127.0.0.1:9791",
		Bypass: []string{"127.0.0.1:8787"}, CAPEM: "-----BEGIN CERTIFICATE-----\n"}
	h := startWith(t, func(s *Server) { s.Endpoints = func() Endpoints { return want } })
	got, err := h.peer.Endpoints(bg)
	if err != nil {
		t.Fatal(err)
	}
	if got.BaseURL != want.BaseURL || got.ForwardProxy != want.ForwardProxy || !got.Ready || got.CAPEM != want.CAPEM ||
		len(got.Bypass) != 1 {
		t.Fatalf("endpoints = %+v", got)
	}
}

func TestEndpointsAbsentWithoutADaemon(t *testing.T) {
	h := start(t)
	_, err := h.peer.Endpoints(bg)
	if codeOf(t, err) != "not_found" {
		t.Fatalf("err = %v", err)
	}
}

func TestSocketGroup(t *testing.T) {
	dir, err := os.MkdirTemp("", "scrim-grp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	gid := os.Getgid()
	if groups, _ := os.Getgroups(); len(groups) > 0 {
		gid = groups[len(groups)-1]
	}
	ln, err := Listen(sock, ListenOptions{Mode: 0o660, Group: gid})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Gid) != gid || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket gid %d mode %v, want %d 0660", st.Gid, fi.Mode().Perm(), gid)
	}
}

func TestClientSocketPathFindsTheSystemService(t *testing.T) {
	user, system := t.TempDir(), shortDir(t)
	t.Setenv(EnvSocket, "")
	t.Setenv("XDG_RUNTIME_DIR", user)
	old := SystemRuntimeDir
	SystemRuntimeDir = system
	t.Cleanup(func() { SystemRuntimeDir = old })

	def := filepath.Join(user, "scrim", "api.sock")
	if got := ClientSocketPath(); got != def {
		t.Fatalf("nothing running: %s, want the user default %s", got, def)
	}
	ln, err := Listen(SystemSocketPath(), ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if got := ClientSocketPath(); got != SystemSocketPath() {
		t.Fatalf("only the system service: %s", got)
	}
	if err := os.MkdirAll(filepath.Dir(def), 0o700); err != nil {
		t.Fatal(err)
	}
	uln, err := Listen(def, ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uln.Close() }()
	if got := ClientSocketPath(); got != def {
		t.Fatalf("both running: %s, want this user's", got)
	}
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "scrim-sys")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
