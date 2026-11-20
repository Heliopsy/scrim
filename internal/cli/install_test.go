// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/install"
	"github.com/heliopsy/scrim/internal/status"
)

type okProbe struct{}

func (okProbe) WaitReady(context.Context, string) error { return nil }
func (okProbe) CA(context.Context, string) (string, error) {
	return "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n", nil
}

// systemctlRunner records calls and answers `systemctl show` with active.
type systemctlRunner struct{ cliFakeRunner }

func (r *systemctlRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	_, _ = r.cliFakeRunner.Run(ctx, name, args...)
	if name == "systemctl" && slices.Contains(args, "show") {
		return []byte("active\n"), nil
	}
	return nil, nil
}

type installFixture struct {
	root, home string
	runner     *systemctlRunner
}

// newInstallFixture points every install injection point at fakes: a fake
// root, a fake binary, a recording runner and a probe that is always ready.
func newInstallFixture(t *testing.T, euid int) *installFixture {
	t.Helper()
	f := &installFixture{root: t.TempDir(), home: t.TempDir(), runner: &systemctlRunner{}}
	for _, d := range []string{"etc/systemd/system", "usr/local/bin", "usr/sbin", "var/lib", "run"} {
		if err := os.MkdirAll(filepath.Join(f.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(f.root, "etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
	_ = os.WriteFile(filepath.Join(f.root, "etc/group"), []byte("root:x:0:\n"), 0o644)
	bin := filepath.Join(t.TempDir(), "scrim")
	_ = os.WriteFile(bin, []byte("fake scrim"), 0o755)
	roots := filepath.Join(t.TempDir(), "roots.pem")
	_ = os.WriteFile(roots, []byte("# roots\n"), 0o644)

	oRunner, oProbe, oRoot, oExe, oEUID := installRunner, installProbe, installRoot, installExecutable, installEUID
	oGOOS, oMemlock, oChown, oCARunner, oCAGOOS, oCARoots := installGOOS, installMemlock, installChown, caRunner, caGOOS, caSysRoots
	t.Cleanup(func() {
		installRunner, installProbe, installRoot, installExecutable, installEUID = oRunner, oProbe, oRoot, oExe, oEUID
		installGOOS, installMemlock, installChown, caRunner, caGOOS, caSysRoots = oGOOS, oMemlock, oChown, oCARunner, oCAGOOS, oCARoots
	})
	installRunner, installProbe, installRoot = f.runner, okProbe{}, f.root
	installExecutable = func() (string, error) { return bin, nil }
	installEUID = func() int { return euid }
	installGOOS, installMemlock = "linux", func() bool { return false }
	installChown = func(string, int, int) error { return nil }
	caRunner, caGOOS, caSysRoots = &f.runner.cliFakeRunner, "linux", []string{roots}
	return f
}

func (f *installFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	e, out, errb := newEnv("HOME="+f.home, "XDG_STATE_HOME="+filepath.Join(f.home, ".local/state"),
		"XDG_CONFIG_HOME="+filepath.Join(f.home, ".config"), "XDG_DATA_HOME="+filepath.Join(f.home, ".local/share"),
		"XDG_RUNTIME_DIR="+filepath.Join(f.home, "run"))
	code := Run(context.Background(), e, args)
	return code, out.String(), errb.String()
}

func treeOf(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		v := d.Type().String()
		if d.Type().IsRegular() {
			b, _ := os.ReadFile(p)
			s := sha256.Sum256(b)
			v = hex.EncodeToString(s[:])
		}
		out[p] = v
		return nil
	})
	return out
}

func TestInstallNeedsAMode(t *testing.T) {
	f := newInstallFixture(t, 1000)
	code, _, errb := f.run(t, "install")
	if code == 0 || !strings.Contains(errb, "--user") || !strings.Contains(errb, "--system") || !strings.Contains(errb, "--quadlet") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestSystemInstallNeedsRoot(t *testing.T) {
	f := newInstallFixture(t, 1000)
	code, _, errb := f.run(t, "install", "--system")
	if code == 0 || !strings.Contains(errb, "as root") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestUserInstallRefusedAsRoot(t *testing.T) {
	f := newInstallFixture(t, 0)
	installRoot = ""
	code, _, errb := f.run(t, "install", "--user")
	if code == 0 || !strings.Contains(errb, "use --system") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestInstallOnlyOnLinux(t *testing.T) {
	f := newInstallFixture(t, 1000)
	installGOOS = "darwin"
	if code, _, errb := f.run(t, "install", "--user"); code == 0 || !strings.Contains(errb, "Linux") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestSystemDryRunShowsEveryChange(t *testing.T) {
	f := newInstallFixture(t, 1000)
	before := treeOf(t, f.root)
	code, out, errb := f.run(t, "install", "--system", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	for _, w := range []string{"would create the system user scrim", "would write " + filepath.Join(f.root, install.SystemUnitPath),
		"would enable and start scrim.service", "Nothing was changed"} {
		if !strings.Contains(out, w) {
			t.Errorf("dry run lacks %q:\n%s", w, out)
		}
	}
	if !maps(before, treeOf(t, f.root)) || len(f.runner.calls) > 0 {
		t.Errorf("dry run changed something: calls %q", f.runner.calls)
	}
}

func maps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestUserInstallTrustsTheCAAndUninstallLeavesNoTrace(t *testing.T) {
	f := newInstallFixture(t, 1000)
	before := treeOf(t, f.home)
	code, out, errb := f.run(t, "install", "--user")
	if code != 0 {
		t.Fatalf("install: exit %d: %s\n%s", code, errb, out)
	}
	data := filepath.Join(f.home, ".local/share/scrim")
	for _, p := range []string{filepath.Join(f.home, ".local/bin/scrim"), filepath.Join(f.home, ".config/systemd/user/scrim.service"),
		filepath.Join(data, "scrim-ca.pem"), filepath.Join(data, "ca-bundle.pem")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("not installed: %v", err)
		}
	}
	if !strings.Contains(out, "export NODE_EXTRA_CA_CERTS=") {
		t.Errorf("trust variables not printed:\n%s", out)
	}

	code, out, errb = f.run(t, "status", "-o", "json")
	if code != 0 {
		t.Fatalf("status: exit %d: %s", code, errb)
	}
	var r status.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.Service == nil || r.Service.Mode != "user" || r.Service.Active != "active" || r.Service.System {
		t.Fatalf("status service = %+v", r.Service)
	}

	code, out, errb = f.run(t, "uninstall", "--purge")
	if code != 0 {
		t.Fatalf("uninstall: exit %d: %s\n%s", code, errb, out)
	}
	after := treeOf(t, f.home)
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("left behind: %s", p)
		}
	}
}

func TestDefaultImageFollowsTheVersion(t *testing.T) {
	if img := defaultImage(); !strings.HasPrefix(img, install.DefaultImage+":") {
		t.Fatal(img)
	}
}

func TestCertsFromPEM(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nb3RoZXI=\n-----END CERTIFICATE-----\n"
	cs := certsFromPEM(pem)
	if len(cs) != 2 || !cs[0].Current || cs[1].Current || cs[0].ID == cs[1].ID {
		t.Fatalf("certs = %+v", cs)
	}
}
