// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/fsview"
	"github.com/heliopsy/scrim/internal/status"
)

// TestStatusRunFSViewOnThisHost is task 10a.8's check, run on macOS in CI:
// status names the filesystem view scrim run gives sessions here, and on
// macOS that is the home mirror fallback with its gaps.
func TestStatusRunFSViewOnThisHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no session filesystem view; internal/fsview tests what it reports there")
	}
	e, out, errb := newEnv(isolatedEnv(t)...)
	if code := Run(context.Background(), e, []string{"status", "-o", "json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var r status.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	v := r.RunView
	if v == nil || v.Requested != fsview.ModeAuto {
		t.Fatalf("status has no run filesystem view: %+v", v)
	}
	t.Logf("run filesystem view here: %+v", *v)
	switch {
	case runtime.GOOS == "darwin":
		if v.Mode != fsview.ModeHome || !strings.Contains(v.Fallback, "darwin") || len(v.Gaps) == 0 {
			t.Fatalf("macOS view = %+v, want the home mirror fallback with gaps", *v)
		}
	case v.Mode == fsview.ModeNamespace:
	case v.Mode == fsview.ModeHome && v.Fallback != "" && len(v.Gaps) > 0:
	default:
		t.Fatalf("view = %+v", *v)
	}

	e, out, _ = newEnv(isolatedEnv(t)...)
	_ = Run(context.Background(), e, []string{"status"})
	if !strings.Contains(out.String(), "Filesystem view (scrim run)") {
		t.Errorf("human status lacks the filesystem view:\n%s", out.String())
	}
}

// TestStatusRunFSViewFallbackAndRefusal: without namespaces, status lists
// the fallback and its gaps and doctor warns; with run.fs-view namespace,
// status reports scrim run as refusing and doctor fails.
func TestStatusRunFSViewFallbackAndRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no session filesystem view; internal/fsview tests what it reports there")
	}
	old := runViewProbe
	runViewProbe = func(context.Context) fsview.Availability {
		return fsview.Availability{Reason: "creating a user namespace is not allowed: operation not permitted"}
	}
	t.Cleanup(func() { runViewProbe = old })

	e, out, _ := newEnv(isolatedEnv(t)...)
	_ = Run(context.Background(), e, []string{"status"})
	for _, want := range []string{"home (fallback: creating a user namespace is not allowed", "not covered: tools that find the home directory through the password database"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}
	e, out, _ = newEnv(isolatedEnv(t)...)
	_ = Run(context.Background(), e, []string{"doctor"})
	if !strings.Contains(out.String(), "[warn] run-fs-view: scrim run falls back to the home mirror") {
		t.Errorf("doctor does not warn:\n%s", out.String())
	}

	e, out, _ = newEnv(isolatedEnv(t, "SCRIM_RUN_FS_VIEW=namespace")...)
	_ = Run(context.Background(), e, []string{"status"})
	if !strings.Contains(out.String(), "REFUSED: run.fs-view is namespace") || !strings.Contains(out.String(), "run-fs-view: run.fs-view is namespace") {
		t.Errorf("status does not report the refusal:\n%s", out.String())
	}
	e, out, _ = newEnv(isolatedEnv(t, "SCRIM_RUN_FS_VIEW=namespace")...)
	_ = Run(context.Background(), e, []string{"doctor"})
	if !strings.Contains(out.String(), "[fail] run-fs-view") {
		t.Errorf("doctor does not fail:\n%s", out.String())
	}
}
