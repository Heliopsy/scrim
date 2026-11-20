// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"strings"
	"testing"
)

// TestProxyCaptureHelpShowsTheEqualsForm: --capture takes an optional value,
// so only `--capture=DIR` sets the directory. The help says so, and the
// space form fails with a hint instead of an unknown-command error.
func TestProxyCaptureHelpShowsTheEqualsForm(t *testing.T) {
	e, out, _ := newEnv(isolatedEnv(t)...)
	if code := Run(context.Background(), e, []string{"proxy", "--help"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	help := out.String()
	if strings.Contains(help, "--capture DIR") || strings.Contains(help, "--capture ~") || !strings.Contains(help, "--capture=DIR") {
		t.Fatalf("help shows a form that does not work:\n%s", help)
	}
	e, _, errb := newEnv(isolatedEnv(t)...)
	if code := Run(context.Background(), e, []string{"proxy", "--capture", t.TempDir()}); code == 0 ||
		!strings.Contains(errb.String(), "--capture=DIR") {
		t.Fatalf("space form: exit %d: %s", code, errb.String())
	}
}
