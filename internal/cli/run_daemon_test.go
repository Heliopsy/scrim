// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRunPrintEnvWithRealDaemon runs `scrim run --print-env` against a
// daemon started in process with the real data plane, as a user without a
// running scrim gets it.
func TestRunPrintEnvWithRealDaemon(t *testing.T) {
	dp := os.Getenv("SCRIM_TEST_DATAPLANE")
	if dp == "" || dp == "embedded" {
		t.Skip("SCRIM_TEST_DATAPLANE is not set; run `just test` to build and use the Rust data plane")
	}
	sock, err := os.MkdirTemp("", "scrim-r")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(sock) }()
	home := t.TempDir()
	e, out, errb := newEnv("HOME="+home, "XDG_STATE_HOME="+home, "XDG_CONFIG_HOME="+home, "XDG_RUNTIME_DIR="+sock,
		"SCRIM_DATAPLANE_PATH="+dp, "SCRIM_PROXY_LISTEN=127.0.0.1:0", "SCRIM_PROXY_FORWARD_LISTEN=127.0.0.1:0",
		"SCRIM_ADMIN_URL=unix:"+sock+"/admin.sock", "SCRIM_API_SOCKET="+sock+"/api.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if code := Run(ctx, e, []string{"run", "--print-env", "--", "claude"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, want := range []string{"ANTHROPIC_BASE_URL=http://127.0.0.1:", "HTTPS_PROXY=http://127.0.0.1:", "SCRIM_API_SOCKET=" + sock + "/api.sock", "NODE_EXTRA_CA_CERTS="} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("print-env lacks %q:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(sock + "/admin.sock"); !os.IsNotExist(err) {
		t.Fatal("the daemon started for the run is still running")
	}
}
