// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

// TestDataPlaneEnvUpstreamCA checks proxy.upstream-ca-file reaches the data
// plane as SCRIM_DP_EXTRA_CA_FILE, and that nothing is passed without it.
func TestDataPlaneEnvUpstreamCA(t *testing.T) {
	build := func(environ ...string) *config.Config {
		t.Helper()
		c, err := config.Build(config.Options{Registry: config.Default, Environ: environ})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if env := dataPlaneEnv(build(), ""); len(env) != 0 {
		t.Fatalf("env without settings = %v", env)
	}
	env := dataPlaneEnv(build("SCRIM_PROXY_UPSTREAM_CA_FILE=/etc/scrim/upstream-ca.pem"), "")
	if !slices.Contains(env, "SCRIM_DP_EXTRA_CA_FILE=/etc/scrim/upstream-ca.pem") {
		t.Fatalf("env = %v", env)
	}
	env = dataPlaneEnv(build(), "/var/capture")
	if !slices.ContainsFunc(env, func(s string) bool { return strings.HasPrefix(s, "SCRIM_DP_CAPTURE_DIR=") }) ||
		slices.ContainsFunc(env, func(s string) bool { return strings.HasPrefix(s, "SCRIM_DP_EXTRA_CA_FILE=") }) {
		t.Fatalf("capture env = %v", env)
	}
}
