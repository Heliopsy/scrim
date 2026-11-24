// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

func platformConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: "+config.APIVersion+"\nkind: Config\n"+yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{ConfigPaths: []string{p}, Environ: []string{}, SystemDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Every setting Windows cannot honour is named at start-up; the defaults
// start.
func TestWindowsRefusesUnsupportedSettings(t *testing.T) {
	if err := checkPlatform(platformConfig(t, "")); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	cfg := platformConfig(t, `
proxy.socket: C:\scrim\llm.sock
proxy.transparent-listen: ["127.0.0.1:9793"]
interception.ebpf.cgroups: ["/sys/fs/cgroup/agents"]
api.permissions: "0660"
api.group: agents
dataplane.memory-lock: require
identity.peers:
  ci: uid:1001
`)
	err := checkPlatform(cfg)
	if !errors.Is(err, errUnsupportedPlatform) {
		t.Fatalf("checkPlatform = %v, want a refusal", err)
	}
	for _, key := range []string{"proxy.socket", "proxy.transparent-listen", "interception.ebpf.cgroups",
		"api.permissions", "api.group", "dataplane.memory-lock", "identity.peers.ci"} {
		if !strings.Contains(err.Error(), key+":") {
			t.Errorf("refusal does not name %s:\n%v", key, err)
		}
	}
}
