// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package matrix

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// nftRules redirect every outgoing TCP connection to port 443 inside the
// sandbox's network namespace to scrim's transparent listener, the way
// `scrim install --transparent` does for a covered user. Nothing else in a
// cell connects to port 443: scrim's upstreams and the store relays use
// other ports.
const nftRules = `table ip scrim-matrix {
	chain output {
		type nat hook output priority dstnat; policy accept;
		tcp dport 443 redirect to :9793
	}
}
`

// TestMatrix runs the cells of one store (SCRIM_MATRIX_STORE, or the cells
// in SCRIM_MATRIX_CELLS): it starts the store's server in rootless podman,
// then runs TestMatrixInner inside test/e2e/sandbox.sh with a relay to the
// server, the provider hosts in /etc/hosts and the transparent redirect.
// test/e2e/matrix/run.sh builds the binaries and calls it.
func TestMatrix(t *testing.T) {
	store := Store(os.Getenv("SCRIM_MATRIX_STORE"))
	spec := os.Getenv("SCRIM_MATRIX_CELLS")
	if store == "" && spec == "" {
		t.Skip("set SCRIM_MATRIX_STORE or SCRIM_MATRIX_CELLS (test/e2e/matrix/run.sh)")
	}
	if os.Getenv("SCRIM_E2E_SCRIM") == "" || os.Getenv("SCRIM_DATAPLANE_PATH") == "" {
		t.Fatal("SCRIM_E2E_SCRIM and SCRIM_DATAPLANE_PATH must name the scrim and scrim-dataplane binaries")
	}
	cells := Plan(store)
	if spec != "" {
		var err error
		if cells, err = ParseCells(spec); err != nil {
			t.Fatal(err)
		}
	}
	if len(cells) == 0 {
		t.Fatalf("no cells for store %q", store)
	}
	for _, c := range cells[1:] {
		if c.Store != cells[0].Store {
			t.Fatal("SCRIM_MATRIX_CELLS: one store per run")
		}
	}
	// Unix socket paths are short: keep the directory out of t.TempDir().
	dir, err := os.MkdirTemp("", "scrim-matrix-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if os.Getenv("SCRIM_TEST_CONTAINER_PREFIX") == "" {
		t.Setenv("SCRIM_TEST_CONTAINER_PREFIX", "scrim-matrix")
	}
	srv, stop, err := startStore(t, cells[0].Store, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	results := os.Getenv("SCRIM_MATRIX_RESULTS")
	if results == "" {
		results = filepath.Join(dir, "results")
	}
	if err := os.MkdirAll(results, 0o700); err != nil {
		t.Fatal(err)
	}
	p := plan{Store: srv, Results: results}
	for _, c := range cells {
		p.Cells = append(p.Cells, c.String())
	}
	planFile := filepath.Join(dir, "plan.json")
	hosts := filepath.Join(dir, "hosts")
	rules := filepath.Join(dir, "rules.nft")
	b, _ := json.Marshal(p)
	for path, content := range map[string][]byte{planFile: b, hosts: []byte(SandboxHosts()), rules: []byte(nftRules)} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{self, "-test.run", "^TestMatrixInner$", "-test.count=1", "-test.timeout=50m"}
	if testing.Verbose() {
		args = append(args, "-test.v")
	}
	sandbox, err := filepath.Abs(filepath.Join("..", "sandbox.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sandbox, args...) //nolint:gosec // the repository's own sandbox script
	cmd.Env = append(os.Environ(), "SCRIM_MATRIX_PLAN="+planFile, "SCRIM_SANDBOX_HOSTS="+hosts, "SCRIM_SANDBOX_NFT="+rules)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Errorf("cells of store %s: %v", cells[0].Store, err)
	}
	summary(t, results)
}

// summary logs one line per cell and appends a Markdown table to
// GITHUB_STEP_SUMMARY when CI sets it.
func summary(t *testing.T, dir string) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(files)
	var b strings.Builder
	b.WriteString("| Cell | Result | Matrix results | Scenarios | Cloud requests | MCP calls | Gated leaks | Limitation leaks | Seconds |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r Result
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		verdict := "pass"
		if !r.Pass {
			verdict = "FAIL"
		}
		t.Logf("%-4s %-45s rows=%d scenarios=%d cloud=%d mcp=%d gated=%d limitation=%d %.0fs", verdict, r.Cell, r.Rows, r.Scenarios,
			r.CloudRequests, r.MCPCalls, r.GatedLeaks, r.LimitationLeaks, r.Seconds)
		fmt.Fprintf(&b, "| `%s` | %s | %d | %d | %d | %d | %d | %d | %.0f |\n", r.Cell, verdict, r.Rows, r.Scenarios, r.CloudRequests,
			r.MCPCalls, r.GatedLeaks, r.LimitationLeaks, r.Seconds)
	}
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err == nil {
			_, _ = f.WriteString(b.String() + "\n")
			_ = f.Close()
		}
	}
}
