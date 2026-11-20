// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFileYAMLAndJSON(t *testing.T) {
	dir := t.TempDir()
	y := filepath.Join(dir, "p.yaml")
	_ = os.WriteFile(y, []byte(`default: ask
rules:
  - name: jit
    decision: ask
    when: op == "inject"
    approval: {timeout: 5m, notifiers: [ntfy]}
    grant: {ttl: 30m, max_ttl: 2h, uses: 3, scope: host}
`), 0o600)
	c, err := LoadFile(y)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Rules[0]
	if c.Default != "ask" || r.Approval.Timeout.D() != 5*time.Minute || r.Approval.Notifiers[0] != "ntfy" ||
		r.Grant.TTL.D() != 30*time.Minute || r.Grant.MaxTTL.D() != 2*time.Hour || r.Grant.Uses != 3 || r.Grant.Scope != ScopeHost {
		t.Fatalf("%+v", c)
	}
	j := filepath.Join(dir, "p.json")
	_ = os.WriteFile(j, []byte(`{"rules":[{"name":"a","decision":"deny","whne":"x"}]}`), 0o600)
	if _, err := LoadFile(j); err == nil || !strings.Contains(err.Error(), "whne") {
		t.Fatalf("unknown JSON key: %v", err)
	}
	e := filepath.Join(dir, "empty.yaml")
	_ = os.WriteFile(e, nil, 0o600)
	if c, err := LoadFile(e); err != nil || len(c.Rules) != 0 {
		t.Fatalf("empty file: %+v %v", c, err)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file accepted")
	}
}
