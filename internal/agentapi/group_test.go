// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestLookupGroup(t *testing.T) {
	if id, err := lookupGroup(""); err != nil || id != 0 {
		t.Fatalf("empty: %d %v", id, err)
	}
	if id, err := lookupGroup("4242"); err != nil || id != 4242 {
		t.Fatalf("numeric: %d %v", id, err)
	}
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip("own group not in the group database")
	}
	if id, err := lookupGroup(g.Name); err != nil || id != os.Getgid() {
		t.Fatalf("by name %s: %d %v", g.Name, id, err)
	}
	if _, err := lookupGroup("no-such-group-scrim-test"); err == nil {
		t.Fatal("unknown group accepted")
	}
}
