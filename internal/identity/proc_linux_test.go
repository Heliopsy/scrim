// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package identity

import (
	"errors"
	"testing"
)

func TestParseStatWithAwkwardCommandName(t *testing.T) {
	raw := []byte("4242 (we ird) (name)) S 77 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 0 0")
	p, err := parseStat(4242, raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.PPID != 77 || p.Start != 987654 {
		t.Fatalf("parsed %+v, want ppid 77 start 987654", p)
	}
	if _, err := parseStat(1, []byte("1 (x) S 0")); !errors.Is(err, ErrNoProcessInfo) {
		t.Fatalf("short stat: err = %v", err)
	}
}
