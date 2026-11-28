// SPDX-License-Identifier: AGPL-3.0-only

package doclint

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Violation is one problem a check found. Check, File and Subject identify it
// for the allowlist; line numbers are not part of the identity, so an entry
// survives edits elsewhere in the file.
type Violation struct {
	Check   string // links, command, setting, version
	File    string
	Line    int
	Subject string
	Detail  string
}

func (v Violation) key() string { return v.Check + " | " + v.File + " | " + v.Subject }

// allowEntry is one line of known-violations.txt:
//
//	check | file | subject | reason
type allowEntry struct {
	line   int
	key    string
	reason string
}

const allowFile = "known-violations.txt"

func loadAllowlist(t *testing.T, root string) map[string][]allowEntry {
	t.Helper()
	data := readFile(t, root, "test/e2e/docs/doclint/"+allowFile)
	out := map[string][]allowEntry{}
	for i, raw := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.Split(l, " | ")
		if len(parts) != 4 || strings.TrimSpace(parts[3]) == "" {
			t.Fatalf("%s:%d: want \"check | file | subject | reason\", got %q", allowFile, i+1, l)
		}
		for j := range parts {
			parts[j] = strings.TrimSpace(parts[j])
		}
		e := allowEntry{line: i + 1, key: strings.Join(parts[:3], " | "), reason: parts[3]}
		out[parts[0]] = append(out[parts[0]], e)
	}
	return out
}

// report fails t for every violation not in the allowlist, and for every
// allowlist entry of this check that matched nothing.
func report(t *testing.T, root, check string, found []Violation) {
	t.Helper()
	allowed := map[string]*allowEntry{}
	used := map[string]bool{}
	entries := loadAllowlist(t, root)[check]
	for i := range entries {
		if allowed[entries[i].key] != nil {
			t.Errorf("%s:%d: duplicate entry %q", allowFile, entries[i].line, entries[i].key)
		}
		allowed[entries[i].key] = &entries[i]
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		return found[i].Line < found[j].Line
	})
	for _, v := range found {
		if allowed[v.key()] != nil {
			used[v.key()] = true
			continue
		}
		t.Errorf("%s:%d: %s\n\tallowlist key: %s", v.File, v.Line, v.Detail, v.key())
	}
	for _, e := range entries {
		if !used[e.key] {
			t.Errorf("%s:%d: %q no longer matches anything: delete the entry", allowFile, e.line, e.key)
		}
	}
	if !t.Failed() {
		t.Logf("%d known %s violations allowed", len(used), check)
	}
}

func violation(check, file string, line int, subject, format string, args ...any) Violation {
	return Violation{Check: check, File: file, Line: line, Subject: subject, Detail: fmt.Sprintf(format, args...)}
}
