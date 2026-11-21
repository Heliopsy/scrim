package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ignoreEntry lets one dependency stay behind its latest major until a date.
//
//	<ecosystem> <name> <expires YYYY-MM-DD> <reason>
//
// ecosystem is go (name is the module path as go.mod requires it) or cargo
// (name is the crates.io crate name). The entry stops applying after the
// expiry date (UTC), and an expired entry fails the gate.
type ignoreEntry struct {
	eco, name string
	expires   time.Time
	reason    string
	line      int
	used      bool
}

func (e *ignoreEntry) expired(now time.Time) bool {
	return now.UTC().After(e.expires.Add(24*time.Hour - time.Nanosecond))
}

type ignoreList []*ignoreEntry

func readIgnore(path string) (ignoreList, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseIgnore(path, data)
}

func parseIgnore(name string, data []byte) (ignoreList, error) {
	var out ignoreList
	seen := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			return nil, fmt.Errorf("%s:%d: want <go|cargo> <name> <expires YYYY-MM-DD> <reason>", name, n)
		}
		if f[0] != "go" && f[0] != "cargo" {
			return nil, fmt.Errorf("%s:%d: ecosystem %q is not go or cargo", name, n, f[0])
		}
		exp, err := time.Parse(time.DateOnly, f[2])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: expiry %q is not a YYYY-MM-DD date", name, n, f[2])
		}
		key := f[0] + " " + f[1]
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("%s:%d: %s is already listed on line %d", name, n, key, prev)
		}
		seen[key] = n
		out = append(out, &ignoreEntry{
			eco: f[0], name: f[1], expires: exp, line: n,
			reason: strings.Join(f[3:], " "),
		})
	}
	return out, sc.Err()
}

func (l ignoreList) find(eco, name string) *ignoreEntry {
	for _, e := range l {
		if e.eco == eco && e.name == name {
			return e
		}
	}
	return nil
}
