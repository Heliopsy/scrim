package main

import (
	"strconv"
	"strings"
)

// version is a semantic version. Build metadata is dropped; a version with a
// pre-release part is never a stable release.
type version struct {
	major, minor, patch int64
	pre                 string
}

// parseVersion reads "1", "1.2", "1.2.3", "v1.2.3", "1.2.3-rc.1" and
// "1.2.3+build". Missing minor or patch parts are zero.
func parseVersion(s string) (version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v version
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.pre = s[i+1:]
		s = s[:i]
		if v.pre == "" {
			return version{}, false
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return version{}, false
	}
	nums := [3]int64{}
	for i, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 || p == "" {
			return version{}, false
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	return v, true
}

func (v version) stable() bool { return v.pre == "" }

func (v version) String() string {
	s := strconv.FormatInt(v.major, 10) + "." + strconv.FormatInt(v.minor, 10) + "." + strconv.FormatInt(v.patch, 10)
	if v.pre != "" {
		s += "-" + v.pre
	}
	return s
}

// compare orders versions; a pre-release sorts before its release. Only
// stable versions are ever compared for the gate, so pre-release identifiers
// are compared as plain strings.
func compare(a, b version) int {
	for _, d := range [3]int64{a.major - b.major, a.minor - b.minor, a.patch - b.patch} {
		switch {
		case d < 0:
			return -1
		case d > 0:
			return 1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	case a.pre < b.pre:
		return -1
	default:
		return 1
	}
}

// breakingLine is the release line within which Cargo treats versions as
// compatible: the major for 1.0 and later, 0.minor before that, and 0.0.patch
// for 0.0 versions.
type breakingLine [3]int64

func lineOf(v version) breakingLine {
	switch {
	case v.major > 0:
		return breakingLine{v.major, -1, -1}
	case v.minor > 0:
		return breakingLine{0, v.minor, -1}
	default:
		return breakingLine{0, 0, v.patch}
	}
}

func (l breakingLine) less(o breakingLine) bool {
	for i := range l {
		if l[i] != o[i] {
			return l[i] < o[i]
		}
	}
	return false
}

// latestStable returns the newest stable version among vs.
func latestStable(vs []string) (version, bool) {
	var best version
	found := false
	for _, s := range vs {
		v, ok := parseVersion(s)
		if !ok || !v.stable() {
			continue
		}
		if !found || compare(v, best) > 0 {
			best, found = v, true
		}
	}
	return best, found
}
