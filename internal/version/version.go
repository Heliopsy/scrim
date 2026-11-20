// SPDX-License-Identifier: AGPL-3.0-only

// Package version holds build-time version information injected via ldflags,
// falling back to what the Go toolchain recorded when they were not.
package version

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

// These variables are set at build time via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// When the ldflags were not passed (go install, go build in a checkout),
// fill what the toolchain recorded: the module version for an install, the
// VCS revision, time and dirty flag for a build from a working tree.
func init() { fill(debug.ReadBuildInfo) }

func fill(read func() (*debug.BuildInfo, bool)) {
	info, ok := read()
	if !ok {
		return
	}

	if Version == "dev" && isRelease(info.Main.Version) {
		Version = strings.TrimPrefix(info.Main.Version, "v")
	}

	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if Commit == "none" && s.Value != "" {
				Commit = s.Value
			}
		case "vcs.time":
			if Date == "unknown" && s.Value != "" {
				Date = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}

	if dirty && Commit != "none" && !strings.HasSuffix(Commit, "-dirty") {
		Commit += "-dirty"
	}
}

// pseudo matches the version the module system invents for a commit that no
// tag points at: a timestamp and a short revision, appended to the tag after
// the one it follows.
var pseudo = regexp.MustCompile(`[0-9]{14}-[0-9a-f]{12}(\+[0-9A-Za-z.-]+)?$`)

// isRelease reports whether a recorded module version names a release. A
// build from a working tree records a pseudo-version naming the release after
// the newest tag, which was never released, so it keeps "dev".
func isRelease(v string) bool {
	return v != "" && v != "(devel)" && !pseudo.MatchString(v)
}

// String returns a formatted version string.
func String() string {
	return fmt.Sprintf("scrim %s (commit: %s, built: %s, %s/%s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
}
