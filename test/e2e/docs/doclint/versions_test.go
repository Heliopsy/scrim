// SPDX-License-Identifier: AGPL-3.0-only

package doclint

import (
	"encoding/json"
	"regexp"
	"strconv"
	"testing"
)

const semver = `(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`

// scrimVersion matches the places a doc names a scrim release: the images,
// the chart, archive and directory names, `scrim 1.2.0` or `scrim v1.2.0` in
// prose and version output, release URLs, and the variables and fields the
// install and GitOps examples pin a version with.
var scrimVersion = []*regexp.Regexp{
	regexp.MustCompile(`ghcr\.io/heliopsy/scrim(?:-dataplane)?:v?` + semver),
	regexp.MustCompile(`charts/scrim\b.*--version[ =]v?` + semver),
	regexp.MustCompile(`\bscrim[-_]v?` + semver),
	regexp.MustCompile(`(?i)\bscrim v?` + semver),
	regexp.MustCompile(`\bchart v?` + semver),
	regexp.MustCompile(`heliopsy/scrim/releases/(?:download|tag)/v` + semver),
	regexp.MustCompile(`\b(?:VERSION|scrim_version|SCRIM_VERSION)=["']?v?` + semver),
	regexp.MustCompile(`\b(?:newTag|ref\.tag|tag):\s*["']?v?` + semver),
	regexp.MustCompile(`\btag=v` + semver),
}

// releasedVersions returns every scrim version a doc may name: the versions
// CHANGELOG.md has a section for (release-please writes one per release), the
// base of each section's compare link (which covers the first release, made
// before the changelog), and the release-please manifest version. Git tags are
// not read: most CI checkouts are shallow and have none, and the answer must
// not depend on how the repository was cloned.
func releasedVersions(t *testing.T, root string) map[string]bool {
	out := map[string]bool{}
	changelog := string(readFile(t, root, "CHANGELOG.md"))
	heading := regexp.MustCompile(`(?m)^## \[` + semver + `\]`)
	for _, m := range heading.FindAllStringSubmatch(changelog, -1) {
		out[m[1]] = true
	}
	compare := regexp.MustCompile(`(?m)^## \[[^\]]+\]\(https://github\.com/Heliopsy/scrim/compare/v` + semver + `\.\.\.`)
	for _, m := range compare.FindAllStringSubmatch(changelog, -1) {
		out[m[1]] = true
	}
	var manifest map[string]string
	if err := json.Unmarshal(readFile(t, root, ".release-please-manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["."] == "" {
		t.Fatal(".release-please-manifest.json has no version for the root package")
	}
	out[manifest["."]] = true
	return out
}

// TestReleaseVersions checks that every scrim release a doc names exists:
// no example upgrades to a version that was never published.
func TestReleaseVersions(t *testing.T) {
	root := repoRoot(t)
	released := releasedVersions(t, root)
	var found []Violation
	seen := 0
	for _, f := range referenceDocs(t, root) {
		for _, l := range lines(readFile(t, root, f)) {
			for _, re := range scrimVersion {
				for _, m := range re.FindAllStringSubmatch(l.Text, -1) {
					seen++
					if !released[m[1]] {
						found = append(found, violation("version", f, l.N, m[1],
							"scrim %s was never released (%q)", m[1], m[0]))
					}
				}
			}
		}
	}
	t.Logf("%d scrim versions checked against %d released", seen, len(released))
	report(t, root, "version", dedupe(found))
}

// dedupe drops repeats of one subject on one line (two patterns matching
// the same text).
func dedupe(vs []Violation) []Violation {
	seen := map[string]bool{}
	var out []Violation
	for _, v := range vs {
		k := v.key() + "\x00" + strconv.Itoa(v.Line)
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}
