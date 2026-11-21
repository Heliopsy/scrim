package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRenovateSeesEveryAnnotation runs the extraction on this repository:
// every "renovate:" annotation must be matched by a custom manager of
// renovate.json (a typo would leave a pin that neither Renovate nor -pins
// sees), every manager must match something, and every sha256 annotation
// must belong to a pin.
func TestRenovateSeesEveryAnnotation(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := readRenovate(filepath.Join(root, "renovate.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := trackedFiles(root)
	if err != nil {
		t.Skip("not a git checkout:", err)
	}
	ex, err := extractPins(root, files, cfg)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	perManager := map[int]int{}
	for _, e := range ex {
		perManager[e.manager]++
		seen[e.pin.where[0]] = true
		if e.pin.datasource == "" || e.pin.depName == "" || e.pin.currentValue == "" {
			t.Errorf("%s: incomplete pin %+v", e.pin.where[0], e.pin)
		}
	}
	for i, m := range cfg.CustomManagers {
		if m.CustomType == "regex" && perManager[i] == 0 {
			t.Errorf("customManagers[%d] matches nothing", i)
		}
	}
	ann := regexp.MustCompile(`^\s*(#|//) renovate: `)
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if ann.MatchString(line) && !strings.HasSuffix(f, "_test.go") && !strings.HasSuffix(f, ".md") {
				n++
				if !seen[f+":"+strconv.Itoa(i+2)] {
					t.Errorf("%s:%d: annotation no custom manager in renovate.json picks up", f, i+1)
				}
			}
		}
	}
	if n < 20 {
		t.Errorf("only %d annotations found; is the pattern still right?", n)
	}
	if _, err := scanSums(root, files); err != nil {
		t.Error(err)
	}
}

func TestExtractForms(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.sh", "# renovate: datasource=github-releases depName=o/r extractVersion=^v(?<version>.+)$\nX_VERSION=1.2.3\n"+
		"# renovate: datasource=github-releases depName=o/k8s\nK=\"${K:-1.37.2}\"\n")
	writeFile(t, dir, "w.yaml", "      run: pip install --quiet a==1.0 b-c==2.0.1\n        # renovate: datasource=npm depName=x\n        V: \"3.0.0\"\n")
	writeFile(t, dir, "x.go", "// renovate: datasource=docker depName=docker.io/o/img\nconst v = \"v0.1.2\"\n")
	cfg := &renovateConfig{CustomManagers: []customManager{
		{CustomType: "regex", ManagerFilePatterns: []string{`/\.(sh|yaml|go)$/`}, MatchStrings: []string{
			`(?:#|//) renovate: datasource=(?<datasource>\S+) depName=(?<depName>\S+)(?: extractVersion=(?<extractVersion>\S+))?\n\s*(?:const |export )?[A-Za-z0-9_]+(?: = |=|: )"?(?:\$\{[A-Za-z0-9_]+:-)?(?<currentValue>[^"\s}]+)`,
		}},
		{CustomType: "regex", ManagerFilePatterns: []string{`/\.yaml$/`}, MatchStringsStrategy: "recursive",
			MatchStrings:       []string{`pip"? install [^\n]+`, `(?<depName>[a-z][a-z0-9_.-]*)==(?<currentValue>[0-9][^\s]*)`},
			DatasourceTemplate: "pypi"},
	}}
	ex, err := extractPins(dir, []string{"a.sh", "w.yaml", "x.go"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ex {
		got = append(got, fmt.Sprintf("%s %s %s %s %s", e.pin.where[0], e.pin.datasource, e.pin.depName, e.pin.currentValue, e.pin.extractVersion))
	}
	want := []string{
		"a.sh:2 github-releases o/r 1.2.3 ^v(?<version>.+)$",
		"a.sh:4 github-releases o/k8s 1.37.2 ",
		"w.yaml:3 npm x 3.0.0 ",
		"x.go:2 docker docker.io/o/img v0.1.2 ",
		"w.yaml:1 pypi a 1.0 ",
		"w.yaml:1 pypi b-c 2.0.1 ",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestNewerPicksCompatibleReleases(t *testing.T) {
	rels := func(vs ...string) []release {
		var out []release
		for _, v := range vs {
			out = append(out, release{version: v, pre: strings.Contains(v, "rc")})
		}
		return out
	}
	cases := []struct {
		p    pin
		rels []release
		want string
	}{
		{pin{currentValue: "19.0-alpine3.24"}, rels("19.1-alpine3.24", "20.0-alpine3.25", "20", "20.0", "19.2-alpine3.24"), "19.2-alpine3.24"},
		{pin{currentValue: "v0.30.0"}, rels("v0.33.0", "v0.34.0-rc.1", "v0.29.0"), "v0.33.0"},
		{pin{currentValue: "v3.22.1", allowedVersions: "<4.0.0"}, rels("v4.3.2", "v3.22.2", "v3.22.0"), "v3.22.2"},
		{pin{currentValue: "26.04", versioning: "ubuntu"}, rels("26.10", "27.04", "28.04", "25.10"), "28.04"},
		{pin{currentValue: "3.9.2"}, rels("3.9.2", "3.9.1"), ""},
	}
	for _, c := range cases {
		got, err := newer(c.p, c.rels)
		if err != nil {
			t.Fatal(err)
		}
		first := ""
		if len(got) > 0 {
			first = got[0].version
		}
		if first != c.want {
			t.Errorf("%s: newest replacement %q, want %q (%v)", c.p.currentValue, first, c.want, got)
		}
	}
}

// TestCheckPinGrace checks a pin and an action against a fake GitHub API: a
// release past the grace period fails, one inside it is pending, and an
// action whose SHA is not its tag is an error.
func TestCheckPinGrace(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no token", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/repos/o/old/releases":
			writeJSON(w, []map[string]any{
				{"tag_name": "v1.3.0", "published_at": now.Add(-2 * 24 * time.Hour)},
				{"tag_name": "v1.2.0", "published_at": now.Add(-30 * 24 * time.Hour)},
				{"tag_name": "v1.1.0", "published_at": now.Add(-60 * 24 * time.Hour)},
			})
		case "/repos/o/new/releases":
			writeJSON(w, []map[string]any{{"tag_name": "v2.1.0", "published_at": now.Add(-3 * 24 * time.Hour)}, {"tag_name": "v2.0.0", "published_at": now.Add(-90 * 24 * time.Hour)}})
		case "/repos/o/act/git/ref/tags/v1.0.0":
			writeJSON(w, map[string]any{"object": map[string]string{"type": "tag", "sha": "t1"}})
		case "/repos/o/act/git/tags/t1":
			writeJSON(w, map[string]any{"object": map[string]string{"type": "commit", "sha": strings.Repeat("a", 40)}})
		case "/repos/o/act/releases":
			writeJSON(w, []map[string]any{{"tag_name": "v1.0.0", "published_at": now.Add(-90 * 24 * time.Hour)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()
	src := newSources(options{githubAPI: gh.URL, githubToken: "tok"})
	grace := 14 * 24 * time.Hour
	ctx := context.Background()

	r := checkPin(ctx, src, pin{datasource: "github-releases", depName: "o/old", packageName: "o/old", currentValue: "v1.1.0", where: []string{"f:1"}}, now, grace)
	if r.status != statusBehind || r.latest != "v1.3.0" || !strings.Contains(r.note, "v1.2.0 is past the grace period") {
		t.Errorf("behind: %+v", r)
	}
	r = checkPin(ctx, src, pin{datasource: "github-releases", depName: "o/new", packageName: "o/new", currentValue: "v2.0.0", where: []string{"f:1"}}, now, grace)
	if r.status != statusPending || r.status.fails() {
		t.Errorf("pending: %+v", r)
	}
	act := pin{datasource: "github-releases", depName: "o/act", packageName: "o/act", currentValue: "v1.0.0", currentDigest: strings.Repeat("a", 40), action: true, where: []string{"f:1"}}
	if r = checkPin(ctx, src, act, now, grace); r.status != statusOK || r.eco != "action" {
		t.Errorf("action: %+v", r)
	}
	act.currentDigest = strings.Repeat("b", 40)
	if r = checkPin(ctx, src, act, now, grace); r.status != statusError || !strings.Contains(r.note, "is not v1.0.0") {
		t.Errorf("action with a foreign SHA: %+v", r)
	}
}

// TestDockerTags lists tags from a fake registry that wants an anonymous
// bearer token and pages its tag list, then reads a creation date through an
// image index.
func TestDockerTags(t *testing.T) {
	created := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if r.URL.Query().Get("scope") != "repository:o/img:pull" {
				http.Error(w, "scope", http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"token": "t"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer t" {
			w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:o/img:pull"`, srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path + "?" + r.URL.RawQuery {
		case "/v2/o/img/tags/list?n=1000":
			w.Header().Set("Link", `</v2/o/img/tags/list?n=1000&last=1.1>; rel="next"`)
			writeJSON(w, map[string]any{"tags": []string{"1.0", "1.1"}})
		case "/v2/o/img/tags/list?n=1000&last=1.1":
			writeJSON(w, map[string]any{"tags": []string{"1.2", "latest"}})
		case "/v2/o/img/manifests/1.2?":
			writeJSON(w, map[string]any{"manifests": []map[string]any{
				{"digest": "sha256:arm", "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
				{"digest": "sha256:amd", "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
			}})
		case "/v2/o/img/manifests/sha256:amd?":
			writeJSON(w, map[string]any{"config": map[string]string{"digest": "sha256:cfg"}})
		case "/v2/o/img/blobs/sha256:cfg?":
			writeJSON(w, map[string]any{"created": created})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	src := newSources(options{insecureRegistries: []string{host}})
	rels, err := src.dockerTags(context.Background(), host+"/o/img")
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, r := range rels {
		tags = append(tags, r.version)
	}
	if strings.Join(tags, ",") != "1.0,1.1,1.2,latest" {
		t.Errorf("tags %v", tags)
	}
	d, err := src.dockerCreated(context.Background(), host+"/o/img", "1.2")
	if err != nil || !d.Equal(created) {
		t.Errorf("created %v, %v", d, err)
	}
	if h, r := splitImage("docker.io/library/postgres"); h != "registry-1.docker.io" || r != "library/postgres" {
		t.Errorf("docker.io: %s %s", h, r)
	}
}

func TestParseHelmIndex(t *testing.T) {
	idx := `apiVersion: v1
entries:
  kyverno:
  - annotations:
      a: b
    appVersion: v1.20.0
    created: "2026-11-18T10:00:00.5Z"
    dependencies:
    - name: crds
      version: 9.9.9
    name: kyverno
    version: 3.10.0
  - apiVersion: v2
    created: "2026-11-11T10:00:00Z"
    version: 3.10.0-rc.1
  kyverno-policies:
  - created: "2026-11-18T10:00:00Z"
    version: 3.10.1
generated: "2026-11-19T00:00:00Z"
`
	got := parseHelmIndex(idx, "kyverno")
	if len(got) != 2 || got[0].version != "3.10.0" || got[0].date.IsZero() || !got[1].pre {
		t.Errorf("got %+v", got)
	}
}

// TestSums rewrites a stale sum with -fix and fails without it.
func TestSums(t *testing.T) {
	asset := []byte("release asset bytes")
	sum := sha256.Sum256(asset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dl/v1.2.0/tool.tgz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(asset)
	}))
	defer srv.Close()
	dir := t.TempDir()
	stale := strings.Repeat("0", 64)
	body := "# renovate: datasource=github-releases depName=o/tool\nTOOL_VERSION=v1.2.0\n# sha256: " + srv.URL + "/dl/{version}/tool.tgz\nTOOL_SHA256=" + stale + "\n"
	writeFile(t, dir, "tools.env", body)
	for _, args := range [][]string{{"init", "-q"}, {"add", "tools.env"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	opts := options{root: dir, jobs: 2}
	var out bytes.Buffer
	if code, err := runSums(context.Background(), opts, &out); err != nil || code != 1 || !strings.Contains(out.String(), "MISMATCH") {
		t.Fatalf("stale sum: exit %d, %v:\n%s", code, err, out.String())
	}
	opts.fix = true
	out.Reset()
	if code, err := runSums(context.Background(), opts, &out); err != nil || code != 0 {
		t.Fatalf("fix: exit %d, %v:\n%s", code, err, out.String())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "tools.env"))
	if want := strings.Replace(body, stale, hex.EncodeToString(sum[:]), 1); string(data) != want {
		t.Errorf("after -fix:\n%s", data)
	}
	opts.fix = false
	out.Reset()
	if code, _ := runSums(context.Background(), opts, &out); code != 0 {
		t.Errorf("fixed sum still fails:\n%s", out.String())
	}
}

func TestParseIgnoreTakesPinsAndActions(t *testing.T) {
	l, err := parseIgnore("f", []byte("pin kyverno 2027-01-31 waits for the chart\naction o/r 2027-01-31 reason\n"))
	if err != nil || l.find("pin", "kyverno") == nil || l.find("action", "o/r") == nil {
		t.Fatalf("%v %v", l, err)
	}
}

func writeFile(t *testing.T, dir, name, s string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
