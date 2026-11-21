package main

// Datasources for -pins: GitHub releases, tags and commits, npm, PyPI,
// container registries, Helm repositories, crates.io, the Go module proxy and
// go.dev. Lookups are cached per package, so a pin written in several files
// costs one.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultGitHubAPI = "https://api.github.com"
	defaultNPM       = "https://registry.npmjs.org"
	defaultPyPI      = "https://pypi.org"
	defaultGoDev     = "https://go.dev"
)

type sources struct {
	reg                    *registry
	github, npm, pypi, god string
	token                  string
	insecureHosts          map[string]bool // test registries served over http

	mu    sync.Mutex
	cache map[string]*cached
}

type cached struct {
	once sync.Once
	rels []release
	err  error
}

func newSources(opts options) *sources {
	s := &sources{
		reg:    newRegistry(opts.goProxy, opts.cratesIndex),
		github: strings.TrimSuffix(opts.githubAPI, "/"), npm: strings.TrimSuffix(opts.npm, "/"),
		pypi: strings.TrimSuffix(opts.pypi, "/"), god: strings.TrimSuffix(opts.goDev, "/"),
		token: opts.githubToken, insecureHosts: map[string]bool{}, cache: map[string]*cached{},
	}
	for _, h := range opts.insecureRegistries {
		s.insecureHosts[h] = true
	}
	return s
}

// memo runs fn once per key.
func (s *sources) memo(key string, fn func() ([]release, error)) ([]release, error) {
	s.mu.Lock()
	c, ok := s.cache[key]
	if !ok {
		c = &cached{}
		s.cache[key] = c
	}
	s.mu.Unlock()
	c.once.Do(func() { c.rels, c.err = fn() })
	return c.rels, c.err
}

// releases lists what the pin's datasource offers. supported is false for a
// datasource this check does not read.
func (s *sources) releases(ctx context.Context, p pin) (rels []release, supported bool, err error) {
	key := p.datasource + "|" + p.packageName + "|" + p.registryURL
	var fn func() ([]release, error)
	switch p.datasource {
	case "github-releases":
		fn = func() ([]release, error) { return s.githubReleases(ctx, p.packageName) }
	case "github-tags":
		fn = func() ([]release, error) { return s.githubTags(ctx, p.packageName) }
	case "npm":
		fn = func() ([]release, error) { return s.npmVersions(ctx, p.packageName) }
	case "pypi":
		fn = func() ([]release, error) { return s.pypiVersions(ctx, p.packageName) }
	case "docker":
		fn = func() ([]release, error) { return s.dockerTags(ctx, p.packageName) }
	case "helm":
		fn = func() ([]release, error) { return s.helmVersions(ctx, p.registryURL, p.packageName) }
	case "crate":
		fn = func() ([]release, error) {
			vs, err := s.reg.crateVersions(ctx, p.packageName)
			return plain(vs), err
		}
	case "go":
		fn = func() ([]release, error) {
			vs, _, err := s.reg.goVersions(ctx, p.packageName)
			return plain(vs), err
		}
	case "golang-version":
		fn = func() ([]release, error) { return s.goReleases(ctx) }
	default:
		return nil, false, nil
	}
	rels, err = s.memo(key, fn)
	if err != nil {
		return nil, true, err
	}
	if p.extractVersion == "" {
		return rels, true, nil
	}
	re, err := regexp.Compile(p.extractVersion)
	if err != nil {
		return nil, true, fmt.Errorf("extractVersion %q: %w", p.extractVersion, err)
	}
	i := re.SubexpIndex("version")
	var out []release
	for _, r := range rels {
		m := re.FindStringSubmatch(r.version)
		if m == nil {
			continue
		}
		if i >= 0 {
			r.version = m[i]
		} else {
			r.version = m[0]
		}
		out = append(out, r)
	}
	return out, true, nil
}

func plain(vs []string) []release {
	out := make([]release, 0, len(vs))
	for _, v := range vs {
		pv, ok := parseVersion(v)
		out = append(out, release{version: v, pre: ok && !pv.stable()})
	}
	return out
}

// releaseDate looks up when a release without a date in its listing came out.
// Zero means unknown: the release counts as past the grace period.
func (s *sources) releaseDate(ctx context.Context, p pin, ver string) (time.Time, error) {
	switch p.datasource {
	case "github-tags":
		tag := ver
		if p.extractVersion != "" {
			// The tag is what was listed; find it again.
			rels, err := s.memo(p.datasource+"|"+p.packageName+"|"+p.registryURL, nil)
			if err != nil {
				return time.Time{}, err
			}
			re := regexp.MustCompile(p.extractVersion)
			for _, r := range rels {
				if m := re.FindStringSubmatch(r.version); m != nil && m[re.SubexpIndex("version")] == ver {
					tag = r.version
				}
			}
		}
		return s.githubCommitDate(ctx, p.packageName, tag)
	case "docker":
		return s.dockerCreated(ctx, p.packageName, ver)
	case "go":
		body, found, err := s.reg.get(ctx, s.reg.goProxy+"/"+escapeModulePath(p.packageName)+"/@v/"+ver+".info")
		if err != nil || !found {
			return time.Time{}, err
		}
		var info struct{ Time time.Time }
		if err := json.Unmarshal(body, &info); err != nil {
			return time.Time{}, err
		}
		return info.Time, nil
	}
	return time.Time{}, nil
}

// ---------------------------------------------------------------- GitHub

func (s *sources) githubGet(ctx context.Context, path string, out any) (bool, error) {
	hdr := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	if s.token != "" {
		hdr["Authorization"] = "Bearer " + s.token
	}
	body, _, found, err := s.reg.getWith(ctx, s.github+path, hdr, 32<<20)
	if err != nil || !found {
		return found, err
	}
	return true, json.Unmarshal(body, out)
}

func (s *sources) githubReleases(ctx context.Context, repo string) ([]release, error) {
	var out []release
	for page := 1; page <= 3; page++ {
		var rs []struct {
			TagName     string    `json:"tag_name"`
			Draft       bool      `json:"draft"`
			Prerelease  bool      `json:"prerelease"`
			PublishedAt time.Time `json:"published_at"`
		}
		found, err := s.githubGet(ctx, fmt.Sprintf("/repos/%s/releases?per_page=100&page=%d", repo, page), &rs)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("github.com/%s has no releases", repo)
		}
		for _, r := range rs {
			if !r.Draft {
				out = append(out, release{version: r.TagName, date: r.PublishedAt, pre: r.Prerelease})
			}
		}
		if len(rs) < 100 {
			break
		}
	}
	return out, nil
}

func (s *sources) githubTags(ctx context.Context, repo string) ([]release, error) {
	var refs []struct {
		Ref string `json:"ref"`
	}
	found, err := s.githubGet(ctx, "/repos/"+repo+"/git/matching-refs/tags/", &refs)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("github.com/%s not found", repo)
	}
	out := make([]release, 0, len(refs))
	for _, r := range refs {
		out = append(out, release{version: strings.TrimPrefix(r.Ref, "refs/tags/")})
	}
	return out, nil
}

func (s *sources) githubCommitDate(ctx context.Context, repo, ref string) (time.Time, error) {
	var c struct {
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	found, err := s.githubGet(ctx, "/repos/"+repo+"/commits/"+url.PathEscape(ref), &c)
	if err != nil || !found {
		return time.Time{}, err
	}
	return c.Commit.Committer.Date, nil
}

// githubTagCommit resolves a tag to its commit, dereferencing annotated tags.
func (s *sources) githubTagCommit(ctx context.Context, repo, tag string) (string, error) {
	var ref struct {
		Object struct{ Type, SHA string } `json:"object"`
	}
	found, err := s.githubGet(ctx, "/repos/"+repo+"/git/ref/tags/"+tag, &ref)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("github.com/%s has no tag %s", repo, tag)
	}
	for range 3 {
		if ref.Object.Type != "tag" {
			break
		}
		var t struct {
			Object struct{ Type, SHA string } `json:"object"`
		}
		if _, err := s.githubGet(ctx, "/repos/"+repo+"/git/tags/"+ref.Object.SHA, &t); err != nil {
			return "", err
		}
		ref.Object = t.Object
	}
	return ref.Object.SHA, nil
}

// commitsAfter compares a pinned commit with a branch of a GitHub repository
// (packageName is its https URL): how many commits the branch is ahead, the
// date of the first of them and the head.
func (s *sources) commitsAfter(ctx context.Context, gitURL, base, branch string) (int, time.Time, string, error) {
	repo := strings.TrimSuffix(strings.TrimPrefix(gitURL, "https://github.com/"), ".git")
	if repo == gitURL {
		return 0, time.Time{}, "", fmt.Errorf("git-refs %s: only github.com repositories are checked", gitURL)
	}
	var c struct {
		Status  string `json:"status"`
		AheadBy int    `json:"ahead_by"`
		Commits []struct {
			SHA    string `json:"sha"`
			Commit struct {
				Committer struct {
					Date time.Time `json:"date"`
				} `json:"committer"`
			} `json:"commit"`
		} `json:"commits"`
	}
	found, err := s.githubGet(ctx, "/repos/"+repo+"/compare/"+base+"..."+branch+"?per_page=100", &c)
	if err != nil {
		return 0, time.Time{}, "", err
	}
	if !found {
		return 0, time.Time{}, "", fmt.Errorf("%s: cannot compare %s with %s", gitURL, short(base), branch)
	}
	if c.AheadBy == 0 || len(c.Commits) == 0 {
		return 0, time.Time{}, base, nil
	}
	first := c.Commits[0].Commit.Committer.Date
	for _, cm := range c.Commits {
		if cm.Commit.Committer.Date.Before(first) {
			first = cm.Commit.Committer.Date
		}
	}
	return c.AheadBy, first, c.Commits[len(c.Commits)-1].SHA, nil
}

// ---------------------------------------------------------------- npm, PyPI, go.dev

func (s *sources) npmVersions(ctx context.Context, name string) ([]release, error) {
	body, _, found, err := s.reg.getWith(ctx, s.npm+"/"+strings.Replace(name, "/", "%2F", 1), nil, 256<<20)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("npm has no package %s", name)
	}
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]time.Time       `json:"time"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("npm %s: %w", name, err)
	}
	out := make([]release, 0, len(doc.Versions))
	for v := range doc.Versions {
		pv, ok := parseVersion(v)
		out = append(out, release{version: v, date: doc.Time[v], pre: !ok || !pv.stable()})
	}
	return out, nil
}

func (s *sources) pypiVersions(ctx context.Context, name string) ([]release, error) {
	body, found, err := s.reg.get(ctx, s.pypi+"/pypi/"+name+"/json")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("PyPI has no package %s", name)
	}
	var doc struct {
		Releases map[string][]struct {
			Upload time.Time `json:"upload_time_iso_8601"`
			Yanked bool      `json:"yanked"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("PyPI %s: %w", name, err)
	}
	var out []release
	for v, files := range doc.Releases {
		if len(files) == 0 || files[0].Yanked {
			continue
		}
		pre := strings.ContainsAny(v, "abrcdev")
		out = append(out, release{version: v, date: files[0].Upload, pre: pre})
	}
	return out, nil
}

func (s *sources) goReleases(ctx context.Context) ([]release, error) {
	body, found, err := s.reg.get(ctx, s.god+"/dl/?mode=json&include=all")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("go.dev/dl: not found")
	}
	var rs []struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
	}
	if err := json.Unmarshal(body, &rs); err != nil {
		return nil, err
	}
	out := make([]release, 0, len(rs))
	for _, r := range rs {
		out = append(out, release{version: strings.TrimPrefix(r.Version, "go"), pre: !r.Stable})
	}
	return out, nil
}

// ---------------------------------------------------------------- Helm

// helmVersions reads a chart's versions and dates from a repository's
// index.yaml without a YAML parser: entries.<chart> is a list whose items
// carry version and created at the item's top level.
func (s *sources) helmVersions(ctx context.Context, repoURL, chart string) ([]release, error) {
	if repoURL == "" {
		return nil, fmt.Errorf("helm chart %s has no registryUrl", chart)
	}
	body, _, found, err := s.reg.getWith(ctx, strings.TrimSuffix(repoURL, "/")+"/index.yaml", nil, 128<<20)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%s has no index.yaml", repoURL)
	}
	return parseHelmIndex(string(body), chart), nil
}

func parseHelmIndex(index, chart string) []release {
	var out []release
	inEntries, inChart := false, false
	var cur *release
	flush := func() {
		if cur != nil && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(strings.NewReader(index))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "entries:":
			inEntries = true
			continue
		case inEntries && line != "" && line[0] != ' ':
			flush()
			inEntries, inChart = false, false
			continue
		}
		if !inEntries {
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && !strings.HasPrefix(line, "  - ") && strings.HasSuffix(line, ":") {
			flush()
			inChart = strings.TrimSuffix(strings.TrimSpace(line), ":") == chart
			continue
		}
		if !inChart {
			continue
		}
		key := ""
		if rest, ok := strings.CutPrefix(line, "  - "); ok {
			flush()
			cur = &release{}
			key = rest
		} else if rest, ok := strings.CutPrefix(line, "    "); ok && !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "-") {
			key = rest
		}
		if cur == nil || key == "" {
			continue
		}
		k, v, ok := strings.Cut(key, ": ")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "version":
			cur.version = v
			pv, ok := parseVersion(v)
			cur.pre = !ok || !pv.stable()
		case "created":
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				cur.date = t
			}
		}
	}
	flush()
	return out
}

// ---------------------------------------------------------------- containers

// splitImage turns docker.io/library/postgres into the registry host to call
// and the repository path.
func splitImage(image string) (host, repo string) {
	host, repo, ok := strings.Cut(image, "/")
	if !ok || !strings.ContainsAny(host, ".:") {
		host, repo = "docker.io", image
	}
	if host == "docker.io" {
		host = "registry-1.docker.io"
		if !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
	}
	return host, repo
}

var authParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// registryGet calls a registry's v2 API, fetching an anonymous pull token
// when the registry asks for one.
func (s *sources) registryGet(ctx context.Context, host, repo, path string, hdr map[string]string, token *string) ([]byte, map[string][]string, bool, error) {
	scheme := "https://"
	if s.insecureHosts[host] {
		scheme = "http://"
	}
	u := path
	if !strings.HasPrefix(path, "http") {
		u = scheme + host + path
	}
	h := map[string]string{}
	for k, v := range hdr {
		h[k] = v
	}
	for attempt := 0; attempt < 2; attempt++ {
		if *token != "" {
			h["Authorization"] = "Bearer " + *token
		}
		body, rh, found, err := s.reg.getWith(ctx, u, h, 64<<20)
		var ae *authError
		if errors.As(err, &ae) && attempt == 0 {
			t, terr := s.registryToken(ctx, ae.header.Get("Www-Authenticate"), repo)
			if terr != nil {
				return nil, nil, false, terr
			}
			*token = t
			continue
		}
		return body, rh, found, err
	}
	return nil, nil, false, fmt.Errorf("GET %s: refused after authenticating", u)
}

func (s *sources) registryToken(ctx context.Context, challenge, repo string) (string, error) {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", fmt.Errorf("registry wants %q authentication", scheme)
	}
	p := map[string]string{}
	for _, m := range authParam.FindAllStringSubmatch(params, -1) {
		p[m[1]] = m[2]
	}
	if p["realm"] == "" {
		return "", fmt.Errorf("registry challenge %q has no realm", challenge)
	}
	q := url.Values{}
	if p["service"] != "" {
		q.Set("service", p["service"])
	}
	scope := p["scope"]
	if scope == "" {
		scope = "repository:" + repo + ":pull"
	}
	q.Set("scope", scope)
	body, found, err := s.reg.get(ctx, p["realm"]+"?"+q.Encode())
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("token endpoint %s not found", p["realm"])
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return "", err
	}
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	return t.Token, nil
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func (s *sources) dockerTags(ctx context.Context, image string) ([]release, error) {
	host, repo := splitImage(image)
	var token string
	path := "/v2/" + repo + "/tags/list?n=1000"
	var out []release
	for page := 0; page < 50 && path != ""; page++ {
		body, h, found, err := s.registryGet(ctx, host, repo, path, nil, &token)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%s: no such repository", image)
		}
		var tl struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &tl); err != nil {
			return nil, fmt.Errorf("%s tags: %w", image, err)
		}
		for _, t := range tl.Tags {
			out = append(out, release{version: t})
		}
		path = ""
		for _, l := range h["Link"] {
			if m := nextLink.FindStringSubmatch(l); m != nil {
				path = m[1]
			}
		}
	}
	return out, nil
}

// dockerCreated reads the creation time from the image config of a tag
// (linux/amd64 for an index).
func (s *sources) dockerCreated(ctx context.Context, image, tag string) (time.Time, error) {
	host, repo := splitImage(image)
	var token string
	accept := map[string]string{"Accept": strings.Join([]string{
		"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json",
	}, ", ")}
	ref := tag
	for range 2 {
		body, _, found, err := s.registryGet(ctx, host, repo, "/v2/"+repo+"/manifests/"+ref, accept, &token)
		if err != nil || !found {
			return time.Time{}, err
		}
		var m struct {
			Manifests []struct {
				Digest   string `json:"digest"`
				Platform struct {
					OS           string `json:"os"`
					Architecture string `json:"architecture"`
				} `json:"platform"`
			} `json:"manifests"`
			Config struct {
				Digest string `json:"digest"`
			} `json:"config"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			return time.Time{}, err
		}
		if m.Config.Digest != "" {
			cfg, _, found, err := s.registryGet(ctx, host, repo, "/v2/"+repo+"/blobs/"+m.Config.Digest, nil, &token)
			if err != nil || !found {
				return time.Time{}, err
			}
			var c struct {
				Created time.Time `json:"created"`
			}
			if err := json.Unmarshal(cfg, &c); err != nil {
				return time.Time{}, err
			}
			return c.Created, nil
		}
		ref = ""
		for _, d := range m.Manifests {
			if d.Platform.OS == "linux" && d.Platform.Architecture == "amd64" {
				ref = d.Digest
			}
		}
		if ref == "" {
			return time.Time{}, nil
		}
	}
	return time.Time{}, nil
}
