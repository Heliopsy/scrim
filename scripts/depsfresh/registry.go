package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// The only hosts the gate talks to.
const (
	defaultGoProxy     = "https://proxy.golang.org"
	defaultCratesIndex = "https://index.crates.io"
)

// retryBase is the first retry delay; the n-th retry waits n*n times it.
var retryBase = time.Second

type registry struct {
	client      *http.Client
	goProxy     string
	cratesIndex string
}

func newRegistry(goProxy, cratesIndex string) *registry {
	return &registry{
		client:      &http.Client{Timeout: 90 * time.Second},
		goProxy:     strings.TrimSuffix(goProxy, "/"),
		cratesIndex: strings.TrimSuffix(cratesIndex, "/"),
	}
}

// get fetches url. A 404 or 410 is "not found", not an error: the module proxy
// answers that way for a major version that does not exist. Network errors,
// 429 and 5xx are retried; anything else fails the lookup, and a failed
// lookup fails the gate.
func (r *registry) get(ctx context.Context, url string) ([]byte, bool, error) {
	var lastErr error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * retryBase):
			}
		}
		body, status, err := r.fetch(ctx, url)
		switch {
		case err != nil:
			lastErr = err
			continue
		case status == http.StatusOK:
			return body, true, nil
		case status == http.StatusNotFound || status == http.StatusGone:
			return nil, false, nil
		case status == http.StatusTooManyRequests || status >= 500:
			lastErr = fmt.Errorf("GET %s: HTTP %d", url, status)
			continue
		default:
			return nil, false, fmt.Errorf("GET %s: HTTP %d", url, status)
		}
	}
	return nil, false, lastErr
}

func (r *registry) fetch(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "scrim-deps-fresh")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

// escapeModulePath applies the module proxy's case encoding: every upper-case
// letter becomes '!' and its lower-case form.
func escapeModulePath(p string) string {
	var b strings.Builder
	for _, c := range p {
		if unicode.IsUpper(c) {
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(c))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// goVersions lists the released versions of a module path. found is false
// when the proxy has no such module.
func (r *registry) goVersions(ctx context.Context, path string) ([]string, bool, error) {
	body, found, err := r.get(ctx, r.goProxy+"/"+escapeModulePath(path)+"/@v/list")
	if err != nil || !found {
		return nil, found, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		// +incompatible versions are v2+ tags on a path without /vN; they are
		// not a major version of this module path.
		if line == "" || strings.HasSuffix(line, "+incompatible") {
			continue
		}
		out = append(out, line)
	}
	return out, len(out) > 0, nil
}

// goLatestQuery returns the version the proxy's @latest names (it may be a
// pseudo-version for a module without tags).
func (r *registry) goLatestQuery(ctx context.Context, path string) (string, bool, error) {
	body, found, err := r.get(ctx, r.goProxy+"/"+escapeModulePath(path)+"/@latest")
	if err != nil || !found {
		return "", found, err
	}
	var info struct{ Version string }
	if err := json.Unmarshal(body, &info); err != nil {
		return "", false, fmt.Errorf("%s@latest: %w", path, err)
	}
	return info.Version, info.Version != "", nil
}

// goDeprecation returns the "Deprecated:" message in the go.mod of
// path@version, or "".
func (r *registry) goDeprecation(ctx context.Context, path, ver string) (string, error) {
	body, found, err := r.get(ctx, r.goProxy+"/"+escapeModulePath(path)+"/@v/"+ver+".mod")
	if err != nil || !found {
		return "", err
	}
	return deprecationOf(string(body)), nil
}

// deprecationOf finds the module deprecation comment: a "// Deprecated:"
// paragraph in the comment block directly above the module directive, or a
// trailing comment on it.
func deprecationOf(gomod string) string {
	var block []string
	for _, raw := range strings.Split(gomod, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "//"):
			block = append(block, strings.TrimSpace(strings.TrimPrefix(line, "//")))
			continue
		case strings.HasPrefix(line, "module"):
			if i := strings.Index(line, "//"); i >= 0 {
				block = append(block, strings.TrimSpace(line[i+2:]))
			}
			for _, c := range block {
				if msg, ok := strings.CutPrefix(c, "Deprecated:"); ok {
					return strings.TrimSpace(msg)
				}
			}
			return ""
		}
		block = nil
	}
	return ""
}

// crateIndexPath is the sparse index path of a crate name.
func crateIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	default:
		return n[:2] + "/" + n[2:4] + "/" + n
	}
}

var errNoCrate = errors.New("not on crates.io")

// crateVersions lists the versions of a crate that are not yanked.
func (r *registry) crateVersions(ctx context.Context, name string) ([]string, error) {
	body, found, err := r.get(ctx, r.cratesIndex+"/"+crateIndexPath(name))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errNoCrate
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e struct {
			Vers   string `json:"vers"`
			Yanked bool   `json:"yanked"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("index entry for %s: %w", name, err)
		}
		if !e.Yanked {
			out = append(out, e.Vers)
		}
	}
	return out, nil
}
