package main

// Checksums of pinned release assets (-sums, `just pin-sums`).
//
// Renovate moves a pin's version but cannot compute the sha256 of the asset
// next to it. Each such sum carries the asset's URL on the line above:
//
//	# renovate: datasource=github-releases depName=helm/helm
//	HELM_VERSION=v4.3.2
//	# sha256: https://get.helm.sh/helm-{version}-linux-amd64.tar.gz
//	HELM_LINUX_AMD64_SHA256=d1c0...
//
// {version} is the value of the nearest annotated pin above (and {version#v}
// the same without a leading v). -sums downloads every asset and compares; with
// -fix it rewrites the sums that differ, which is what a Renovate branch
// needs before CI passes.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

var (
	sumAnnotation   = regexp.MustCompile(`^\s*(?:#|//) sha256: (https?://\S+)\s*$`)
	pinAnnotation   = regexp.MustCompile(`^\s*(?:#|//) renovate: `)
	pinValue        = regexp.MustCompile(`^\s*(?:const |export )?[A-Za-z0-9_]+(?: = |=|: )"?(?:\$\{[A-Za-z0-9_]+:-)?([^"\s}]+)`)
	hexSum          = regexp.MustCompile(`\b[0-9a-f]{64}\b`)
	versionTemplate = regexp.MustCompile(`\{version(#v)?\}`)
)

type pinnedSum struct {
	file      string
	line      int // 1-based line of the sum
	url, want string
}

// scanSums finds every annotated sum in the files.
func scanSums(root string, files []string) ([]pinnedSum, error) {
	var out []pinnedSum
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return nil, err
		}
		if !strings.Contains(string(data), "sha256: http") {
			continue
		}
		lines := strings.Split(string(data), "\n")
		cur := ""
		for i := 0; i < len(lines); i++ {
			if pinAnnotation.MatchString(lines[i]) && i+1 < len(lines) {
				if m := pinValue.FindStringSubmatch(lines[i+1]); m != nil {
					cur = m[1]
				}
				continue
			}
			m := sumAnnotation.FindStringSubmatch(lines[i])
			if m == nil {
				continue
			}
			if cur == "" {
				return nil, fmt.Errorf("%s:%d: sha256 annotation with no annotated pin above it", f, i+1)
			}
			if i+1 >= len(lines) || hexSum.FindString(lines[i+1]) == "" {
				return nil, fmt.Errorf("%s:%d: no sha256 on the line after the annotation", f, i+1)
			}
			u := versionTemplate.ReplaceAllStringFunc(m[1], func(t string) string {
				if t == "{version#v}" {
					return strings.TrimPrefix(cur, "v")
				}
				return cur
			})
			out = append(out, pinnedSum{file: f, line: i + 2, url: u, want: hexSum.FindString(lines[i+1])})
		}
	}
	return out, nil
}

// changedFiles lists the files that differ between ref and the working tree.
func changedFiles(root, ref string) ([]string, error) {
	out, err := exec.Command("git", "-C", root, "diff", "--name-only", ref).Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only %s: %w", ref, err)
	}
	return strings.Fields(string(out)), nil
}

func download(ctx context.Context, client *http.Client, u string) (string, error) {
	var lastErr error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * retryBase):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "scrim-deps-fresh")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		h := sha256.New()
		_, err = io.Copy(h, resp.Body)
		_ = resp.Body.Close()
		switch {
		case err != nil:
			lastErr = err
			continue
		case resp.StatusCode == http.StatusOK:
			return hex.EncodeToString(h.Sum(nil)), nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
			continue
		default:
			return "", fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
		}
	}
	return "", lastErr
}

// runSums checks (and with fix, rewrites) every annotated sum.
func runSums(ctx context.Context, opts options, w io.Writer) (int, error) {
	files, err := trackedFiles(opts.root)
	if err != nil {
		return 0, err
	}
	if opts.sumsSince != "" {
		changed, err := changedFiles(opts.root, opts.sumsSince)
		if err != nil {
			return 0, err
		}
		files = slices.DeleteFunc(files, func(f string) bool { return !slices.Contains(changed, f) })
	}
	sums, err := scanSums(opts.root, files)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	got := make([]string, len(sums))
	errs := make([]error, len(sums))
	sem := make(chan struct{}, max(1, opts.jobs))
	var wg sync.WaitGroup
	for i, s := range sums {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			got[i], errs[i] = download(ctx, client, s.url)
		}()
	}
	wg.Wait()

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STATUS\tWHERE\tASSET")
	bad := 0
	fixes := map[string]map[int]string{} // file -> line -> new sum
	for i, s := range sums {
		st := "ok"
		switch {
		case errs[i] != nil:
			st, bad = "ERROR", bad+1
			s.url += " (" + errs[i].Error() + ")"
		case got[i] != s.want && opts.fix:
			st = "fixed"
			if fixes[s.file] == nil {
				fixes[s.file] = map[int]string{}
			}
			fixes[s.file][s.line] = got[i]
		case got[i] != s.want:
			st, bad = "MISMATCH", bad+1
			s.url += " is " + got[i] + ", pinned " + s.want
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s:%d\t%s\n", st, s.file, s.line, s.url)
	}
	if err := tw.Flush(); err != nil {
		return 0, err
	}
	for f, lines := range fixes {
		p := filepath.Join(opts.root, f)
		data, err := os.ReadFile(p)
		if err != nil {
			return 0, err
		}
		ls := strings.Split(string(data), "\n")
		for n, sum := range lines {
			ls[n-1] = hexSum.ReplaceAllString(ls[n-1], sum)
		}
		info, err := os.Stat(p)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(p, []byte(strings.Join(ls, "\n")), info.Mode().Perm()); err != nil {
			return 0, err
		}
	}
	if bad > 0 {
		_, _ = fmt.Fprintf(w, "pin-sums: %d of %d pinned checksums do not match their asset. A version moved without its sum (a Renovate pull request does that): run `just pin-sums`, review the diff and commit it.\n", bad, len(sums))
		return 1, nil
	}
	_, _ = fmt.Fprintf(w, "pin-sums: %d pinned checksums match their assets%s.\n", len(sums), map[bool]string{true: " (" + strconv.Itoa(countFixes(fixes)) + " rewritten)", false: ""}[opts.fix])
	return 0, nil
}

func countFixes(f map[string]map[int]string) int {
	n := 0
	for _, l := range f {
		n += len(l)
	}
	return n
}
