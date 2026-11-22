// SPDX-License-Identifier: AGPL-3.0-only

// Package projectscan finds secret values in a project's files
// (specs/credential-injection, "Secrets in project files"; tasks 10a.11).
//
// [Scan] walks the session's working directory for the files secrets are
// usually written into (`.env*`, `*.tfvars`, application config, compose
// files, `.npmrc`, ...) and returns every value of a secret-looking key (a
// name with TOKEN, KEY, SECRET, PASSWORD, ...) and every password in a URL.
// `scrim run` registers them as known values for the session, so they are
// redacted from the first request, and rescans to pick up changes. [Move]
// replaces one in its file with a `{{scrim:<ref>}}` reference after the value
// was written to a store; nothing is rewritten without the caller asking.
//
// Values only ever live in [secret.Value]: file content is read into a buffer
// that is wiped once the values are copied out, and a [Finding] holds names,
// positions and the value handle, never a string of the value.
package projectscan

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// Limits and defaults.
const (
	// DefaultMinLength is the shortest value registered; shorter ones are
	// too likely to be ordinary words.
	DefaultMinLength = 8
	// DefaultMaxDepth is how many directory levels below the root are
	// walked.
	DefaultMaxDepth = 4
	// MaxFileSize bounds a scanned file; larger ones are skipped.
	MaxFileSize = 1 << 20
	// MaxFiles bounds the files scanned in one walk.
	MaxFiles = 500
	// MaxEntries bounds the directory entries visited in one walk.
	MaxEntries = 20000
)

// Options tune a scan.
type Options struct {
	// MinLength is the shortest value kept; zero is DefaultMinLength.
	MinLength int
	// MaxDepth is the directory depth walked; zero is DefaultMaxDepth.
	MaxDepth int
}

// Finding is one secret value in a project file. It holds no string of the
// value.
type Finding struct {
	// File is the path relative to the scanned directory, slash-separated.
	File string `json:"file"`
	// Line is 1-based.
	Line int `json:"line"`
	// Key is the setting's name as written; for a password in a URL it is
	// the setting's name plus ".password".
	Key string `json:"key"`
	// Value is the secret. Result.Wipe wipes it.
	Value secret.Value `json:"-"`

	// start and end are the value's byte offsets in the line as written.
	start, end int
	// decoded is set when the value was double-quoted with escapes and
	// Value is the decoded form; the raw form is a second finding.
	decoded bool
}

// Name is the finding's stable name, `<file>#<key>`, used as its reference
// path and in messages.
func (f Finding) Name() string { return f.File + "#" + f.Key }

// String names the finding without its value.
func (f Finding) String() string { return fmt.Sprintf("%s:%d %s", f.File, f.Line, f.Key) }

// Result is one scan.
type Result struct {
	// Dir is the scanned directory, absolute.
	Dir string
	// Findings are sorted by file and line.
	Findings []Finding
	// Files are the scanned files, relative and slash-separated.
	Files []string
	// Skipped names files that were not read and why.
	Skipped []string

	fingerprint []byte
}

// Wipe wipes every value.
func (r *Result) Wipe() {
	if r == nil {
		return
	}
	for _, f := range r.Findings {
		f.Value.Wipe()
	}
}

// Same reports whether two scans found the same values at the same names,
// without comparing values outside a keyed digest.
func (r *Result) Same(o *Result) bool {
	if r == nil || o == nil {
		return r == o
	}
	return hmac.Equal(r.fingerprint, o.fingerprint)
}

// fingerprintKey is random per process: the digest never leaves it and
// cannot be checked against guesses elsewhere.
var fingerprintKey = func() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}()

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true, ".terraform": true,
	"target": true, "dist": true, "build": true, ".venv": true, "venv": true, "__pycache__": true,
	".cache": true, ".next": true, ".tox": true, ".gradle": true, ".idea": true, ".worktrees": true,
}

// exampleSuffixes mark files that hold sample values, not secrets.
var exampleSuffixes = []string{".example", ".sample", ".template", ".dist", ".defaults", ".tmpl", ".tpl"}

// Matches reports whether a file (path relative to the project root,
// slash-separated) is one the scan reads.
func Matches(rel string) bool {
	base := path.Base(rel)
	lower := strings.ToLower(base)
	for _, s := range exampleSuffixes {
		if strings.HasSuffix(lower, s) {
			return false
		}
	}
	switch {
	case lower == ".env", strings.HasPrefix(lower, ".env."), strings.HasSuffix(lower, ".env"):
		return true
	case strings.HasSuffix(lower, ".tfvars"), strings.HasSuffix(lower, ".tfvars.json"):
		return true
	case lower == ".npmrc", lower == ".pypirc", lower == ".netrc":
		return true
	case strings.HasPrefix(lower, "application") && hasExt(lower, ".properties", ".yml", ".yaml"):
		return true
	case strings.HasPrefix(lower, "appsettings") && hasExt(lower, ".json"):
		return true
	case (strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose")) && hasExt(lower, ".yml", ".yaml"):
		return true
	case (strings.HasPrefix(lower, "secrets") || strings.HasPrefix(lower, "credentials")) &&
		hasExt(lower, ".yml", ".yaml", ".json", ".toml", ".ini", ".properties"):
		return true
	}
	dir := path.Base(path.Dir(rel))
	return (dir == "config" || dir == "conf") && hasExt(lower, ".yml", ".yaml", ".json", ".toml", ".ini", ".properties", ".conf")
}

func hasExt(name string, exts ...string) bool {
	return slices.ContainsFunc(exts, func(e string) bool { return strings.HasSuffix(name, e) })
}

// Scan walks dir and returns the secret values in its project files.
func Scan(dir string, o Options) (*Result, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if o.MinLength <= 0 {
		o.MinLength = DefaultMinLength
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	r := &Result{Dir: abs}
	entries := 0
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if entries++; entries > MaxEntries {
			r.Skipped = append(r.Skipped, "the rest of the tree: more than "+strconv.Itoa(MaxEntries)+" entries")
			return filepath.SkipAll
		}
		if err != nil {
			if p == abs {
				return err
			}
			return nil // unreadable entries are not ours to report
		}
		rel, _ := filepath.Rel(abs, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != abs && (skipDirs[d.Name()] || strings.Count(rel, "/")+1 > o.MaxDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !Matches(rel) {
			return nil
		}
		if len(r.Files) >= MaxFiles {
			r.Skipped = append(r.Skipped, rel+": more than "+strconv.Itoa(MaxFiles)+" project files")
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			r.Skipped = append(r.Skipped, rel+": "+errText(err))
			return nil //nolint:nilerr // a file gone since the listing is skipped, not fatal
		}
		if info.Size() > MaxFileSize {
			r.Skipped = append(r.Skipped, rel+": larger than "+strconv.Itoa(MaxFileSize)+" bytes")
			return nil
		}
		fs, err := scanFile(p, rel, o)
		if err != nil {
			r.Skipped = append(r.Skipped, rel+": "+errText(err))
			return nil
		}
		r.Files = append(r.Files, rel)
		r.Findings = append(r.Findings, fs...)
		return nil
	})
	if err != nil {
		r.Wipe()
		return nil, err
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	mac := hmac.New(sha256.New, fingerprintKey)
	for _, f := range r.Findings {
		mac.Write([]byte(f.Name()))
		mac.Write([]byte{0})
		_ = f.Value.Expose(func(b []byte) error { mac.Write(b); return nil })
		mac.Write([]byte{0})
	}
	r.fingerprint = mac.Sum(nil)
	return r, nil
}

// errText names the failure without file content.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "unreadable"
}

// line is `key = value`, `key: value`, `"key": "value",` or
// `export KEY=value`, with the key optionally quoted.
var line = regexp.MustCompile(`^\s*(?:export\s+|-\s+)?(["']?)([A-Za-z0-9_.\-/:@]+)(["']?)\s*([=:])\s*`)

var (
	secretWords = regexp.MustCompile(`(^|_)(TOKEN|KEY|SECRET|PASSWORD|PASSWD|PASS|PWD|PAT|CREDENTIALS?|AUTH|AUTHTOKEN|APIKEY|DSN|PRIVATE|CLIENTSECRET)(_|$)`)
	notSecret   = regexp.MustCompile(`(^|_)(FILE|PATH|DIR|URL|URI|HOST|PORT|USER|USERNAME|NAME|ID|TYPE|ALGORITHM|ALG|LENGTH|SIZE|TTL|TIMEOUT|EXPIRY|EXPIRES|HEADER|PREFIX|FORMAT|REGION|ENABLED)$`)
	camel       = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	nonAlnum    = regexp.MustCompile(`[^A-Za-z0-9]+`)
)

// normKey turns apiKey, api-key and api.key into API_KEY.
func normKey(k string) string {
	k = camel.ReplaceAllString(k, "${1}_${2}")
	return strings.Trim(strings.ToUpper(nonAlnum.ReplaceAllString(k, "_")), "_")
}

// SecretKey reports whether a setting's name says it holds a secret.
func SecretKey(key string) bool {
	n := normKey(key)
	if !secretWords.MatchString(n) {
		return false
	}
	// AWS_ACCESS_KEY_ID is a credential even though it ends in ID.
	if strings.HasSuffix(n, "ACCESS_KEY_ID") || strings.HasSuffix(n, "KEY_ID") && strings.Contains(n, "ACCESS") {
		return true
	}
	return !notSecret.MatchString(n)
}

func scanFile(p, rel string, o Options) ([]Finding, error) {
	data, err := os.ReadFile(p) //nolint:gosec // a project file under the session's working directory
	if err != nil {
		return nil, err
	}
	buf := secret.Adopt(data)
	defer buf.Wipe()
	var out []Finding
	err = buf.Expose(func(b []byte) error {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), MaxFileSize)
		n := 0
		for sc.Scan() {
			n++
			out = append(out, scanLine(sc.Bytes(), rel, n, o)...)
		}
		return sc.Err()
	})
	if err != nil {
		for _, f := range out {
			f.Value.Wipe()
		}
		return nil, err
	}
	return out, nil
}

// scanLine returns the findings of one line. Every value is copied into a
// new secret.Value; the line itself stays in the caller's wiped buffer.
func scanLine(l []byte, rel string, n int, o Options) []Finding {
	trimmed := bytes.TrimSpace(l)
	if len(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == ';' || bytes.HasPrefix(trimmed, []byte("//")) && !bytes.Contains(trimmed, []byte("_authToken")) {
		return nil
	}
	m := line.FindSubmatchIndex(l)
	if m == nil || (m[3]-m[2] != m[7]-m[6]) {
		return nil
	}
	key := string(l[m[4]:m[5]])
	start, end, quote := valueSpan(l, m[1])
	if start >= end {
		return nil
	}
	v := l[start:end]
	var out []Finding
	if bytes.Contains(v, []byte("://")) {
		if f, ok := urlPassword(l, start, end, rel, n, key, o); ok {
			out = append(out, f)
		}
		return out
	}
	if !SecretKey(key) || !plausible(v, o) {
		return out
	}
	out = append(out, Finding{File: rel, Line: n, Key: key, Value: secret.New(v), start: start, end: end})
	if quote == '"' && bytes.IndexByte(v, '\\') >= 0 {
		// The application reads the decoded form; register it as well.
		if dec := unescape(v); !bytes.Equal(dec, v) {
			out = append(out, Finding{File: rel, Line: n, Key: key, Value: secret.Adopt(dec), start: start, end: end, decoded: true})
		} else {
			secret.WipeBytes(dec)
		}
	}
	return out
}

// unescape decodes the common escapes of a double-quoted value (\n, \r,
// \t, \", \\) into a new buffer.
func unescape(v []byte) []byte {
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' || i+1 == len(v) {
			out = append(out, c)
			continue
		}
		i++
		switch v[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '"', '\\':
			out = append(out, v[i])
		default:
			out = append(out, '\\', v[i])
		}
	}
	return out
}

// valueSpan finds the value after offset i: the text inside matching
// quotes, or up to a trailing comment, comma or end of line.
func valueSpan(l []byte, i int) (start, end int, quote byte) {
	for i < len(l) && (l[i] == ' ' || l[i] == '\t') {
		i++
	}
	if i >= len(l) {
		return i, i, 0
	}
	if q := l[i]; q == '"' || q == '\'' || q == '`' {
		for j := i + 1; j < len(l); j++ {
			if l[j] == '\\' && q == '"' {
				j++
				continue
			}
			if l[j] == q {
				return i + 1, j, q
			}
		}
		return i + 1, i + 1, q // unterminated: multi-line values are not read
	}
	end = len(l)
	if c := bytes.Index(l[i:], []byte(" #")); c >= 0 {
		end = i + c
	}
	for end > i && (l[end-1] == ' ' || l[end-1] == '\t' || l[end-1] == ',' || l[end-1] == '\r') {
		end--
	}
	return i, end, 0
}

// plausible filters out what is clearly not a secret value: references,
// placeholders, interpolations, booleans, numbers, paths and short words.
// It works on the bytes and never copies them into a string.
func plausible(v []byte, o Options) bool {
	if len(v) < o.MinLength {
		return false
	}
	lower := bytes.ToLower(v)
	defer secret.WipeBytes(lower)
	for _, p := range [][]byte{[]byte("scrim_"), []byte("{{"), []byte("${"), []byte("$("), []byte("<"), []byte("%("),
		[]byte("#{"), []byte("!ref"), []byte("env("), []byte("process.env"), []byte("os.environ")} {
		if bytes.HasPrefix(lower, p) {
			return false
		}
	}
	for _, w := range sampleWords {
		if bytes.Equal(lower, w) {
			return false
		}
	}
	for _, p := range [][]byte{[]byte("/"), []byte("./"), []byte("~/"), []byte("../")} {
		if bytes.HasPrefix(v, p) {
			return false
		}
	}
	if bytes.ContainsAny(v, " \t") && !bytes.HasPrefix(v, []byte("-----BEGIN")) {
		return false
	}
	if len(bytes.Trim(v, string(v[:1]))) == 0 { // one repeated character
		return false
	}
	digits, letters, other := 0, 0, 0
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= 0x80:
			letters++
		case c == '.' || c == '-' || c == '+' || c == 'e':
			other++
		}
	}
	if letters == 0 && digits > 0 && digits+other == len(v) {
		return false // a number
	}
	return letters+digits > 0
}

var sampleWords = func() [][]byte {
	var out [][]byte
	for _, w := range []string{"changeme", "change-me", "change_me", "password", "secret", "true", "false", "null",
		"none", "undefined", "placeholder", "redacted", "your-token", "your_token", "your-key", "your_api_key"} {
		out = append(out, []byte(w))
	}
	return out
}()

// urlPassword returns the password of a URL value, located in the line.
func urlPassword(l []byte, start, end int, rel string, n int, key string, o Options) (Finding, bool) {
	v := l[start:end]
	at := bytes.LastIndexByte(v, '@')
	scheme := bytes.Index(v, []byte("://"))
	if at < 0 || scheme < 0 || at < scheme {
		return Finding{}, false
	}
	userinfo := v[scheme+3 : at]
	colon := bytes.IndexByte(userinfo, ':')
	if colon < 0 {
		return Finding{}, false
	}
	pw := userinfo[colon+1:]
	if len(pw) == 0 {
		return Finding{}, false
	}
	ps := start + scheme + 3 + colon + 1
	pe := ps + len(pw)
	if !plausible(pw, Options{MinLength: min(o.MinLength, 6)}) {
		return Finding{}, false
	}
	return Finding{File: rel, Line: n, Key: key + ".password", Value: secret.New(pw), start: ps, end: pe}, true
}
