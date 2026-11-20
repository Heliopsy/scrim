// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- the macOS keychain names certificates by SHA-1 fingerprint
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Runner runs the external commands trust installation needs (security,
// certutil). Tests inject a fake so they never touch a real keychain or NSS
// database.
type Runner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// LookPath implements [Runner].
func (ExecRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

// Run implements [Runner] and returns the combined output.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed tools, arguments built here
}

// Entry kinds in the trust manifest.
const (
	KindFile     = "file"
	KindKeychain = "keychain"
	KindNSSDB    = "nssdb"
)

// File purposes.
const (
	// PurposeExtra is a file of the scrim CA certificates only, for runtimes
	// that add it to their own roots (NODE_EXTRA_CA_CERTS).
	PurposeExtra = "extra"
	// PurposeBundle is the system roots plus the scrim CA, for variables
	// that replace the roots (SSL_CERT_FILE, REQUESTS_CA_BUNDLE,
	// CURL_CA_BUNDLE, GIT_SSL_CAINFO).
	PurposeBundle = "bundle"
)

// Entry is one change recorded in the trust manifest.
type Entry struct {
	Kind string `json:"kind"`
	// Target is the file written, the keychain or the NSS database.
	Target string `json:"target"`
	// CertID, Nickname, SHA1 and CertPEM describe the trusted certificate
	// for keychain and NSS entries.
	CertID   string `json:"cert_id,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	SHA1     string `json:"sha1,omitempty"`
	CertPEM  string `json:"cert_pem,omitempty"`
	// Purpose and Roots describe a file entry.
	Purpose string    `json:"purpose,omitempty"`
	Roots   string    `json:"roots,omitempty"`
	At      time.Time `json:"at"`
}

func (e Entry) describe() string {
	switch e.Kind {
	case KindKeychain:
		return fmt.Sprintf("trust %q in the keychain %s (security add-trusted-cert -r trustRoot)", e.Nickname, e.Target)
	case KindNSSDB:
		return fmt.Sprintf("trust %q in the NSS database %s (certutil -A -t C,,)", e.Nickname, e.Target)
	}
	if e.Purpose == PurposeBundle {
		return fmt.Sprintf("write %s (system roots from %s plus the scrim CA, for SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO)", e.Target, e.Roots)
	}
	return fmt.Sprintf("write %s (the scrim CA certificates, for NODE_EXTRA_CA_CERTS)", e.Target)
}

func (e Entry) manualStep() string {
	switch e.Kind {
	case KindKeychain:
		return fmt.Sprintf("open Keychain Access, select the login keychain, delete the certificate %q (SHA-1 %s)", e.Nickname, e.SHA1)
	case KindNSSDB:
		return fmt.Sprintf("certutil -d sql:%s -D -n %q", e.Target, e.Nickname)
	}
	return "rm " + e.Target
}

// Manifest lists every trust change `scrim ca install` made, so uninstall
// reverts exactly those.
type Manifest struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// ReadManifest reads the trust manifest in dir; a missing one is empty.
func ReadManifest(dir string) (Manifest, error) {
	b, err := readFile(filepath.Join(dir, manifestFile))
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{Version: 1}, nil
	}
	if err != nil {
		return Manifest{}, err
	}
	var mf Manifest
	if err := json.Unmarshal(b, &mf); err != nil {
		return Manifest{}, fmt.Errorf("ca: %s: %w", filepath.Join(dir, manifestFile), err)
	}
	if mf.Version != 1 {
		return Manifest{}, fmt.Errorf("ca: %s: unsupported version %d", filepath.Join(dir, manifestFile), mf.Version)
	}
	return mf, nil
}

func writeManifest(dir string, mf Manifest) error {
	p := filepath.Join(dir, manifestFile)
	if len(mf.Entries) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("ca: %w", err)
		}
		return nil
	}
	mf.Version = 1
	b, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(p, append(b, '\n'), 0o600)
}

// DefaultSystemRoots are the system CA bundles looked for, in order, to
// build the combined bundle file.
var DefaultSystemRoots = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Arch, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // macOS, Alpine, BSD
}

// DefaultDataDir is where the user bundle files go:
// $XDG_DATA_HOME/scrim, or ~/.local/share/scrim.
func DefaultDataDir(getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if dir := getenv("XDG_DATA_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, "scrim"), nil
	}
	home, err := homeDir(getenv)
	if err != nil {
		return "", fmt.Errorf("ca: no XDG_DATA_HOME and %w", err)
	}
	return filepath.Join(home, ".local", "share", "scrim"), nil
}

// Installer adds the CA to the per-user trust stores and removes it again.
type Installer struct {
	// Dir holds the trust manifest (the CA directory).
	Dir string
	// Home is the user's home directory.
	Home string
	// DataDir receives the bundle files.
	DataDir string
	// GOOS selects the trust stores: "darwin" uses the login keychain,
	// "linux" the NSS database in ~/.pki/nssdb.
	GOOS   string
	Runner Runner
	// Out receives every change before it is made, and the results.
	Out io.Writer
	// SystemRoots are the candidate system bundles; nil means
	// DefaultSystemRoots.
	SystemRoots []string
	// DryRun shows the changes without making them.
	DryRun bool
	// Now is the clock for manifest timestamps; nil means time.Now.
	Now func() time.Time
}

func (in *Installer) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

func (in *Installer) printf(format string, a ...any) {
	_, _ = fmt.Fprintf(in.Out, format, a...)
}

// Paths of the two user bundle files.
func (in *Installer) extraPath() string  { return filepath.Join(in.DataDir, "scrim-ca.pem") }
func (in *Installer) bundlePath() string { return filepath.Join(in.DataDir, "ca-bundle.pem") }

func (in *Installer) systemRoots() string {
	roots := in.SystemRoots
	if roots == nil {
		roots = DefaultSystemRoots
	}
	for _, p := range roots {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
			return p
		}
	}
	return ""
}

// ErrNotReverted is returned when some changes could not be made or
// reverted; each is reported on Out with the manual step.
var ErrNotReverted = errors.New("some trust changes could not be made or reverted")

// Install trusts certs in the per-user stores of this OS and writes the
// user bundle files, showing every change before making it and recording
// it in the manifest. Store entries of certificates no longer in certs (a
// previous generation whose overlap ended) are removed. Running it again
// after a rotation adds the new generation.
func (in *Installer) Install(ctx context.Context, certs []Certificate) error {
	if err := ensureDir(in.Dir); err != nil {
		return err
	}
	unlock, err := lockDir(in.Dir, true)
	if err != nil {
		return err
	}
	defer unlock()
	mf, err := ReadManifest(in.Dir)
	if err != nil {
		return err
	}
	var bundle string
	for _, c := range certs {
		bundle += c.PEM
	}
	failed := 0
	verb := ""
	if in.DryRun {
		verb = "would "
	}

	// Files.
	roots := in.systemRoots()
	files := []Entry{{Kind: KindFile, Target: in.extraPath(), Purpose: PurposeExtra}}
	if roots != "" {
		files = append(files, Entry{Kind: KindFile, Target: in.bundlePath(), Purpose: PurposeBundle, Roots: roots})
	}
	for _, e := range files {
		i := slices.IndexFunc(mf.Entries, func(x Entry) bool { return x.Kind == KindFile && x.Target == e.Target })
		if i < 0 {
			if _, err := os.Lstat(e.Target); err == nil {
				in.printf("! %s exists and was not written by scrim; left alone\n", e.Target)
				continue
			}
		}
		in.printf("+ %s%s\n", verb, e.describe())
		if in.DryRun {
			continue
		}
		if err := writeTrustFile(e, bundle); err != nil {
			in.printf("  failed: %v\n", err)
			failed++
			continue
		}
		e.At = in.now().UTC()
		if i < 0 {
			mf.Entries = append(mf.Entries, e)
		} else {
			mf.Entries[i] = e
		}
		if err := writeManifest(in.Dir, mf); err != nil {
			return err
		}
	}

	// Stores.
	stores, notes := in.stores()
	for _, n := range notes {
		in.printf("  %s\n", n)
	}
	for _, s := range stores {
		for _, c := range certs {
			if slices.ContainsFunc(mf.Entries, func(x Entry) bool { return x.Kind == s.Kind && x.Target == s.Target && x.CertID == c.ID }) {
				continue
			}
			e, err := storeEntry(s, c)
			if err != nil {
				return err
			}
			in.printf("+ %s%s\n", verb, e.describe())
			if in.DryRun {
				continue
			}
			if err := in.apply(ctx, e); err != nil {
				in.printf("  failed: %v\n", err)
				failed++
				continue
			}
			e.At = in.now().UTC()
			mf.Entries = append(mf.Entries, e)
			if err := writeManifest(in.Dir, mf); err != nil {
				return err
			}
		}
	}

	// Store entries of generations no longer in use.
	for _, e := range slices.Clone(mf.Entries) {
		if e.Kind == KindFile || slices.ContainsFunc(certs, func(c Certificate) bool { return c.ID == e.CertID }) {
			continue
		}
		in.printf("- %sremove %q from %s (no longer in use)\n", verb, e.Nickname, e.Target)
		if in.DryRun {
			continue
		}
		if err := in.revert(ctx, e); err != nil {
			in.printf("  failed: %v\n  manual step: %s\n", err, e.manualStep())
			failed++
			continue
		}
		mf.Entries = slices.DeleteFunc(mf.Entries, func(x Entry) bool { return x == e })
		if err := writeManifest(in.Dir, mf); err != nil {
			return err
		}
	}

	in.printf("\nRuntimes with their own trust settings read these variables; set them in the agent's environment:\n")
	in.printf("  export NODE_EXTRA_CA_CERTS=%s\n", in.extraPath())
	if roots != "" {
		for _, v := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"} {
			in.printf("  export %s=%s\n", v, in.bundlePath())
		}
	} else {
		in.printf("  (no system CA bundle found, so no combined bundle was written; SSL_CERT_FILE and similar\n" +
			"  variables replace the system roots and need one)\n")
	}
	if failed > 0 {
		return fmt.Errorf("%w: %d", ErrNotReverted, failed)
	}
	return nil
}

// Uninstall reverts every change the manifest lists, newest first. Changes
// that cannot be reverted stay in the manifest and are reported with the
// manual step.
func (in *Installer) Uninstall(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(in.Dir, manifestFile)); errors.Is(err, fs.ErrNotExist) {
		in.printf("nothing to uninstall: no trust changes are recorded in %s\n", in.Dir)
		return nil
	}
	unlock, err := lockDir(in.Dir, true)
	if err != nil {
		return err
	}
	defer unlock()
	mf, err := ReadManifest(in.Dir)
	if err != nil {
		return err
	}
	verb := ""
	if in.DryRun {
		verb = "would "
	}
	var notReverted []Entry
	for i := len(mf.Entries) - 1; i >= 0; i-- {
		e := mf.Entries[i]
		if e.Kind == KindFile {
			in.printf("- %sremove %s\n", verb, e.Target)
		} else {
			in.printf("- %sremove %q from %s\n", verb, e.Nickname, e.Target)
		}
		if in.DryRun {
			continue
		}
		if err := in.revert(ctx, e); err != nil {
			in.printf("  failed: %v\n", err)
			notReverted = append(notReverted, e)
			continue
		}
		mf.Entries = slices.Delete(mf.Entries, i, i+1)
		if err := writeManifest(in.Dir, mf); err != nil {
			return err
		}
	}
	if len(notReverted) == 0 {
		return nil
	}
	in.printf("\nNot reverted (still listed in %s):\n", filepath.Join(in.Dir, manifestFile))
	for _, e := range notReverted {
		in.printf("  %s\n    manual step: %s\n", e.Target, e.manualStep())
	}
	return fmt.Errorf("%w: %d", ErrNotReverted, len(notReverted))
}

// stores returns the per-user trust stores of this OS that can be used,
// and notes on those that cannot.
func (in *Installer) stores() ([]Entry, []string) {
	switch in.GOOS {
	case "darwin":
		if _, err := in.Runner.LookPath("security"); err != nil {
			return nil, []string{"skipped the login keychain: the security tool was not found"}
		}
		return []Entry{{Kind: KindKeychain, Target: filepath.Join(in.Home, "Library", "Keychains", "login.keychain-db")}}, nil
	case "linux":
		db := filepath.Join(in.Home, ".pki", "nssdb")
		if _, err := os.Stat(filepath.Join(db, "cert9.db")); err != nil {
			return nil, []string{"skipped the NSS database: " + db + " does not exist (it is created by Chromium-based browsers)"}
		}
		if _, err := in.Runner.LookPath("certutil"); err != nil {
			return nil, []string{"skipped the NSS database " + db + ": certutil was not found (package libnss3-tools or nss-tools)"}
		}
		return []Entry{{Kind: KindNSSDB, Target: db}}, nil
	}
	return nil, []string{"no per-user trust store is supported on " + in.GOOS + "; use the bundle files"}
}

func storeEntry(s Entry, c Certificate) (Entry, error) {
	block, _ := pem.Decode([]byte(c.PEM))
	if block == nil {
		return Entry{}, fmt.Errorf("ca: certificate %s is not PEM", c.ID)
	}
	cert, err := parseCert([]byte(c.PEM))
	if err != nil {
		return Entry{}, fmt.Errorf("ca: certificate %s: %w", c.ID, err)
	}
	sum := sha1.Sum(block.Bytes) // #nosec G401 -- fingerprint the keychain uses, not a security decision
	s.CertID = c.ID
	s.Nickname = cert.Subject.CommonName
	s.SHA1 = strings.ToUpper(hex.EncodeToString(sum[:]))
	s.CertPEM = c.PEM
	return s, nil
}

// apply makes one store change.
func (in *Installer) apply(ctx context.Context, e Entry) error {
	tmp, cleanup, err := in.certTemp(e)
	if err != nil {
		return err
	}
	defer cleanup()
	switch e.Kind {
	case KindKeychain:
		return in.run(ctx, "security", "add-trusted-cert", "-r", "trustRoot", "-k", e.Target, tmp)
	case KindNSSDB:
		return in.run(ctx, "certutil", "-d", "sql:"+e.Target, "-A", "-t", "C,,", "-n", e.Nickname, "-i", tmp)
	}
	return fmt.Errorf("ca: unknown trust store kind %q", e.Kind)
}

// revert undoes one recorded change. A change already undone by hand counts
// as reverted.
func (in *Installer) revert(ctx context.Context, e Entry) error {
	switch e.Kind {
	case KindFile:
		if err := os.Remove(e.Target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	case KindKeychain:
		tmp, cleanup, err := in.certTemp(e)
		if err != nil {
			return err
		}
		defer cleanup()
		if err := in.run(ctx, "security", "remove-trusted-cert", tmp); err != nil {
			return err
		}
		return in.run(ctx, "security", "delete-certificate", "-Z", e.SHA1, e.Target)
	case KindNSSDB:
		return in.run(ctx, "certutil", "-d", "sql:"+e.Target, "-D", "-n", e.Nickname)
	}
	return fmt.Errorf("ca: unknown trust store kind %q", e.Kind)
}

func (in *Installer) run(ctx context.Context, name string, args ...string) error {
	out, err := in.Runner.Run(ctx, name, args...)
	if err != nil {
		msg := strings.TrimSpace(string(bytes.ToValidUTF8(out, nil)))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		if msg != "" {
			return fmt.Errorf("%s %s: %w: %s", name, args[0], err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	return nil
}

// certTemp writes the entry's public certificate to a temporary file for a
// tool that takes a path.
func (in *Installer) certTemp(e Entry) (string, func(), error) {
	f, err := os.CreateTemp(in.Dir, ".trust-*.pem")
	if err != nil {
		return "", nil, fmt.Errorf("ca: %w", err)
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := f.WriteString(e.CertPEM); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, fmt.Errorf("ca: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("ca: %w", err)
	}
	return name, cleanup, nil
}

// writeTrustFile writes a bundle file, readable by everyone (it holds only
// public certificates).
func writeTrustFile(e Entry, bundle string) error {
	content := bundle
	if e.Purpose == PurposeBundle {
		roots, err := os.ReadFile(e.Roots) // #nosec G304 -- system bundle path from a fixed list
		if err != nil {
			return fmt.Errorf("read the system roots: %w", err)
		}
		if len(roots) > 0 && roots[len(roots)-1] != '\n' {
			roots = append(roots, '\n')
		}
		content = string(roots) + "# scrim interception CA\n" + bundle
	}
	if err := os.MkdirAll(filepath.Dir(e.Target), 0o755); err != nil { // #nosec G301 -- public certificates
		return err
	}
	return writeFileAtomic(e.Target, []byte(content), 0o644)
}

// refreshTrustFiles rewrites the bundle files recorded in the manifest after
// the generations changed, so runtimes that read them trust the new CA
// without another install. Keychain and NSS entries need `scrim ca install`
// again. Called with the directory lock held.
func (m *Manager) refreshTrustFiles() {
	mf, err := ReadManifest(m.dir)
	if err != nil {
		m.log.Warn("could not read the trust manifest to refresh the bundle files", "err", err)
		return
	}
	bundle := m.TrustBundlePEM()
	for _, e := range mf.Entries {
		if e.Kind != KindFile {
			continue
		}
		if err := writeTrustFile(e, bundle); err != nil {
			m.log.Warn("could not refresh a CA bundle file", "path", e.Target, "err", err)
			continue
		}
		m.log.Info("refreshed a CA bundle file", "path", e.Target)
	}
}

// Fingerprint returns the SHA-256 fingerprint of a PEM certificate, for
// display.
func Fingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}
