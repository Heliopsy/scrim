// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// Layout of the CA directory:
//
//	<dir>/                      0700
//	  state.json                0600  which generations are in use, overlap end
//	  gen/<id>/cert.pem         0644  public certificate
//	  gen/<id>/key.pem          0600  PKCS#8 private key
//	  trust-manifest.json       0600  trust changes made by `scrim ca install`
//	  .lock                     0600  advisory lock between processes
//
// A rotation writes the new generation's directory first and then replaces
// state.json atomically, so state.json is the commit point: a crash leaves
// either the old or the new state, never a half-written one.
const (
	stateFile    = "state.json"
	genDir       = "gen"
	certFile     = "cert.pem"
	keyFile      = "key.pem"
	lockFile     = ".lock"
	manifestFile = "trust-manifest.json"
	stateVersion = 1
	maxFileSize  = 64 << 10
)

var idPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{1,8}$`)

// diskState is state.json.
type diskState struct {
	Version  int    `json:"version"`
	Current  string `json:"current"`
	Previous string `json:"previous,omitempty"`
	// OverlapUntil is when the previous generation stops being trusted.
	OverlapUntil time.Time `json:"overlap_until,omitzero"`
}

func (s diskState) validate() error {
	if s.Version != stateVersion {
		return fmt.Errorf("%s: unsupported version %d", stateFile, s.Version)
	}
	if !idPattern.MatchString(s.Current) {
		return fmt.Errorf("%s: invalid current generation %q", stateFile, s.Current)
	}
	if s.Previous != "" && (!idPattern.MatchString(s.Previous) || s.Previous == s.Current) {
		return fmt.Errorf("%s: invalid previous generation %q", stateFile, s.Previous)
	}
	return nil
}

// DefaultDir is the CA directory used when tool-proxy.ca.dir is empty:
// $XDG_STATE_HOME/scrim/ca, or ~/.local/state/scrim/ca. getenv nil means
// os.Getenv.
func DefaultDir(getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if dir := getenv("XDG_STATE_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, "scrim", "ca"), nil
	}
	home, err := homeDir(getenv)
	if err != nil {
		return "", fmt.Errorf("ca: no XDG_STATE_HOME and %w", err)
	}
	return filepath.Join(home, ".local", "state", "scrim", "ca"), nil
}

func homeDir(getenv func(string) string) (string, error) {
	if h := getenv("HOME"); h != "" && filepath.IsAbs(h) {
		return h, nil
	}
	return "", errors.New("no home directory ($HOME is not set)")
}

// ensureDir creates dir with mode 0700 and refuses one that others can
// reach.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ca: create %s: %w", dir, err)
	}
	return checkPrivateDir(dir)
}

func checkPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ca: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("ca: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("ca: %s is accessible to group or others (mode %04o); run `chmod 700 %s`", dir, fi.Mode().Perm(), dir)
	}
	return checkOwner(dir, fi)
}

// readState reads state.json. ok is false when there is none.
func readState(dir string) (st diskState, raw []byte, ok bool, err error) {
	raw, err = readFile(filepath.Join(dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return diskState{}, nil, false, nil
	}
	if err != nil {
		return diskState{}, nil, false, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return diskState{}, nil, false, fmt.Errorf("ca: %s: %w", filepath.Join(dir, stateFile), err)
	}
	if err := st.validate(); err != nil {
		return diskState{}, nil, false, fmt.Errorf("ca: %s: %w", dir, err)
	}
	return st, raw, true, nil
}

func writeState(dir string, st diskState) error {
	st.Version = stateVersion
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, stateFile), append(b, '\n'), 0o600)
}

func genPath(dir, id string, name string) string {
	return filepath.Join(dir, genDir, id, name)
}

// writeGeneration persists a generation: key 0600, certificate 0644, both
// written atomically, in a directory of their own.
func writeGeneration(dir string, g *generation) error {
	gd := filepath.Join(dir, genDir, g.id)
	if err := os.MkdirAll(gd, 0o700); err != nil {
		return fmt.Errorf("ca: create %s: %w", gd, err)
	}
	if err := g.key.Expose(func(b []byte) error {
		return writeFileAtomic(filepath.Join(gd, keyFile), b, 0o600)
	}); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(gd, certFile), []byte(g.certPEM), 0o644)
}

// loadCert reads the public certificate of a generation.
func loadCert(dir, id string) (string, *x509.Certificate, error) {
	b, err := readFile(genPath(dir, id, certFile))
	if err != nil {
		return "", nil, err
	}
	c, err := parseCert(b)
	if err != nil {
		return "", nil, fmt.Errorf("ca: %s: %w", genPath(dir, id, certFile), err)
	}
	return string(b), c, nil
}

// loadGeneration reads a generation with its key and checks they belong
// together.
func loadGeneration(dir, id string) (*generation, error) {
	certPEM, cert, err := loadCert(dir, id)
	if err != nil {
		return nil, err
	}
	key, err := readPrivateFile(genPath(dir, id, keyFile))
	if err != nil {
		return nil, err
	}
	if err := checkKey(cert, key); err != nil {
		key.Wipe()
		return nil, fmt.Errorf("ca: %s: %w", genPath(dir, id, keyFile), err)
	}
	return &generation{id: id, certPEM: certPEM, cert: cert, key: key}, nil
}

// removeUnused deletes every generation directory not named in keep.
func removeUnused(dir string, keep ...string) error {
	entries, err := os.ReadDir(filepath.Join(dir, genDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ca: %w", err)
	}
	var errs []error
	for _, e := range entries {
		used := false
		for _, k := range keep {
			used = used || e.Name() == k
		}
		if used {
			continue
		}
		p := filepath.Join(dir, genDir, e.Name())
		wipeFile(filepath.Join(p, keyFile))
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, fmt.Errorf("ca: remove %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// wipeFile overwrites a key file with zeros before it is removed, a best
// effort against recovery from the filesystem.
func wipeFile(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- path inside the CA directory
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	_, _ = f.Write(make([]byte, fi.Size()))
	_ = f.Sync()
}

// readFile reads a public file of bounded size.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path inside the CA directory or configured by the operator
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("ca: read %s: %w", path, err)
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("ca: %s is larger than %d bytes", path, maxFileSize)
	}
	return b, nil
}

// readPrivateFile reads a key file, refusing one that group or others can
// read or that another user owns. The error names the path, never content.
func readPrivateFile(path string) (secret.Value, error) {
	f, err := os.Open(path) // #nosec G304 -- path inside the CA directory
	if err != nil {
		return secret.Value{}, fmt.Errorf("ca: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return secret.Value{}, fmt.Errorf("ca: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return secret.Value{}, fmt.Errorf("ca: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return secret.Value{}, fmt.Errorf("ca: %s is readable by group or others (mode %04o); refusing to use it, run `chmod 600 %s`",
			path, fi.Mode().Perm(), path)
	}
	if err := checkOwner(path, fi); err != nil {
		return secret.Value{}, err
	}
	b := make([]byte, 0, 512)
	b, err = readAllInto(f, b)
	if err != nil {
		secret.WipeBytes(b)
		return secret.Value{}, fmt.Errorf("ca: read %s failed", path)
	}
	if len(b) > maxFileSize {
		secret.WipeBytes(b)
		return secret.Value{}, fmt.Errorf("ca: %s is larger than %d bytes", path, maxFileSize)
	}
	return secret.Adopt(b), nil
}

// readAllInto reads r to the end without leaving copies of the data in
// discarded buffers.
func readAllInto(r io.Reader, b []byte) ([]byte, error) {
	for {
		if len(b) == cap(b) {
			nb := make([]byte, len(b), 2*cap(b)+512)
			copy(nb, b)
			secret.WipeBytes(b)
			b = nb
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if errors.Is(err, io.EOF) {
			return b, nil
		}
		if err != nil {
			return b, err
		}
		if len(b) > maxFileSize {
			return b, nil
		}
	}
}

// writeFileAtomic writes data to a temporary file next to path with mode,
// syncs it and renames it over path.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("ca: write %s failed", path)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	ok = true
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	d, err := os.Open(dir) // #nosec G304 -- directory we just wrote into
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
