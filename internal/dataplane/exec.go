// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// executable is a materialised image ready to exec.
type executable struct {
	// path is what exec runs: /proc/self/fd/N or a file path.
	path string
	// keep holds the descriptor path refers to open until the child runs.
	keep *os.File
	// how says which mechanism was used, for logs: "memfd" or "file".
	how string
}

func (e *executable) Close() {
	if e != nil && e.keep != nil {
		_ = e.keep.Close()
	}
}

// fileName is the cached file's name: content-addressed, so a different
// build never reuses another's file.
func fileName(sum [32]byte) string {
	return "scrim-dataplane-" + hex.EncodeToString(sum[:8])
}

// writeVerified makes sure dir/fileName(sum) holds exactly the image and
// returns it opened read-only, its content checked against sum through the
// returned descriptor. dir is created 0700 and must be owned by us.
func writeVerified(dir string, b Binary) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkPrivateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, fileName(b.Sum))
	if f, err := openVerified(path, b.Sum); err == nil {
		return f, nil
	}
	tmp, err := os.CreateTemp(dir, ".scrim-dataplane-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := io.Copy(tmp, bytes.NewReader(b.Image)); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Chmod(0o500); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, err
	}
	return openVerified(path, b.Sum)
}

// openVerified opens path and checks its content hashes to sum.
func openVerified(path string, sum [32]byte) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return nil, err
	}
	if !bytes.Equal(h.Sum(nil), sum[:]) {
		_ = f.Close()
		return nil, fmt.Errorf("%s does not match the expected data plane hash", path)
	}
	return f, nil
}

// checkPrivateDir refuses a directory other users can write to or that we
// do not own, since anyone who can replace the file controls the data plane.
func checkPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by other users", dir)
	}
	return checkOwner(fi, dir)
}
