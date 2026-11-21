// SPDX-License-Identifier: AGPL-3.0-only

package projectscan

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// ErrChanged is returned by [Replace] when the value is no longer where the
// scan found it.
var ErrChanged = errors.New("the file changed since it was scanned")

// Decoded reports whether f is the decoded twin of a quoted value with
// escapes. It names the same place in the file as the raw finding, which is
// the one to move.
func (f Finding) Decoded() bool { return f.decoded }

// Movable returns the findings that can be moved: one per place in a file.
func (r *Result) Movable() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if !f.decoded {
			out = append(out, f)
		}
	}
	return out
}

// Replace rewrites f's value in its file under dir with text, typically a
// `{{scrim:<ref>}}` reference, keeping the file's mode. It checks that the
// value is still at the position the scan recorded and refuses otherwise.
// The file is replaced atomically.
func Replace(dir string, f Finding, text string) error {
	if f.decoded {
		return errors.New("projectscan: replace the raw finding, not its decoded form")
	}
	rel := filepath.FromSlash(f.File)
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("projectscan: %s is outside the project", f.File)
	}
	p := filepath.Join(dir, rel)
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(p) //nolint:gosec // a project file the user asked to rewrite
	if err != nil {
		return err
	}
	buf := secret.Adopt(data)
	defer buf.Wipe()
	var out []byte
	err = buf.Expose(func(b []byte) error {
		ls, le, ok := lineBounds(b, f.Line)
		if !ok || ls+f.end > le {
			return ErrChanged
		}
		at := b[ls+f.start : ls+f.end]
		same := false
		_ = f.Value.Expose(func(v []byte) error {
			same = subtle.ConstantTimeCompare(at, v) == 1
			return nil
		})
		if !same {
			return ErrChanged
		}
		out = make([]byte, 0, len(b)-len(at)+len(text))
		out = append(out, b[:ls+f.start]...)
		out = append(out, text...)
		out = append(out, b[ls+f.end:]...)
		return nil
	})
	defer secret.WipeBytes(out)
	if err != nil {
		return fmt.Errorf("%s:%d: %w", f.File, f.Line, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".scrim-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// lineBounds returns the byte range of line n (1-based) without its newline.
func lineBounds(b []byte, n int) (start, end int, ok bool) {
	for i := 1; i < n; i++ {
		j := bytes.IndexByte(b[start:], '\n')
		if j < 0 {
			return 0, 0, false
		}
		start += j + 1
	}
	if start > len(b) {
		return 0, 0, false
	}
	end = len(b)
	if j := bytes.IndexByte(b[start:], '\n'); j >= 0 {
		end = start + j
	}
	return start, end, true
}
