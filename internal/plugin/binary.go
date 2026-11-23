// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CheckBinary resolves command and refuses to run it unless it is safe to:
// an absolute path to a regular executable file that, like every directory
// above it, is owned by root or by scrim's user and writable by no one else
// (a world-writable directory is accepted only with the sticky bit, as /tmp
// has it). With want set, the file's sha256 must equal it. It returns the
// resolved path, which is what is executed, so a symlink cannot be pointed
// elsewhere between the check and the start.
//
// The check and the exec are not atomic: whoever may replace the file could
// swap it in between, which is why no one but root and scrim's user may.
func CheckBinary(command, want string) (string, error) {
	if command == "" {
		return "", fmt.Errorf("command is not set")
	}
	if !filepath.IsAbs(command) {
		return "", fmt.Errorf("command %s is not an absolute path", command)
	}
	resolved, err := filepath.EvalSymlinks(command)
	if err != nil {
		return "", fmt.Errorf("command %s: %w", command, err)
	}
	if err := checkOwnership(resolved); err != nil {
		return "", fmt.Errorf("command %s: %w", command, err)
	}
	if want != "" {
		if err := checkSum(resolved, want); err != nil {
			return "", fmt.Errorf("command %s: %w", command, err)
		}
	}
	return resolved, nil
}

// checkSum compares the file's sha256 with want, a hex digest optionally
// prefixed `sha256:`.
func checkSum(path, want string) error {
	want = strings.ToLower(strings.TrimPrefix(want, "sha256:"))
	if len(want) != sha256.Size*2 {
		return fmt.Errorf("sha256 must be 64 hex digits")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("sha256 is %s, configuration pins %s", got, want)
	}
	return nil
}
