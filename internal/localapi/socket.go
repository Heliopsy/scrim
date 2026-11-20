// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Environment variables the clients read. They follow the configuration
// rule: SCRIM_ plus the key upper-cased with dots as underscores, for the keys
// api.socket and session.token.
const (
	EnvSocket = "SCRIM_API_SOCKET"
	EnvToken  = "SCRIM_SESSION_TOKEN"
)

// DefaultSocketPath is where the API listens and clients look when nothing
// else is configured: $XDG_RUNTIME_DIR/scrim/api.sock, or a per-user
// directory under the temporary directory.
func DefaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "scrim", "api.sock")
	}
	return filepath.Join(os.TempDir(), "scrim-"+strconv.Itoa(os.Getuid()), "api.sock")
}

// SocketPath returns the socket clients should use: $SCRIM_API_SOCKET, or
// the default.
func SocketPath() string {
	if p := os.Getenv(EnvSocket); p != "" {
		return p
	}
	return DefaultSocketPath()
}

// ListenOptions configure the socket.
type ListenOptions struct {
	// Mode is the socket file's permission bits. Zero takes 0600: only the
	// user scrim runs as can connect. Agents running as other local users
	// need a wider mode (for example 0660 with a shared group); their
	// identity still comes from peer credentials, and unmapped users are
	// refused.
	Mode fs.FileMode
}

// Listen creates the API socket at path. The parent directory is created
// with mode 0700 when missing. A stale socket left by a crashed scrim is
// replaced; a live one, or any other file at path, is an error.
func Listen(path string, o ListenOptions) (net.Listener, error) {
	// sun_path is 108 bytes on Linux and 104 on macOS, including the NUL.
	if len(path) >= 104 {
		return nil, fmt.Errorf("localapi: socket path %s is %d bytes, longer than Unix sockets allow; set api.socket to a shorter path", path, len(path))
	}
	mode := o.Mode
	if mode == 0 {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("localapi: creating the socket directory: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("localapi: %s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("localapi: another scrim is listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("localapi: removing the stale socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("localapi: checking the socket path: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("localapi: listening: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("localapi: setting the socket mode: %w", err)
	}
	return ln, nil
}
