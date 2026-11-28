// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/heliopsy/scrim/internal/runtimedir"
)

// Environment variables the clients read. They follow the configuration
// rule: SCRIM_ plus the key upper-cased with dots as underscores, for the keys
// api.socket and session.token.
const (
	EnvSocket = "SCRIM_API_SOCKET"
	EnvToken  = "SCRIM_SESSION_TOKEN"
)

// DefaultSocketPath is where the API listens and clients look when nothing
// else is configured: api.sock in this user's runtime directory
// ([runtimedir.Dir]).
func DefaultSocketPath() string { return filepath.Join(runtimedir.Dir(), "api.sock") }

// SystemRuntimeDir holds the sockets of the system service that
// `scrim install --system` sets up. A variable so tests can move it.
var SystemRuntimeDir = "/run/scrim"

// SystemAgentGroup is the group whose members may use the system service's
// agent API socket.
const SystemAgentGroup = "scrim-agents"

// SystemSocketPath is the system service's agent API socket.
func SystemSocketPath() string { return filepath.Join(SystemRuntimeDir, "api.sock") }

// SocketPath returns the socket clients should use: $SCRIM_API_SOCKET, or
// the default.
func SocketPath() string {
	if p := os.Getenv(EnvSocket); p != "" {
		return p
	}
	return DefaultSocketPath()
}

// ClientSocketPath is where a client looks when nothing is configured: the
// per-user default socket when it exists, otherwise the system service's
// socket when that exists, otherwise the per-user default (so the error
// names the path the user's own daemon would use).
func ClientSocketPath() string {
	def := DefaultSocketPath()
	if _, err := os.Stat(def); err == nil {
		return def
	}
	if fi, err := os.Stat(SystemSocketPath()); err == nil && fi.Mode().Type() == fs.ModeSocket {
		return SystemSocketPath()
	}
	return def
}

// ListenOptions configure the socket.
type ListenOptions struct {
	// Mode is the socket file's permission bits. Zero takes 0600: only the
	// user scrim runs as can connect. Agents running as other local users
	// need a wider mode (for example 0660 with a shared group); their
	// identity still comes from peer credentials, and unmapped users are
	// refused.
	Mode fs.FileMode
	// Group, when positive, is the group ID the socket file is given,
	// so members of that group can connect under a 0660 mode. The process
	// must be a member of it.
	Group int
}

// Listen creates the API socket at path. The parent directory is created
// with mode 0700 when missing; in this user's runtime directory, one owned
// by another user or writable by group or others is refused
// ([runtimedir.Mkdir]). A stale socket left by a crashed scrim is
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
	if err := runtimedir.Mkdir(filepath.Dir(path)); err != nil {
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
	if o.Group > 0 {
		if err := os.Chown(path, -1, o.Group); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("localapi: setting the socket group: %w", err)
		}
	}
	if err := setMode(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("localapi: setting the socket mode: %w", err)
	}
	return ln, nil
}
