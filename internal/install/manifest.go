// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Entry kinds in the install manifest. Each names one change and how
// uninstall reverts it.
const (
	// KindGroup is a group created with groupadd; reverted with groupdel.
	KindGroup = "group"
	// KindUser is a system user created with useradd; reverted with userdel.
	KindUser = "user"
	// KindMember is a user added to a group; reverted with gpasswd -d.
	KindMember = "member"
	// KindDir is a directory created by install; removed when empty.
	KindDir = "dir"
	// KindFile is a file written by install; removed while its content is
	// still what install wrote.
	KindFile = "file"
	// KindService is a unit enabled and started (or only started, for a
	// Quadlet unit); reverted by stopping and disabling it.
	KindService = "service"
	// KindSystemTrust is the CA in the system trust store: an anchor file
	// and the tool that rebuilds the store.
	KindSystemTrust = "system-trust"
	// KindUserTrust is the CA in the per-user trust stores, recorded in the
	// trust manifest of `scrim ca install --user`.
	KindUserTrust = "user-trust"
	// KindState is a state directory that did not exist before install.
	// Uninstall keeps it (it holds the CA, keys and audit log) unless
	// asked to purge.
	KindState = "state"
	// KindVolume is a podman volume the Quadlet container created; removed
	// only when purging.
	KindVolume = "volume"
	// KindImage is an image podman pulled for the Quadlet container;
	// removed only when purging.
	KindImage = "image"
)

// Scopes of a service, volume or image.
const (
	ScopeSystem = "system"
	ScopeUser   = "user"
)

// Entry is one recorded change.
type Entry struct {
	Kind string `json:"kind"`
	// Target is the path, account, unit, volume or image changed.
	Target string `json:"target"`
	// Scope is system or user for services, volumes and images, and the
	// systemd manager to reload after a unit file is removed.
	Scope string `json:"scope,omitempty"`
	// Group is the group of a membership.
	Group string `json:"group,omitempty"`
	// SHA256 is the content written, for files and trust anchors.
	SHA256 string `json:"sha256,omitempty"`
	// Tool is the trust store tool to run after removing an anchor.
	Tool string `json:"tool,omitempty"`
	// Reload names the systemd manager (system or user) to reload after a
	// unit file is removed.
	Reload string    `json:"reload,omitempty"`
	At     time.Time `json:"at"`
}

func (e Entry) same(o Entry) bool {
	return e.Kind == o.Kind && e.Target == o.Target && e.Group == o.Group && e.Scope == o.Scope
}

// Manifest lists every change install made, oldest first.
type Manifest struct {
	Version int  `json:"version"`
	Mode    Mode `json:"mode"`
	// System is true for a system-wide install (--system, or --quadlet
	// --system).
	System  bool    `json:"system"`
	Image   string  `json:"image,omitempty"`
	Entries []Entry `json:"entries"`
}

func (m *Manifest) find(e Entry) int {
	for i, x := range m.Entries {
		if x.same(e) {
			return i
		}
	}
	return -1
}

// ReadManifest reads the manifest at path. A missing one returns ok false.
func ReadManifest(path string) (Manifest, bool, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed manifest location
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{Version: 1}, false, nil
	}
	if err != nil {
		return Manifest{}, false, fmt.Errorf("install: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, false, fmt.Errorf("install: %s: %w", path, err)
	}
	if m.Version != 1 {
		return Manifest{}, false, fmt.Errorf("install: %s: unsupported version %d", path, m.Version)
	}
	return m, true, nil
}

// writeManifest writes m atomically (mode 0600), or removes the file when m
// has no entries left.
func writeManifest(path string, m Manifest) error {
	if len(m.Entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("install: %w", err)
		}
		return nil
	}
	m.Version = 1
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0o600)
}

func writeAtomic(path string, b []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("install: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("install: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}
