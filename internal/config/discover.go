// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// EnvConfig names the variable holding explicit config file paths, separated
// like PATH. It is not a setting: it decides which files are read.
const EnvConfig = "SCRIM_CONFIG"

// SystemConfigDir is the system-wide configuration directory.
const SystemConfigDir = "/etc/scrim"

// configFileName is the file looked for in each search directory.
const configFileName = "config.yaml"

// Discovery is the outcome of the config file search.
type Discovery struct {
	// Paths are the top-level files to load, in order; later ones win.
	Paths []string
	// Explicit reports whether Paths came from --config or SCRIM_CONFIG.
	Explicit bool
	// Searched lists the candidates looked at when no explicit path was
	// given, in search order.
	Searched []string
}

// Discover finds the config files to load. Explicit paths (from --config,
// then SCRIM_CONFIG) are used as given and must exist. Otherwise the first
// existing file of $XDG_CONFIG_HOME/scrim/config.yaml,
// ~/.config/scrim/config.yaml and <systemDir>/config.yaml is used, and no
// file at all is fine: every setting keeps its default.
func Discover(explicit []string, env map[string]string, systemDir string) (Discovery, error) {
	if len(explicit) == 0 {
		if v := env[EnvConfig]; v != "" {
			explicit = filepath.SplitList(v)
		}
	}
	if len(explicit) > 0 {
		d := Discovery{Explicit: true}
		var errs []error
		for _, p := range explicit {
			if p == "" {
				continue
			}
			abs, err := filepath.Abs(p)
			if err != nil {
				errs = append(errs, &Problem{Err: fmt.Errorf("config file %s: %w", p, err)})
				continue
			}
			if err := regularFile(abs); err != nil {
				errs = append(errs, &Problem{Err: fmt.Errorf("config file %s: %w", abs, err)})
				continue
			}
			d.Paths = append(d.Paths, abs)
		}
		return d, errors.Join(errs...)
	}

	if systemDir == "" {
		systemDir = SystemConfigDir
	}
	var d Discovery
	if xdg := env["XDG_CONFIG_HOME"]; xdg != "" && filepath.IsAbs(xdg) {
		d.Searched = append(d.Searched, filepath.Join(xdg, "scrim", configFileName))
	}
	if home := env["HOME"]; home != "" {
		d.Searched = append(d.Searched, filepath.Join(home, ".config", "scrim", configFileName))
	}
	d.Searched = append(d.Searched, filepath.Join(systemDir, configFileName))
	seen := map[string]bool{}
	for _, p := range d.Searched {
		if seen[p] {
			continue
		}
		seen[p] = true
		err := regularFile(p)
		if err == nil {
			d.Paths = []string{p}
			return d, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			// A candidate that exists but cannot be read is a problem, not
			// a reason to fall through to a file with other settings.
			return d, &Problem{Err: fmt.Errorf("config file %s: %w", p, err)}
		}
	}
	return d, nil
}

func regularFile(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return pe.Err
		}
		return err
	}
	if fi.IsDir() {
		return errors.New("is a directory")
	}
	return nil
}

// environMap turns os.Environ-style pairs into a map. A later duplicate wins,
// as in the process environment.
func environMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}
