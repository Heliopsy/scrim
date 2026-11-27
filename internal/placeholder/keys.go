// SPDX-License-Identifier: AGPL-3.0-only

package placeholder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/fsperm"
	"github.com/heliopsy/scrim/internal/secret"
)

// Settings of the placeholder keys.
var (
	// Keys are operator-supplied key versions, by reference.
	Keys = config.RegisterCollection(config.CollectionSpec{
		Key: "redaction.placeholder-keys",
		Description: "Placeholder keys by name, each with `version` (1 to 255) and `key` (a reference to at least 16 bytes). " +
			"The highest version is current; lower ones keep resolving placeholders made before a rotation. " +
			"Every replica sharing conversations needs the same keys. Empty means a key generated once and kept in redaction.placeholder-key-dir.",
		SecretFields:   []string{"key"},
		RequiredFields: []string{"version", "key"},
		Validate: func(inst config.Instance) error {
			_, err := versionOf(inst)
			return err
		},
	})
	// KeyDir holds the generated key when no key is configured.
	KeyDir = config.Register(config.Spec[string]{
		Key:             "redaction.placeholder-key-dir",
		KeyMaterial:     true,
		KeyMaterialWhen: func(c *config.Config) bool { return len(Keys.Get(c)) == 0 },
		Description:     "Directory of the generated placeholder key, used when redaction.placeholder-keys is empty. Empty means $XDG_STATE_HOME/scrim/keys (~/.local/state/scrim/keys).",
		RestartRequired: true,
	})
)

// Ring is the placeholder keys in force: the current one and those retained
// for placeholders made before a rotation. It owns the key bytes.
type Ring struct {
	// Keys are sorted by version, highest (current) first.
	Keys []Key
	// Source says where the keys came from, for logs and status: a list of
	// setting keys or the generated key file. Never key material.
	Source string
}

// Current returns the key new placeholders are derived with.
func (r *Ring) Current() Key { return r.Keys[0] }

// Wipe clears every key.
func (r *Ring) Wipe() {
	for _, k := range r.Keys {
		k.Key.Wipe()
	}
}

// Load returns the configured keys, or the generated key, creating and
// persisting it the first time. The key bytes are never logged.
func Load(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Ring, error) {
	if insts := Keys.Get(cfg); len(insts) > 0 {
		return fromConfig(ctx, cfg, insts)
	}
	dir := KeyDir.Get(cfg)
	if dir == "" {
		d, err := cfg.StateDir()
		if err != nil {
			return nil, fmt.Errorf("placeholder: %w", err)
		}
		dir = filepath.Join(d, "keys")
	}
	return loadOrGenerate(dir, log)
}

func versionOf(inst config.Instance) (int, error) {
	raw, _ := inst.Field("version")
	var v int
	switch x := raw.(type) {
	case int:
		v = x
	case float64:
		v = int(x)
	case string:
		n, err := strconv.Atoi(x)
		if err != nil {
			return 0, fmt.Errorf("redaction.placeholder-keys.%s.version: %w", inst.Name, ErrKeyVersion)
		}
		v = n
	}
	if v < 1 || v > 255 {
		return 0, fmt.Errorf("redaction.placeholder-keys.%s.version: %w", inst.Name, ErrKeyVersion)
	}
	return v, nil
}

func fromConfig(ctx context.Context, cfg *config.Config, insts []config.Instance) (*Ring, error) {
	r := &Ring{}
	var names []string
	seen := map[int]string{}
	for _, inst := range insts {
		v, err := versionOf(inst)
		if err != nil {
			r.Wipe()
			return nil, err
		}
		if other, dup := seen[v]; dup {
			r.Wipe()
			return nil, fmt.Errorf("redaction.placeholder-keys: %s and %s both have version %d", other, inst.Name, v)
		}
		seen[v] = inst.Name
		field := inst.Key(Keys.Key(), "key")
		val, ok := cfg.SecretAt(field)
		if ok {
			val = copyOf(val)
		} else {
			val, err = cfg.ResolveRef(ctx, config.SecretRef(inst.String("key")))
			if err != nil {
				r.Wipe()
				return nil, fmt.Errorf("%s: %w", field, err)
			}
		}
		k := Key{Version: v, Key: val}
		if err := k.Validate(); err != nil {
			val.Wipe()
			r.Wipe()
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		r.Keys = append(r.Keys, k)
		names = append(names, field)
	}
	slices.SortFunc(r.Keys, func(a, b Key) int { return b.Version - a.Version })
	slices.Sort(names)
	r.Source = strings.Join(names, ", ")
	return r, nil
}

func copyOf(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}

var keyFile = regexp.MustCompile(`^placeholder-([0-9a-f]{2})\.key$`)

// loadOrGenerate reads every placeholder-<vv>.key in dir, generating
// placeholder-01.key when there is none. Files hold the key in hex.
func loadOrGenerate(dir string, log *slog.Logger) (*Ring, error) {
	if err := fsperm.MkdirPrivate(dir); err != nil {
		return nil, fmt.Errorf("placeholder: creating %s: %w", dir, err)
	}
	if err := private(dir, true); err != nil {
		return nil, err
	}
	r, err := readDir(dir)
	if err != nil {
		return nil, err
	}
	if len(r.Keys) > 0 {
		return r, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("placeholder: generating a key: %w", err)
	}
	enc := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(enc, raw)
	secret.WipeBytes(raw)
	path := filepath.Join(dir, "placeholder-01.key")
	err = writeExclusive(path, enc)
	secret.WipeBytes(enc)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if log != nil && err == nil {
		log.Info("generated a placeholder key; set redaction.placeholder-keys to share one between replicas", "file", path)
	}
	// Read back, so two processes racing to generate end on the same key.
	return readDir(dir)
}

func readDir(dir string) (*Ring, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("placeholder: reading %s: %w", dir, err)
	}
	r := &Ring{}
	var files []string
	for _, e := range entries {
		m := keyFile.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		v, _ := strconv.ParseUint(m[1], 16, 8)
		path := filepath.Join(dir, e.Name())
		if err := private(path, false); err != nil {
			r.Wipe()
			return nil, err
		}
		k, err := readKey(path, int(v))
		if err != nil {
			r.Wipe()
			return nil, err
		}
		r.Keys = append(r.Keys, k)
		files = append(files, path)
	}
	slices.SortFunc(r.Keys, func(a, b Key) int { return b.Version - a.Version })
	r.Source = strings.Join(files, ", ")
	return r, nil
}

func readKey(path string, version int) (Key, error) {
	enc, err := os.ReadFile(path) //nolint:gosec // the path is built from a configured directory and a fixed pattern
	if err != nil {
		return Key{}, fmt.Errorf("placeholder: reading %s: %w", path, err)
	}
	defer secret.WipeBytes(enc)
	trimmed := []byte(strings.TrimSpace(string(enc)))
	defer secret.WipeBytes(trimmed)
	raw := make([]byte, hex.DecodedLen(len(trimmed)))
	if _, err := hex.Decode(raw, trimmed); err != nil {
		secret.WipeBytes(raw)
		return Key{}, fmt.Errorf("placeholder: %s does not hold a hex key", path)
	}
	k := Key{Version: version, Key: secret.Adopt(raw)}
	if err := k.Validate(); err != nil {
		k.Key.Wipe()
		return Key{}, fmt.Errorf("placeholder: %s: %w", path, err)
	}
	return k, nil
}

// private refuses a key file or directory group or others can access.
func private(path string, dir bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("placeholder: %w", err)
	}
	if fi.IsDir() != dir {
		return fmt.Errorf("placeholder: %s has the wrong type", path)
	}
	if loose, detail, err := fsperm.Loose(path, fi); err != nil {
		return fmt.Errorf("placeholder: %w", err)
	} else if loose {
		return fmt.Errorf("placeholder: %s is accessible to group or others (%s); %s", path, detail, fsperm.FixHint(path, dir))
	}
	return nil
}

func writeExclusive(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".placeholder-*.tmp")
	if err != nil {
		return fmt.Errorf("placeholder: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("placeholder: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("placeholder: writing the key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("placeholder: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("placeholder: %w", err)
	}
	// A hard link fails if the target exists, so a concurrent generator
	// never replaces a key already in use.
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fs.ErrExist
		}
		return fmt.Errorf("placeholder: %w", err)
	}
	return nil
}
