// SPDX-License-Identifier: AGPL-3.0-only

// Package file is the file store adapter: secrets read from files under one
// configured root directory, addressed as `file://<path under root>[#field]`.
//
// The source is read-only: it declares read, list and watch, and a write is
// refused with stores.ErrUnsupported ("file source is read-only") before
// anything is touched.
//
// Every access goes through an os.Root opened on the configured root, so a
// reference cannot leave it: `..` segments and absolute paths are rejected
// as invalid references, and a symlink that points outside the root is
// refused as a permission error.
//
// A file's bytes map to fields by format: raw (the whole file is the field
// "value", one trailing newline removed by default), dotenv (KEY=VALUE
// lines) or json (a top-level object). The default, auto, picks dotenv for
// `.env` names, json for `.json` and raw otherwise. File content is read
// into a buffer that is wiped once the fields are copied out, and no value
// passes through a Go string.
//
// Watch polls: every watch.interval (with jitter) it stats the files under
// the prefix and compares each file's size, modification time and a keyed
// digest of its content, since a rewrite of the same length can land in the
// same coarse mtime tick. The digest key is random per process and the
// digest never leaves the adapter; Metadata.Version is only mtime and size.
package file

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Kind is the adapter kind this package registers.
const Kind = "file"

const readOnly = "file source is read-only"

// Defaults.
const (
	DefaultMaxSize       = 1 << 20
	DefaultWatchInterval = 10 * time.Second
)

func init() {
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		cfg, err := ParseOptions(inst.Name, inst.Options)
		if err != nil {
			return nil, err
		}
		return New(inst.Name, cfg)
	})
}

// Config is the file source's configuration.
type Config struct {
	// Root is the absolute directory every reference is resolved under
	// (option `root`, required).
	Root string
	// Format is how file content maps to fields (option `format`).
	Format Format
	// TrimNewline removes one trailing newline from raw files (option
	// `trim-newline`, default true).
	TrimNewline bool
	// MaxSize refuses larger files (option `max-size`, default 1 MiB).
	MaxSize int64
	// WatchInterval is the polling interval (option `watch.interval`).
	WatchInterval time.Duration
}

// ParseOptions decodes and validates instance options strictly.
func ParseOptions(store string, raw map[string]any) (Config, error) {
	d := options.New(store, raw)
	cfg := Config{
		Root:          d.String("root", ""),
		Format:        Format(d.String("format", string(FormatAuto))),
		TrimNewline:   d.Bool("trim-newline", true),
		MaxSize:       d.Size("max-size", DefaultMaxSize),
		WatchInterval: d.Duration("watch.interval", DefaultWatchInterval),
	}
	if cfg.Root == "" {
		d.Errorf("option root is required")
	} else if !filepath.IsAbs(cfg.Root) {
		d.Errorf("option root must be an absolute path")
	}
	switch cfg.Format {
	case FormatAuto, FormatRaw, FormatDotenv, FormatJSON:
	default:
		d.Errorf("option format must be auto, raw, dotenv or json")
	}
	if cfg.MaxSize <= 0 {
		d.Errorf("option max-size must be positive")
	}
	if cfg.WatchInterval <= 0 {
		d.Errorf("option watch.interval must be positive")
	}
	return cfg, d.Finish()
}

// Adapter is the file source.
type Adapter struct {
	name string
	cfg  Config
	root *os.Root
	key  []byte // digest key for change detection, never exposed

	closeOnce sync.Once
	mu        sync.RWMutex
	closed    bool
}

// New opens the root and returns a file source. Missing or unreadable roots
// fail here, at start-up, rather than on first read.
func New(name string, cfg Config) (*Adapter, error) {
	if cfg.Format == "" {
		cfg.Format = FormatAuto
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxSize
	}
	if cfg.WatchInterval <= 0 {
		cfg.WatchInterval = DefaultWatchInterval
	}
	if !filepath.IsAbs(cfg.Root) {
		return nil, fmt.Errorf("store %s: option root must be an absolute path", name)
	}
	root, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("store %s: open root: %w", name, err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &Adapter{name: name, cfg: cfg, root: root, key: key}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter: read, list and watch.
func (a *Adapter) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapWatch | stores.CapGlob
}

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string, cause error) error {
	e := stores.NewError(a.name, op, ref, kind, cause)
	e.Detail = detail
	return e
}

// clean validates a reference path and returns it in os.Root form.
func clean(p string) (string, bool) {
	if p == "" {
		return ".", true
	}
	if strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || strings.Contains(p, `\`) {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "" {
			return "", false
		}
	}
	return p, true
}

// classify maps a filesystem error to a store error kind. Errors carry the
// path, which is a reference, never content.
func (a *Adapter) classify(op stores.Op, ref stores.Ref, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return a.err(op, ref, stores.ErrNotFound, "", nil)
	case errors.Is(err, fs.ErrPermission):
		return a.err(op, ref, stores.ErrPermission, "", err)
	case strings.Contains(err.Error(), "escapes from parent"), strings.Contains(err.Error(), "not a directory"):
		// os.Root refuses a symlink or path that leaves the root.
		return a.err(op, ref, stores.ErrPermission, "path leaves the store root", nil)
	}
	return a.err(op, ref, stores.ErrUnavailable, "", err)
}

func (a *Adapter) isClosed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.closed
}

func (a *Adapter) format(p string) Format {
	if a.cfg.Format == FormatAuto {
		return detect(p)
	}
	return a.cfg.Format
}

// labels are a file secret's native labels: file.root (the configured
// root), file.path (the absolute path of the file) and file.format (how its
// content maps to fields).
func (a *Adapter) labels(p string) map[string]string {
	l := map[string]string{}
	stores.SetNative(l, Kind, "root", a.cfg.Root)
	stores.SetNative(l, Kind, "path", filepath.Join(a.cfg.Root, filepath.FromSlash(p)))
	stores.SetNative(l, Kind, "format", string(a.format(p)))
	return l
}

func version(fi fs.FileInfo) string {
	return fmt.Sprintf("%d-%d", fi.ModTime().UnixNano(), fi.Size())
}

// readFile opens p under the root and reads it whole. The caller wipes the
// returned buffer.
func (a *Adapter) readFile(op stores.Op, ref stores.Ref, p string) ([]byte, fs.FileInfo, error) {
	f, err := a.root.Open(p)
	if err != nil {
		return nil, nil, a.classify(op, ref, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, a.classify(op, ref, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, a.err(op, ref, stores.ErrNotFound, "not a regular file", nil)
	}
	if fi.Size() > a.cfg.MaxSize {
		return nil, nil, a.err(op, ref, stores.ErrPermission, "file larger than max-size", nil)
	}
	buf := make([]byte, 0, fi.Size()+1)
	for {
		if len(buf) == cap(buf) {
			// The file grew since Stat: grow by hand so the old buffer
			// can be wiped rather than left to the allocator.
			if int64(len(buf)) > a.cfg.MaxSize {
				secret.WipeBytes(buf)
				return nil, nil, a.err(op, ref, stores.ErrPermission, "file larger than max-size", nil)
			}
			nb := make([]byte, len(buf), 2*cap(buf)+512)
			copy(nb, buf)
			secret.WipeBytes(buf)
			buf = nb
		}
		n, err := f.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			secret.WipeBytes(buf)
			return nil, nil, a.classify(op, ref, err)
		}
	}
	if int64(len(buf)) > a.cfg.MaxSize {
		secret.WipeBytes(buf)
		return nil, nil, a.err(op, ref, stores.ErrPermission, "file larger than max-size", nil)
	}
	return buf, fi, nil
}

// Read implements stores.Adapter.
func (a *Adapter) Read(_ context.Context, ref stores.Ref) (stores.Secret, error) {
	if a.isClosed() {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "closed", nil)
	}
	if ref.Selectors != "" {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "the file source has no version selectors", nil)
	}
	p, ok := clean(ref.Path)
	if !ok || p == "." {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "path must be relative to the store root without .. segments", nil)
	}
	buf, fi, err := a.readFile(stores.OpRead, ref, p)
	if err != nil {
		return stores.Secret{}, err
	}
	fields, perr := parse(a.format(p), buf, a.cfg.TrimNewline)
	secret.WipeBytes(buf)
	if perr != nil {
		// perr names a line or offset only.
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, perr.Error(), nil)
	}
	if ref.Field != "" {
		v, ok := fields[ref.Field]
		delete(fields, ref.Field)
		wipeAll(fields)
		if !ok {
			return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "no such field", nil)
		}
		fields = map[string]secret.Value{ref.Field: v}
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	slices.Sort(names)
	return stores.Secret{
		Meta: stores.Metadata{
			Ref:       ref.Secret(),
			Fields:    names,
			Version:   version(fi),
			UpdatedAt: fi.ModTime().UTC(),
			Labels:    a.labels(ref.Path),
		},
		Fields: fields,
	}, nil
}

type entry struct {
	path string
	fi   fs.FileInfo
}

// walk lists regular files under prefix (a file or directory), following
// symlinks only where they stay inside the root.
func (a *Adapter) walk(prefix string) ([]entry, error) {
	fsys := a.root.FS()
	fi, err := a.root.Stat(prefix)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if fi.Mode().IsRegular() {
		return []entry{{prefix, fi}}, nil
	}
	if !fi.IsDir() {
		return nil, nil
	}
	var out []entry
	err = fs.WalkDir(fsys, prefix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // removed while walking
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, err := a.root.Stat(p) // follows symlinks, refuses escapes
		if err != nil || !fi.Mode().IsRegular() {
			return nil //nolint:nilerr // unreadable and non-regular entries are skipped, not fatal
		}
		out = append(out, entry{p, fi})
		return nil
	})
	return out, err
}

// scope is what a List or Watch prefix covers: everything walked from dir
// whose path starts with glob (empty: everything).
type scope struct{ dir, glob string }

func (s scope) match(p string) bool { return strings.HasPrefix(p, s.glob) }

// prefixPath turns a List or Watch prefix into a scope. `dir` and `dir/*`
// cover the folder; a trailing `*` after part of a name (`dir/app-*`,
// `app*`) is a glob (stores.CapGlob): every file whose path under the root
// starts with the text before it, walked from its folder.
func (a *Adapter) prefixPath(op stores.Op, prefix stores.Ref) (scope, error) {
	if a.isClosed() {
		return scope{}, a.err(op, prefix, stores.ErrUnavailable, "closed", nil)
	}
	bad := a.err(op, prefix, stores.ErrInvalidRef, "path must be relative to the store root without .. segments", nil)
	p := prefix.Path
	if text, ok := strings.CutSuffix(p, "*"); ok && text != "" && !strings.HasSuffix(text, "/") {
		dir := "."
		if i := strings.LastIndexByte(text, '/'); i >= 0 {
			dir = text[:i]
		}
		d, ok := clean(dir)
		if !ok || strings.Contains(text, "*") {
			return scope{}, bad
		}
		if _, ok := clean(text); !ok {
			return scope{}, bad
		}
		return scope{dir: d, glob: text}, nil
	}
	d, ok := clean(strings.TrimSuffix(strings.TrimSuffix(p, "*"), "/"))
	if !ok {
		return scope{}, bad
	}
	return scope{dir: d}, nil
}

// List implements stores.Adapter. Field names are not reported, since that
// would need reading every file's content.
func (a *Adapter) List(_ context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	sc, err := a.prefixPath(stores.OpList, prefix)
	if err != nil {
		return nil, err
	}
	entries, err := a.walk(sc.dir)
	if err != nil {
		return nil, a.classify(stores.OpList, prefix, err)
	}
	out := make([]stores.Metadata, 0, len(entries))
	for _, e := range entries {
		if !sc.match(e.path) {
			continue
		}
		out = append(out, stores.Metadata{
			Ref:       stores.Ref{Scheme: prefix.Scheme, Path: e.path},
			Version:   version(e.fi),
			UpdatedAt: e.fi.ModTime().UTC(),
			Labels:    a.labels(e.path),
		})
	}
	return out, nil
}

type state struct {
	version string
	digest  [sha256.Size]byte
}

func (a *Adapter) snapshot(sc scope) (map[string]state, error) {
	entries, err := a.walk(sc.dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]state, len(entries))
	for _, e := range entries {
		if !sc.match(e.path) {
			continue
		}
		st := state{version: version(e.fi)}
		if buf, _, err := a.readFile(stores.OpWatch, stores.Ref{}, e.path); err == nil {
			m := hmac.New(sha256.New, a.key)
			m.Write(buf)
			copy(st.digest[:], m.Sum(nil))
			secret.WipeBytes(buf)
		}
		out[e.path] = st
	}
	return out, nil
}

func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d/5)+1))
	if err != nil {
		return d
	}
	return d - d/10 + time.Duration(n.Int64())
}

// Watch implements stores.Adapter by polling. The baseline is taken before
// Watch returns, so a change made after it is always reported. A poll that
// fails (for example the root became unreadable) reports nothing and keeps
// the previous baseline, so a transient error never looks like deletions.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	p, err := a.prefixPath(stores.OpWatch, prefix)
	if err != nil {
		return nil, err
	}
	prev, err := a.snapshot(p)
	if err != nil {
		return nil, a.classify(stores.OpWatch, prefix, err)
	}
	ch := make(chan stores.Change, 64)
	go func() {
		defer close(ch)
		timer := time.NewTimer(jitter(a.cfg.WatchInterval))
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if a.isClosed() {
				return
			}
			cur, err := a.snapshot(p)
			if err == nil {
				for _, c := range diff(prefix.Scheme, prev, cur) {
					select {
					case ch <- c:
					case <-ctx.Done():
						return
					}
				}
				prev = cur
			}
			timer.Reset(jitter(a.cfg.WatchInterval))
		}
	}()
	return ch, nil
}

func diff(scheme string, prev, cur map[string]state) []stores.Change {
	var out []stores.Change
	for p, s := range cur {
		if old, ok := prev[p]; !ok || old != s {
			out = append(out, stores.Change{Ref: stores.Ref{Scheme: scheme, Path: p}, Kind: stores.Changed})
		}
	}
	for p := range prev {
		if _, ok := cur[p]; !ok {
			out = append(out, stores.Change{Ref: stores.Ref{Scheme: scheme, Path: p}, Kind: stores.Deleted})
		}
	}
	slices.SortFunc(out, func(x, y stores.Change) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out
}

// Write implements stores.Adapter: always refused, before anything is
// touched.
func (a *Adapter) Write(_ context.Context, ref stores.Ref, _ map[string]secret.Value, _ stores.WriteOptions) (stores.Metadata, error) {
	return stores.Metadata{}, a.err(stores.OpWrite, ref.Secret(), stores.ErrUnsupported, readOnly, nil)
}

// Health implements stores.Adapter: the root must still be a readable
// directory.
func (a *Adapter) Health(context.Context) error {
	if a.isClosed() {
		return a.err(stores.OpHealth, stores.Ref{}, stores.ErrUnavailable, "closed", nil)
	}
	if _, err := a.root.Stat("."); err != nil {
		return a.err(stores.OpHealth, stores.Ref{}, stores.ErrUnavailable, "store root not readable", err)
	}
	f, err := a.root.Open(".")
	if err != nil {
		return a.err(stores.OpHealth, stores.Ref{}, stores.ErrUnavailable, "store root not readable", err)
	}
	_ = f.Close()
	return nil
}

// Close implements stores.Adapter. Watches end on their next poll.
func (a *Adapter) Close() error {
	var err error
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		err = a.root.Close()
	})
	return err
}
