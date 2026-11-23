// SPDX-License-Identifier: AGPL-3.0-only

// Package sops is the SOPS file store adapter: secrets read from
// SOPS-encrypted files under one configured root directory, addressed as
// `<instance>://<path under root>[#key-path]`.
//
// The source is read-only: it declares read, list, watch and glob, and a
// write is refused with stores.ErrUnsupported ("sops source is read-only")
// before anything is touched.
//
// Files are YAML, JSON, dotenv or INI documents as sops writes them (a
// binary file is a JSON document with one `data` key). They are decrypted
// with the age identities named by the `age-identity` option, resolved
// through stores.Instance.Resolve on first use, never from sops' ambient
// locations. Decryption is implemented here, compatible with sops 3: the
// data key is opened with filippo.io/age, every encrypted value with
// AES-256-GCM bound to its key path, and the file's MAC (SHA-512 over every
// value, encrypted with the data key) is verified before any value is
// returned, so a file whose values or MAC were changed is refused. The
// getsops library itself is not used: it links every cloud KMS client.
//
// A field is the key path of an encrypted leaf: map keys and list indices
// joined by '/', with '~' and '/' inside a key escaped as "~0" and "~1"
// (RFC 6901). Leaves sops left unencrypted (unencrypted_suffix and the
// other rules) are covered by the MAC but are not fields. Comments are
// neither.
//
// sops metadata is plaintext, so List and ReadMetadata report field names
// and native labels (sops.*) without decrypting anything.
//
// Every access goes through an os.Root opened on the configured root, as in
// the file source. Watch polls, comparing each file's size, modification
// time and a keyed digest of its bytes; the digest key is random per process
// and the digest never leaves the adapter.
package sops

import (
	"bytes"
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

	"filippo.io/age"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Kind is the adapter kind this package registers.
const Kind = "sops"

const readOnly = "sops source is read-only"

// Defaults.
const (
	DefaultMaxSize       = 1 << 20
	DefaultWatchInterval = 10 * time.Second
)

// Native label attributes (sops.<attr>).
const (
	labelRoot         = "root"
	labelPath         = "path"
	labelFormat       = "format"
	labelVersion      = "version"
	labelLastModified = "lastmodified"
	labelMACOnly      = "mac-only-encrypted"
	labelKeyType      = "key-type"
	labelAgeRecipient = "age-recipient"
	labelPGP          = "pgp-fingerprint"
	labelKeyGroups    = "key-groups"
	labelShamir       = "shamir-threshold"
)

func init() {
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		cfg, err := ParseOptions(inst.Name, inst.Options)
		if err != nil {
			return nil, err
		}
		return New(inst.Name, cfg, inst.Resolve)
	})
	stores.DeclareMulti(Kind, labelKeyType, labelAgeRecipient, labelPGP)
}

// Config is the SOPS source's configuration.
type Config struct {
	// Root is the absolute directory every reference is resolved under
	// (option `root`, required).
	Root string
	// Format is the document format (option `format`, default auto).
	Format Format
	// AgeIdentity names the age identities, in age's identity file format,
	// by reference (option `age-identity`, required): `file:/path`,
	// `env:NAME`, `cred:NAME` or a reference into another store.
	AgeIdentity config.SecretRef
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
		AgeIdentity:   d.SecretRef("age-identity"),
		MaxSize:       d.Size("max-size", DefaultMaxSize),
		WatchInterval: d.Duration("watch.interval", DefaultWatchInterval),
	}
	if cfg.Root == "" {
		d.Errorf("option root is required")
	} else if !filepath.IsAbs(cfg.Root) {
		d.Errorf("option root must be an absolute path")
	}
	switch cfg.Format {
	case FormatAuto, FormatYAML, FormatJSON, FormatDotenv, FormatINI:
	default:
		d.Errorf("option format must be auto, yaml, json, dotenv or ini")
	}
	if cfg.AgeIdentity == "" {
		d.Errorf("option age-identity is required (a reference such as file:/path or env:NAME)")
	}
	if cfg.MaxSize <= 0 {
		d.Errorf("option max-size must be positive")
	}
	if cfg.WatchInterval <= 0 {
		d.Errorf("option watch.interval must be positive")
	}
	return cfg, d.Finish()
}

// Resolver resolves the age identity reference (stores.Instance.Resolve).
type Resolver func(ctx context.Context, ref config.SecretRef) (secret.Value, error)

// Adapter is the SOPS source.
type Adapter struct {
	name    string
	cfg     Config
	root    *os.Root
	key     []byte // digest key for change detection, never exposed
	resolve Resolver

	idMu sync.Mutex
	ids  []age.Identity
	// keys are the AGE-SECRET-KEY lines of the identity, kept to report
	// as credentials (stores.CredentialHolder) and wiped on Close.
	keys []secret.Value

	closeOnce sync.Once
	mu        sync.RWMutex
	closed    bool
}

// New opens the root and returns a SOPS source. Missing or unreadable roots
// fail here, at start-up. The age identity is resolved on first use.
func New(name string, cfg Config, resolve Resolver) (*Adapter, error) {
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
	return &Adapter{name: name, cfg: cfg, root: root, key: key, resolve: resolve}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter: read, list, watch and glob.
func (a *Adapter) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapWatch | stores.CapGlob
}

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string, cause error) error {
	e := stores.NewError(a.name, op, ref, kind, cause)
	e.Detail = detail
	return e
}

func (a *Adapter) isClosed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.closed
}

// identities resolves and parses the age identity once. The resolved bytes
// are wiped once parsed; the secret key lines are kept as credentials.
func (a *Adapter) identities(ctx context.Context, op stores.Op, ref stores.Ref) ([]age.Identity, error) {
	a.idMu.Lock()
	defer a.idMu.Unlock()
	if a.ids != nil {
		return a.ids, nil
	}
	if a.resolve == nil {
		return nil, a.err(op, ref, stores.ErrLocked, "age identity not configured", nil)
	}
	v, err := a.resolve(ctx, a.cfg.AgeIdentity)
	if err != nil {
		// The resolver names the reference, never its value.
		return nil, a.err(op, ref, stores.ErrLocked, "age identity could not be resolved", err)
	}
	defer v.Wipe()
	var ids []age.Identity
	var keys []secret.Value
	perr := v.Expose(func(b []byte) error {
		var err error
		// age's own parser keeps the keys it parses in its identity
		// values, which scrim cannot wipe; this is the one copy kept.
		ids, err = age.ParseIdentities(bytes.NewReader(b))
		if err != nil {
			return err
		}
		for line := range bytes.SplitSeq(b, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if bytes.HasPrefix(line, []byte("AGE-SECRET-KEY-")) {
				keys = append(keys, secret.New(line))
			}
		}
		return nil
	})
	if perr != nil || len(ids) == 0 {
		// age's parse error is not passed on: it may quote the key.
		return nil, a.err(op, ref, stores.ErrLocked, "age identity does not parse as an age identity file", nil)
	}
	a.ids, a.keys = ids, keys
	return ids, nil
}

// Credentials implements stores.CredentialHolder: copies of the age secret
// keys, once resolved, so scrim redacts them.
func (a *Adapter) Credentials() []secret.Value {
	a.idMu.Lock()
	defer a.idMu.Unlock()
	out := make([]secret.Value, 0, len(a.keys))
	for _, k := range a.keys {
		_ = k.Expose(func(b []byte) error {
			out = append(out, secret.New(b))
			return nil
		})
	}
	return out
}

// clean validates a reference path and returns it in os.Root form.
func clean(p string) (string, bool) {
	if p == "" {
		return ".", true
	}
	if strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || strings.Contains(p, `\`) {
		return "", false
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".." || seg == "" {
			return "", false
		}
	}
	return p, true
}

// classify maps a filesystem error to a store error kind.
func (a *Adapter) classify(op stores.Op, ref stores.Ref, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return a.err(op, ref, stores.ErrNotFound, "", nil)
	case errors.Is(err, fs.ErrPermission):
		return a.err(op, ref, stores.ErrPermission, "", err)
	case strings.Contains(err.Error(), "escapes from parent"), strings.Contains(err.Error(), "not a directory"):
		return a.err(op, ref, stores.ErrPermission, "path leaves the store root", nil)
	}
	return a.err(op, ref, stores.ErrUnavailable, "", err)
}

// classifyDoc maps a parse, metadata or decryption error to a store error.
// None of these errors carries a value: parse errors name a line or offset,
// decryption errors a field (a key path) at most.
func (a *Adapter) classifyDoc(op stores.Op, ref stores.Ref, err error) error {
	var unsup errUnsupported
	switch {
	case errors.As(err, &unsup):
		return a.err(op, ref, stores.ErrUnsupported, err.Error(), nil)
	case errors.Is(err, errNoKey):
		return a.err(op, ref, stores.ErrPermission, errNoKey.Error(), nil)
	case errors.Is(err, errIntegrity):
		return a.err(op, ref, stores.ErrPermission, err.Error()+"; the file was modified or the MAC does not match, refused", nil)
	}
	return a.err(op, ref, stores.ErrInvalidRef, err.Error(), nil)
}

func (a *Adapter) format(p string) Format {
	if a.cfg.Format == FormatAuto {
		return detect(p)
	}
	return a.cfg.Format
}

// baseLabels are the labels every file gets: sops.root, sops.path (the
// absolute path) and sops.format.
func (a *Adapter) baseLabels(p string) map[string]string {
	l := map[string]string{}
	stores.SetNative(l, Kind, labelRoot, a.cfg.Root)
	stores.SetNative(l, Kind, labelPath, filepath.Join(a.cfg.Root, filepath.FromSlash(p)))
	stores.SetNative(l, Kind, labelFormat, string(a.format(p)))
	return l
}

// labels adds what the file's sops metadata says: version, lastmodified,
// key types, age recipients, PGP fingerprints, key groups and the
// encryption rule. All of it is plaintext metadata.
func (a *Adapter) labels(p string, md *metadata) map[string]string {
	l := a.baseLabels(p)
	stores.SetNative(l, Kind, labelVersion, md.version)
	stores.SetNative(l, Kind, labelLastModified, md.lastModRaw)
	if md.macOnly {
		stores.SetNative(l, Kind, labelMACOnly, "true")
	}
	stores.SetNative(l, Kind, labelKeyType, md.keyTypes...)
	recips := make([]string, 0, len(md.age))
	for _, k := range md.age {
		recips = append(recips, k.recipient)
	}
	stores.SetNative(l, Kind, labelAgeRecipient, recips...)
	stores.SetNative(l, Kind, labelPGP, md.pgp...)
	if md.groups > 1 {
		stores.SetNative(l, Kind, labelKeyGroups, fmt.Sprint(md.groups))
		if md.shamir > 0 {
			stores.SetNative(l, Kind, labelShamir, fmt.Sprint(md.shamir))
		}
	}
	stores.SetNative(l, Kind, "unencrypted-suffix", md.unencSuffix)
	stores.SetNative(l, Kind, "encrypted-suffix", md.encSuffix)
	stores.SetNative(l, Kind, "unencrypted-regex", md.unencRegex)
	stores.SetNative(l, Kind, "encrypted-regex", md.encRegex)
	return l
}

func version(fi fs.FileInfo) string {
	return fmt.Sprintf("%d-%d", fi.ModTime().UnixNano(), fi.Size())
}

// readFile opens p under the root and reads it whole. The caller wipes the
// returned buffer (a SOPS file can hold unencrypted leaves).
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
	tooBig := a.err(op, ref, stores.ErrPermission, "file larger than max-size", nil)
	if fi.Size() > a.cfg.MaxSize {
		return nil, nil, tooBig
	}
	buf := make([]byte, 0, fi.Size()+1)
	for {
		if len(buf) == cap(buf) {
			if int64(len(buf)) > a.cfg.MaxSize {
				secret.WipeBytes(buf)
				return nil, nil, tooBig
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
		return nil, nil, tooBig
	}
	return buf, fi, nil
}

// load reads and parses the file a reference names, without decrypting.
func (a *Adapter) load(op stores.Op, ref stores.Ref) (string, *node, *metadata, fs.FileInfo, error) {
	if a.isClosed() {
		return "", nil, nil, nil, a.err(op, ref, stores.ErrUnavailable, "closed", nil)
	}
	if ref.Selectors != "" {
		return "", nil, nil, nil, a.err(op, ref, stores.ErrInvalidRef, "the sops source has no version selectors", nil)
	}
	p, ok := clean(ref.Path)
	if !ok || p == "." {
		return "", nil, nil, nil, a.err(op, ref, stores.ErrInvalidRef, "path must be relative to the store root without .. segments", nil)
	}
	buf, fi, err := a.readFile(op, ref, p)
	if err != nil {
		return "", nil, nil, nil, err
	}
	data, meta, err := parseDoc(a.format(p), buf)
	secret.WipeBytes(buf)
	if err != nil {
		return "", nil, nil, nil, a.classifyDoc(op, ref, err)
	}
	md, err := parseMetadata(meta)
	if err != nil {
		return "", nil, nil, nil, a.classifyDoc(op, ref, err)
	}
	return p, data, &md, fi, nil
}

// Read implements stores.Adapter: it decrypts the file, verifies its MAC
// and returns its fields, or only ref.Field.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	p, data, md, fi, err := a.load(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	ids, err := a.identities(ctx, stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	key, err := dataKey(md, ids)
	if err != nil {
		return stores.Secret{}, a.classifyDoc(stores.OpRead, ref, err)
	}
	fields, err := decrypt(data, md, key, ref.Field)
	secret.WipeBytes(key)
	if err != nil {
		return stores.Secret{}, a.classifyDoc(stores.OpRead, ref, err)
	}
	if ref.Field != "" {
		if _, ok := fields[ref.Field]; !ok {
			for _, v := range fields {
				v.Wipe()
			}
			return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "no such field", nil)
		}
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
			Labels:    a.labels(p, md),
		},
		Fields: fields,
	}, nil
}

// ReadMetadata implements stores.MetadataReader: field names and labels
// from the plaintext sops metadata and keys, nothing decrypted.
func (a *Adapter) ReadMetadata(_ context.Context, ref stores.Ref) (stores.Metadata, error) {
	p, data, md, fi, err := a.load(stores.OpRead, ref.Secret())
	if err != nil {
		return stores.Metadata{}, err
	}
	names := fieldNames(data, md)
	slices.Sort(names)
	return stores.Metadata{
		Ref:       ref.Secret(),
		Fields:    names,
		Version:   version(fi),
		UpdatedAt: fi.ModTime().UTC(),
		Labels:    a.labels(p, md),
	}, nil
}

type entry struct {
	path string
	fi   fs.FileInfo
}

// skipName is sops' own configuration file, which commonly sits next to
// the files it describes and is not encrypted.
func skipName(p string) bool {
	base := p[strings.LastIndexByte(p, '/')+1:]
	return base == ".sops.yaml" || base == ".sops.yml"
}

// walk lists regular files under prefix (a file or directory), following
// symlinks only where they stay inside the root.
func (a *Adapter) walk(prefix string) ([]entry, error) {
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
	err = fs.WalkDir(a.root.FS(), prefix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || skipName(p) {
			return nil
		}
		fi, err := a.root.Stat(p)
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

// prefixPath turns a List or Watch prefix into a scope, as the file source
// does: `dir` and `dir/*` cover the folder, a trailing `*` after part of a
// name is a glob over paths under the root.
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

// List implements stores.Adapter. It reads each file's plaintext metadata
// for labels and field names; files that parse but carry no sops metadata
// are not SOPS files and are left out, while files that do not parse are
// listed with the base labels so reading them reports the error.
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
		ref := stores.Ref{Scheme: prefix.Scheme, Path: e.path}
		m := stores.Metadata{Ref: ref, Version: version(e.fi), UpdatedAt: e.fi.ModTime().UTC(), Labels: a.baseLabels(e.path)}
		if buf, _, err := a.readFile(stores.OpList, ref, e.path); err == nil {
			data, meta, perr := parseDoc(a.format(e.path), buf)
			secret.WipeBytes(buf)
			if errors.Is(perr, errNoMetadata) {
				continue
			}
			if perr == nil {
				if md, err := parseMetadata(meta); err == nil {
					m.Labels = a.labels(e.path, &md)
					m.Fields = fieldNames(data, &md)
					slices.Sort(m.Fields)
				}
			}
		}
		out = append(out, m)
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

// Watch implements stores.Adapter by polling, as the file source does. The
// baseline is taken before Watch returns; a failed poll reports nothing
// and keeps the previous baseline.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	sc, err := a.prefixPath(stores.OpWatch, prefix)
	if err != nil {
		return nil, err
	}
	prev, err := a.snapshot(sc)
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
			cur, err := a.snapshot(sc)
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
// directory and the age identity must resolve and parse.
func (a *Adapter) Health(ctx context.Context) error {
	if a.isClosed() {
		return a.err(stores.OpHealth, stores.Ref{}, stores.ErrUnavailable, "closed", nil)
	}
	f, err := a.root.Open(".")
	if err != nil {
		return a.err(stores.OpHealth, stores.Ref{}, stores.ErrUnavailable, "store root not readable", err)
	}
	_ = f.Close()
	_, err = a.identities(ctx, stores.OpHealth, stores.Ref{})
	return err
}

// Close implements stores.Adapter. Watches end on their next poll. The age
// secret keys are wiped and the parsed identities dropped.
func (a *Adapter) Close() error {
	var err error
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		a.idMu.Lock()
		for _, k := range a.keys {
			k.Wipe()
		}
		a.keys, a.ids = nil, nil
		a.idMu.Unlock()
		err = a.root.Close()
	})
	return err
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
)
