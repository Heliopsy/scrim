// SPDX-License-Identifier: AGPL-3.0-only

// Package vault is the store adapter for HashiCorp Vault (specs/
// secret-stores, "HashiCorp Vault adapter"): KV version 1 and 2 secrets
// engines, Enterprise namespaces, token, AppRole, Kubernetes and JWT auth,
// and dynamic secrets whose leases are renewed while the grant they were
// issued for is active and revoked when it ends.
//
// References name the mount and the path inside it, and optionally one
// field and, on KV v2, a version:
//
//	vault://secret/agents/github#token
//	vault://secret/agents/github?version=3#token
//	vault://legacy/agents/github#token          (a KV v1 mount)
//	vault://database/creds/readonly#password    (dynamic, issued per grant)
//
// The adapter finds each reference's mount, its type and KV version with
// sys/internal/ui/mounts, which Vault answers for any token with a
// capability under the mount, and falls back to the mounts, kv-v1-mounts
// and dynamic-paths options when the lookup is refused.
//
// The HTTP client, authentication and token renewal are shared with the
// openbao adapter (package vaultapi). Values never pass through Go strings:
// responses are decoded with package wire into secret.Value and request
// bodies are wiped after sending, the token header being the one exception
// (see vaultapi).
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/vaultapi"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Kind is the adapter kind this package registers.
const Kind = "vault"

// Caps is what the adapter supports.
const Caps = stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite | stores.CapDynamic

func init() {
	stores.DeclareMulti(Kind, vaultapi.MultiAttrs...)
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		return New(inst)
	})
}

var (
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.WriteLabeler     = (*Adapter)(nil)
	_ stores.DynamicIssuer    = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
)

// Adapter is one Vault instance.
type Adapter struct {
	c    *vaultapi.Client
	opts Options
	// known holds detected mounts by mount path; unknown remembers, by first
	// path segment, lookups that failed.
	knownMu sync.Mutex
	known   map[string]knownMount
	unknown vaultapi.MountCache
	// mounts caches mount information for labels when detection is off.
	mounts vaultapi.MountCache
	jitter func(time.Duration) time.Duration
	leases leaseManager
	// agents caches the logins of agents' own identities (agent.go).
	agents *vaultapi.AgentLogins
	// digestKey keys the digests that detect changes on KV v1 (watch.go).
	digestKey [32]byte
}

type knownMount struct {
	info *vaultapi.MountInfo
	at   time.Time
}

// New builds an adapter for inst without contacting the store.
func New(inst stores.Instance) (*Adapter, error) {
	opts, err := parseOptions(inst.Name, inst.Options)
	if err != nil {
		return nil, err
	}
	c, err := vaultapi.New(inst.Name, opts.Options, inst.Resolve, inst.Log)
	if err != nil {
		return nil, err
	}
	a := &Adapter{c: c, opts: opts, known: map[string]knownMount{}, jitter: defaultJitter, agents: vaultapi.NewAgentLogins()}
	a.leases.init(a)
	newDigestKey(&a.digestKey)
	return a, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.c.Name() }

// Capabilities implements stores.Adapter.
func (a *Adapter) Capabilities() stores.Capabilities { return Caps }

// Credentials implements stores.CredentialHolder.
func (a *Adapter) Credentials() []secret.Value { return a.c.Credentials() }

// Close implements stores.Adapter. With leases.revoke-on-close (the
// default) every held lease is revoked first.
func (a *Adapter) Close() error {
	a.leases.close()
	a.agents.Close()
	a.c.Close()
	return nil
}

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string) *stores.Error {
	e := stores.NewError(a.c.Name(), op, ref, kind, nil)
	e.Detail = detail
	return e
}

// engine is how the adapter talks to a mount.
type engine int

const (
	kv2 engine = iota
	kv1
	dynamic
)

func (e engine) String() string {
	switch e {
	case kv1:
		return "kv-v1"
	case dynamic:
		return "dynamic"
	}
	return "kv-v2"
}

// location is where a reference path lives.
type location struct {
	mount, rest string
	engine      engine
	// info is the detected mount, nil when unknown.
	info *vaultapi.MountInfo
}

func under(p, prefix string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }

// configuredMount is the longest mount in the mounts option p is under.
func (a *Adapter) configuredMount(p string) string {
	best := ""
	for _, m := range append(slices.Clone(a.opts.Mounts), a.opts.KVv1Mounts...) {
		if under(p, m) && len(m) > len(best) {
			best = m
		}
	}
	return best
}

// locate finds the mount of p and how to talk to it.
func (a *Adapter) locate(ctx context.Context, ref stores.Ref, p string) location {
	mount := a.configuredMount(p)
	var info *vaultapi.MountInfo
	if a.opts.MountDetect {
		if info = a.detect(ctx, ref, p); info != nil {
			if mp := info.MountPath(); mp != "" && under(p, mp) && len(mp) >= len(mount) {
				mount = mp
			}
		}
	}
	if mount == "" {
		mount, _, _ = strings.Cut(p, "/")
	}
	loc := location{mount: mount, rest: strings.TrimPrefix(strings.TrimPrefix(p, mount), "/"), info: info}
	switch {
	case slices.ContainsFunc(a.opts.DynamicPaths, func(d string) bool { return under(p, d) }):
		loc.engine = dynamic
	case slices.Contains(a.opts.KVv1Mounts, mount):
		loc.engine = kv1
	case info != nil && !info.IsKV():
		loc.engine = dynamic
	case info != nil && info.Engine() == "kv-v1":
		loc.engine = kv1
	}
	return loc
}

// detect returns the mount holding p, from the cache or
// sys/internal/ui/mounts/<p>. A failed lookup is remembered per first path
// segment for vaultapi.MountTTL.
func (a *Adapter) detect(ctx context.Context, ref stores.Ref, p string) *vaultapi.MountInfo {
	now := a.c.Now()
	a.knownMu.Lock()
	var best *vaultapi.MountInfo
	for mp, k := range a.known {
		if now.Sub(k.at) < vaultapi.MountTTL && under(p, mp) && (best == nil || len(mp) > len(best.MountPath())) {
			best = k.info
		}
	}
	a.knownMu.Unlock()
	if best != nil {
		return best
	}
	seg, _, _ := strings.Cut(p, "/")
	if _, failed := a.unknown.Get(seg, now); failed {
		return nil
	}
	resp, err := a.c.Do(ctx, vaultapi.Request{
		Op: stores.OpRead, Ref: ref, Method: http.MethodGet, Optional: true,
		Path: "sys/internal/ui/mounts/" + vaultapi.EscapePath(p),
	})
	defer resp.Wipe()
	var mr struct {
		Data *vaultapi.MountInfo `json:"data"`
	}
	if err != nil || json.Unmarshal(resp.Body, &mr) != nil || mr.Data == nil || mr.Data.Type == "" || mr.Data.MountPath() == "" {
		if ctx.Err() == nil {
			a.unknown.Put(seg, nil, now)
		}
		return nil
	}
	a.knownMu.Lock()
	a.known[mr.Data.MountPath()] = knownMount{info: mr.Data, at: now}
	a.knownMu.Unlock()
	return mr.Data
}

// mountInfo is the mount information for labels: the detected mount, or
// with detection off a lookup of the mount (optional, cached).
func (a *Adapter) mountInfo(ctx context.Context, ref stores.Ref, loc location) *vaultapi.MountInfo {
	if loc.info != nil || !a.opts.LabelLookups {
		return loc.info
	}
	return a.c.Mount(ctx, &a.mounts, ref, loc.mount)
}

// cachedMountInfo returns mount information already known, without a
// request.
func (a *Adapter) cachedMountInfo(mount string) *vaultapi.MountInfo {
	a.knownMu.Lock()
	k, ok := a.known[mount]
	a.knownMu.Unlock()
	if ok && a.c.Now().Sub(k.at) < vaultapi.MountTTL {
		return k.info
	}
	info, _ := a.mounts.Get(mount, a.c.Now())
	return info
}

// writeOnly reports whether p is under a configured write-only prefix.
func (a *Adapter) writeOnly(p string) bool {
	return slices.ContainsFunc(a.opts.WriteOnly, func(w string) bool { return under(p, w) })
}

// versionSelector returns the `version` selector, refusing any other.
func (a *Adapter) versionSelector(op stores.Op, ref stores.Ref, loc location) (int, error) {
	if ref.Selectors == "" {
		return 0, nil
	}
	q, _ := url.ParseQuery(ref.Selectors)
	for k := range q {
		if k != "version" {
			return 0, a.err(op, ref, stores.ErrInvalidRef, fmt.Sprintf("unknown selector %q (Vault KV supports version)", k))
		}
	}
	if loc.engine == kv1 {
		return 0, a.err(op, ref, stores.ErrInvalidRef, "KV version 1 keeps no versions; remove the version selector")
	}
	n, err := strconv.Atoi(q.Get("version"))
	if err != nil || n <= 0 {
		return 0, a.err(op, ref, stores.ErrInvalidRef, "version must be a positive integer")
	}
	return n, nil
}

func (a *Adapter) dynamicRefused(op stores.Op, ref stores.Ref) error {
	return a.err(op, ref, stores.ErrUnsupported,
		"dynamic secrets path: credentials here are issued for a grant under a lease, not "+string(op)+" as stored secrets")
}

// kvPath is the API path of a KV secret: <mount>/data/<rest> on v2 (kind
// is data or metadata), <mount>/<rest> on v1.
func kvPath(loc location, kind, rest string) string {
	if loc.engine == kv1 {
		return vaultapi.EscapePath(loc.mount) + "/" + vaultapi.EscapePath(rest)
	}
	return vaultapi.EscapePath(loc.mount) + "/" + kind + "/" + vaultapi.EscapePath(rest)
}

type versionMeta struct {
	CreatedTime    string            `json:"created_time"`
	CustomMetadata map[string]string `json:"custom_metadata"`
	DeletionTime   string            `json:"deletion_time"`
	Destroyed      bool              `json:"destroyed"`
	Version        int               `json:"version"`
}

func wipeRaw(m map[string]wire.Raw) {
	for _, r := range m {
		r.Wipe()
	}
}

func (a *Adapter) future(ts string) bool { return vaultapi.Future(ts, a.c.Now()) }

// labels builds a KV secret's labels.
func (a *Adapter) labels(in vaultapi.KVLabelInput) map[string]string {
	return vaultapi.KVLabels(Kind, a.opts.Namespace, a.c.Now(), in)
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if a.writeOnly(ref.Path) {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrPermission,
			"write-only path: scrim does not read it back from the store")
	}
	loc := a.locate(ctx, ref, ref.Path)
	if loc.engine == dynamic {
		return stores.Secret{}, a.dynamicRefused(stores.OpRead, ref)
	}
	version, err := a.versionSelector(stores.OpRead, ref, loc)
	if err != nil {
		return stores.Secret{}, err
	}
	if loc.rest == "" {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	var q url.Values
	if version > 0 {
		q = url.Values{"version": {strconv.Itoa(version)}}
	}
	resp, err := a.c.Do(ctx, vaultapi.Request{Op: stores.OpRead, Ref: ref, Method: http.MethodGet, Query: q, Path: kvPath(loc, "data", loc.rest)})
	defer resp.Wipe()
	if err != nil {
		return stores.Secret{}, err
	}
	var (
		data map[string]wire.Raw
		meta stores.Metadata
	)
	if loc.engine == kv1 {
		var rr struct {
			Data map[string]wire.Raw `json:"data"`
		}
		if err := json.Unmarshal(resp.Body, &rr); err != nil || rr.Data == nil {
			wipeRaw(rr.Data)
			return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "malformed response")
		}
		data = rr.Data
		meta = stores.Metadata{Ref: ref.Secret(), Labels: a.kv1Labels(ctx, ref, loc, true)}
	} else {
		var rr struct {
			Data *struct {
				Data     map[string]wire.Raw `json:"data"`
				Metadata versionMeta         `json:"metadata"`
			} `json:"data"`
		}
		if err := json.Unmarshal(resp.Body, &rr); err != nil {
			return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "malformed response")
		}
		if rr.Data == nil || rr.Data.Data == nil {
			// Deleted or destroyed versions come back without data.
			return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
		}
		data = rr.Data.Data
		md := rr.Data.Metadata
		// A deletion time still to come was scheduled by
		// delete_version_after; the version is readable until then.
		if (md.DeletionTime != "" && !a.future(md.DeletionTime)) || md.Destroyed {
			wipeRaw(data)
			return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
		}
		destroyed := md.Destroyed
		in := vaultapi.KVLabelInput{
			Mount: loc.mount, Path: loc.rest, Version: md.Version, Custom: md.CustomMetadata,
			VersionCreated: md.CreatedTime, Deletion: md.DeletionTime, Destroyed: &destroyed,
		}
		var createdAt time.Time
		if a.opts.LabelLookups {
			if m, err := a.getMetadata(ctx, ref, loc, loc.rest, true); err == nil {
				in.Meta = &m
				createdAt = vaultapi.ParseTime(m.CreatedTime)
			}
		}
		in.MountInfo = a.mountInfo(ctx, ref, loc)
		meta = stores.Metadata{
			Ref:       ref.Secret(),
			Version:   strconv.Itoa(md.Version),
			CreatedAt: createdAt,
			UpdatedAt: vaultapi.ParseTime(md.CreatedTime),
			Labels:    a.labels(in),
		}
	}
	defer wipeRaw(data)
	return a.secretFrom(stores.OpRead, ref, meta, data)
}

// secretFrom turns decoded fields into a Secret, keeping only ref.Field
// when the reference names one.
func (a *Adapter) secretFrom(op stores.Op, ref stores.Ref, meta stores.Metadata, data map[string]wire.Raw) (stores.Secret, error) {
	out := stores.Secret{Meta: meta, Fields: map[string]secret.Value{}}
	for name := range data {
		out.Meta.Fields = append(out.Meta.Fields, name)
	}
	sort.Strings(out.Meta.Fields)
	for name, raw := range data {
		if ref.Field != "" && name != ref.Field {
			continue
		}
		v, err := raw.Value()
		if err != nil {
			out.Wipe()
			return stores.Secret{}, a.err(op, ref.WithField(name), stores.ErrInvalidRef, "field is not a usable value: "+err.Error())
		}
		out.Fields[name] = v
	}
	if ref.Field != "" && len(out.Fields) == 0 {
		return stores.Secret{}, a.err(op, ref, stores.ErrNotFound, "no such field")
	}
	return out, nil
}

// kv1Labels are the labels of a KV v1 secret: the reference, the
// namespace and the mount. KV v1 keeps no versions or custom metadata.
func (a *Adapter) kv1Labels(ctx context.Context, ref stores.Ref, loc location, lookup bool) map[string]string {
	in := vaultapi.KVLabelInput{Mount: loc.mount, Path: loc.rest, Engine: "kv-v1"}
	if lookup {
		in.MountInfo = a.mountInfo(ctx, ref, loc)
	} else {
		in.MountInfo = a.cachedMountInfo(loc.mount)
	}
	return a.labels(in)
}

// ReadMetadata implements stores.MetadataReader: what Read would report
// about the secret, labels included, without reading its value. On KV v2
// it reads the secret's metadata; on KV v1, which keeps none, it lists the
// secret's folder to see that the name exists. When the store refuses
// that, it falls back to Read and wipes the values.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	ref = ref.Secret()
	if a.writeOnly(ref.Path) {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrPermission,
			"write-only path: scrim does not read it back from the store")
	}
	loc := a.locate(ctx, ref, ref.Path)
	if loc.engine == dynamic {
		return stores.Metadata{}, a.dynamicRefused(stores.OpRead, ref)
	}
	version, err := a.versionSelector(stores.OpRead, ref, loc)
	if err != nil {
		return stores.Metadata{}, err
	}
	if loc.rest == "" {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	fallback := func() (stores.Metadata, error) {
		s, rerr := a.Read(ctx, ref)
		s.Wipe()
		if rerr != nil {
			return stores.Metadata{}, rerr
		}
		s.Meta.Fields = nil
		return s.Meta, nil
	}
	if loc.engine == kv1 {
		folder, name := "", loc.rest
		if i := strings.LastIndexByte(loc.rest, '/'); i >= 0 {
			folder, name = loc.rest[:i], loc.rest[i+1:]
		}
		keys, err := a.listKeys(ctx, stores.OpRead, ref, loc, folder)
		if errors.Is(err, stores.ErrPermission) {
			return fallback()
		}
		if err != nil {
			return stores.Metadata{}, err
		}
		if !slices.Contains(keys, name) {
			return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
		}
		return stores.Metadata{Ref: ref, Labels: a.kv1Labels(ctx, ref, loc, true)}, nil
	}
	m, err := a.getMetadata(ctx, ref, loc, loc.rest, false)
	if errors.Is(err, stores.ErrPermission) {
		return fallback()
	}
	if err != nil {
		return stores.Metadata{}, err
	}
	if version == 0 {
		version = m.CurrentVersion
	}
	v, ok := m.Versions[strconv.Itoa(version)]
	// The same versions Read finds missing: none yet, beyond the current
	// one, pruned, deleted (deletion time passed) or destroyed.
	if version <= 0 || version > m.CurrentVersion || (!ok && m.Versions != nil) ||
		(v.DeletionTime != "" && !a.future(v.DeletionTime)) || v.Destroyed {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	destroyed := v.Destroyed
	in := vaultapi.KVLabelInput{
		Mount: loc.mount, Path: loc.rest, Version: version, Custom: m.CustomMetadata,
		VersionCreated: v.CreatedTime, Deletion: v.DeletionTime, Destroyed: &destroyed,
		MountInfo: a.mountInfo(ctx, ref, loc),
	}
	var createdAt time.Time
	if a.opts.LabelLookups {
		in.Meta = &m
		createdAt = vaultapi.ParseTime(m.CreatedTime)
	}
	return stores.Metadata{
		Ref:       ref,
		Version:   strconv.Itoa(version),
		CreatedAt: createdAt,
		UpdatedAt: vaultapi.ParseTime(v.CreatedTime),
		Labels:    a.labels(in),
	}, nil
}

// getMetadata reads a KV v2 secret's metadata. optional marks a lookup for
// labels whose refusal the caller ignores.
func (a *Adapter) getMetadata(ctx context.Context, ref stores.Ref, loc location, p string, optional bool) (vaultapi.KVMetadata, error) {
	resp, err := a.c.Do(ctx, vaultapi.Request{
		Op: stores.OpRead, Ref: ref, Method: http.MethodGet, Optional: optional,
		Path: kvPath(loc, "metadata", p),
	})
	defer resp.Wipe()
	if err != nil {
		return vaultapi.KVMetadata{}, err
	}
	var mr struct {
		Data *vaultapi.KVMetadata `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &mr); err != nil || mr.Data == nil {
		return vaultapi.KVMetadata{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "malformed response")
	}
	return *mr.Data, nil
}

// live reports whether the current version can be read.
func (a *Adapter) live(m vaultapi.KVMetadata) bool {
	if m.CurrentVersion == 0 {
		return false
	}
	v, ok := m.Versions[strconv.Itoa(m.CurrentVersion)]
	return !ok || ((v.DeletionTime == "" || a.future(v.DeletionTime)) && !v.Destroyed)
}

// List implements stores.Adapter. The prefix is a folder; every live secret
// below it is returned, recursively, with names and metadata only.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	prefix = prefix.Secret()
	prefix.Path = strings.TrimSuffix(strings.TrimSuffix(prefix.Path, "*"), "/")
	if prefix.Selectors != "" {
		return nil, a.err(stores.OpList, prefix, stores.ErrInvalidRef, "selectors do not apply to a list")
	}
	loc := a.locate(ctx, prefix, prefix.Path)
	if loc.engine == dynamic {
		return nil, a.dynamicRefused(stores.OpList, prefix)
	}
	var out []stores.Metadata
	mi := a.mountInfo(ctx, prefix, loc)
	err := a.walk(ctx, prefix, loc, loc.rest, 0, func(p string) error {
		ref := stores.Ref{Scheme: prefix.Scheme, Path: loc.mount + "/" + p}
		if loc.engine == kv1 {
			l := a.labels(vaultapi.KVLabelInput{Mount: loc.mount, Path: p, Engine: "kv-v1", MountInfo: mi})
			out = append(out, stores.Metadata{Ref: ref, Labels: l, WriteOnly: a.writeOnly(ref.Path)})
			return nil
		}
		m, err := a.getMetadata(ctx, ref, loc, p, false)
		if errors.Is(err, stores.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if a.live(m) {
			out = append(out, stores.Metadata{
				Ref:       ref,
				Version:   strconv.Itoa(m.CurrentVersion),
				CreatedAt: vaultapi.ParseTime(m.CreatedTime),
				UpdatedAt: vaultapi.ParseTime(m.UpdatedTime),
				Labels:    a.labels(vaultapi.KVLabelInput{Mount: loc.mount, Path: p, Meta: &m, MountInfo: mi}),
				WriteOnly: a.writeOnly(ref.Path),
			})
		}
		return nil
	})
	if err != nil {
		var se *stores.Error
		if errors.As(err, &se) {
			se.Op, se.Ref = stores.OpList, prefix
		}
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref.Path < out[j].Ref.Path })
	return out, nil
}

// maxDepth bounds recursion against a pathological tree.
const maxDepth = 32

// walk calls fn with the path (inside the mount) of every secret under
// folder, recursively.
func (a *Adapter) walk(ctx context.Context, prefix stores.Ref, loc location, folder string, depth int, fn func(p string) error) error {
	if depth > maxDepth {
		return a.err(stores.OpList, prefix, stores.ErrInvalidRef, "folders nested too deeply")
	}
	if err := ctx.Err(); err != nil {
		return stores.NewError(a.c.Name(), stores.OpList, prefix, stores.ErrUnavailable, err)
	}
	keys, err := a.listKeys(ctx, stores.OpList, prefix, loc, folder)
	if err != nil {
		return err
	}
	for _, k := range keys {
		child := strings.TrimSuffix(k, "/")
		if folder != "" {
			child = folder + "/" + child
		}
		if strings.HasSuffix(k, "/") {
			err = a.walk(ctx, prefix, loc, child, depth+1, fn)
		} else {
			err = fn(child)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// listKeys lists one folder: LIST <mount>/metadata/<folder>/ on v2,
// <mount>/<folder>/ on v1. A folder that does not exist is empty.
func (a *Adapter) listKeys(ctx context.Context, op stores.Op, ref stores.Ref, loc location, folder string) ([]string, error) {
	p := kvPath(loc, "metadata", folder)
	if folder == "" {
		p = strings.TrimSuffix(p, "/")
	}
	resp, err := a.c.Do(ctx, vaultapi.Request{Op: op, Ref: ref, Method: "LIST", Path: p + "/"})
	defer resp.Wipe()
	if errors.Is(err, stores.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lr struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &lr); err != nil {
		return nil, a.err(op, ref, stores.ErrUnavailable, "malformed response")
	}
	return lr.Data.Keys, nil
}

// fieldsBody encodes fields as a JSON object, values written straight from
// their secret.Value.
func (a *Adapter) fieldsBody(ref stores.Ref, buf []byte, fields map[string]secret.Value) ([]byte, []string, []secret.Value, error) {
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	involved := make([]secret.Value, 0, len(fields))
	buf = append(buf, '{')
	for i, n := range names {
		if i > 0 {
			buf = append(buf, ',')
		}
		var err error
		if buf, err = wire.AppendJSON(buf, n); err == nil {
			buf = append(buf, ':')
			buf, err = wire.AppendValue(buf, fields[n])
		}
		if err != nil {
			secret.WipeBytes(buf)
			return nil, nil, nil, a.err(stores.OpWrite, ref.WithField(n), stores.ErrInvalidRef, "value is not valid UTF-8 text")
		}
		involved = append(involved, fields[n])
	}
	return append(buf, '}'), names, involved, nil
}

// Write implements stores.Adapter. On KV v2 it needs only create (new
// secret) or update (new version) on the data path, never read; labels go
// to the secret's custom metadata. KV v1 overwrites the secret in place,
// keeps no labels, and checks a create-only write by listing the folder.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if ref.Selectors != "" {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "selectors do not apply to a write")
	}
	if len(fields) == 0 {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "nothing to write")
	}
	loc := a.locate(ctx, ref, ref.Path)
	if loc.engine == dynamic {
		return stores.Metadata{}, a.dynamicRefused(stores.OpWrite, ref)
	}
	if loc.rest == "" {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	if loc.engine == kv1 {
		return a.writeKV1(ctx, ref, loc, fields, opts)
	}
	buf := []byte(`{`)
	if opts.CreateOnly {
		buf = append(buf, `"options":{"cas":0},`...)
	}
	buf = append(buf, `"data":`...)
	buf, names, involved, err := a.fieldsBody(ref, buf, fields)
	if err != nil {
		return stores.Metadata{}, err
	}
	body := wire.NewBody(append(buf, '}'))
	defer body.Wipe()
	resp, err := a.c.Do(ctx, vaultapi.Request{
		Op: stores.OpWrite, Ref: ref, Method: http.MethodPost,
		Path: kvPath(loc, "data", loc.rest), Body: body, Involved: involved,
	})
	defer resp.Wipe()
	if err != nil {
		return stores.Metadata{}, err
	}
	var wr struct {
		Data *struct {
			CreatedTime string `json:"created_time"`
			Version     int    `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &wr); err != nil || wr.Data == nil {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrUnavailable, "write accepted but the response was malformed")
	}
	m := stores.Metadata{
		Ref:       ref,
		Fields:    names,
		Version:   strconv.Itoa(wr.Data.Version),
		UpdatedAt: vaultapi.ParseTime(wr.Data.CreatedTime),
		WriteOnly: a.writeOnly(ref.Path),
	}
	if wr.Data.Version == 1 {
		m.CreatedAt = m.UpdatedAt
	}
	in := vaultapi.KVLabelInput{
		Mount: loc.mount, Path: loc.rest, Version: wr.Data.Version,
		VersionCreated: wr.Data.CreatedTime, MountInfo: a.cachedMountInfo(loc.mount),
	}
	if len(opts.Labels) > 0 {
		if err := a.writeLabels(ctx, ref, loc, opts.Labels); err != nil {
			if se, ok := err.(*stores.Error); ok {
				se.Detail = strings.TrimSpace(fmt.Sprintf("secret written as version %d but its labels were not: %s", wr.Data.Version, se.Detail))
			}
			m.Labels = a.labels(in)
			return m, err
		}
		in.Custom = opts.Labels
	}
	m.Labels = a.labels(in)
	return m, nil
}

func (a *Adapter) writeLabels(ctx context.Context, ref stores.Ref, loc location, labels map[string]string) error {
	b, err := json.Marshal(map[string]any{"custom_metadata": labels})
	if err != nil {
		return a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "labels cannot be encoded")
	}
	resp, err := a.c.Do(ctx, vaultapi.Request{
		Op: stores.OpWrite, Ref: ref, Method: http.MethodPost,
		Path: kvPath(loc, "metadata", loc.rest), Body: wire.NewBody(b),
	})
	resp.Wipe()
	return err
}

func (a *Adapter) writeKV1(ctx context.Context, ref stores.Ref, loc location, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	if len(opts.Labels) > 0 {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrUnsupported,
			"KV version 1 keeps no custom metadata, so the labels cannot be stored; use a KV version 2 mount")
	}
	if opts.CreateOnly {
		// KV v1 has no check-and-set. Listing the folder tells whether the
		// name exists without reading a value; a writer racing between the
		// list and the write still wins.
		folder, name := "", loc.rest
		if i := strings.LastIndexByte(loc.rest, '/'); i >= 0 {
			folder, name = loc.rest[:i], loc.rest[i+1:]
		}
		keys, err := a.listKeys(ctx, stores.OpWrite, ref, loc, folder)
		if err != nil {
			var se *stores.Error
			if errors.As(err, &se) && errors.Is(err, stores.ErrPermission) {
				se.Detail = strings.TrimSpace("a create-only write on KV version 1 needs list on the folder: " + se.Detail)
			}
			return stores.Metadata{}, err
		}
		if slices.Contains(keys, name) {
			return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrConflict, "secret already exists")
		}
	}
	buf, names, involved, err := a.fieldsBody(ref, nil, fields)
	if err != nil {
		return stores.Metadata{}, err
	}
	body := wire.NewBody(buf)
	defer body.Wipe()
	resp, err := a.c.Do(ctx, vaultapi.Request{
		Op: stores.OpWrite, Ref: ref, Method: http.MethodPost,
		Path: kvPath(loc, "data", loc.rest), Body: body, Involved: involved,
	})
	resp.Wipe()
	if err != nil {
		return stores.Metadata{}, err
	}
	return stores.Metadata{
		Ref: ref, Fields: names, UpdatedAt: a.c.Now(), WriteOnly: a.writeOnly(ref.Path),
		Labels: a.kv1Labels(ctx, ref, loc, false),
	}, nil
}

// WriteLabels implements stores.WriteLabeler: the labels a secret written
// at ref would carry, from the reference and mount information already
// known, without a request.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	p := ref.Secret().Path
	loc := location{mount: a.configuredMount(p)}
	a.knownMu.Lock()
	for mp, k := range a.known {
		if under(p, mp) && len(mp) > len(loc.mount) {
			loc.mount, loc.info = mp, k.info
		}
	}
	a.knownMu.Unlock()
	if loc.mount == "" {
		loc.mount, _, _ = strings.Cut(p, "/")
	}
	loc.rest = strings.TrimPrefix(strings.TrimPrefix(p, loc.mount), "/")
	in := vaultapi.KVLabelInput{Mount: loc.mount, Path: loc.rest, MountInfo: loc.info}
	if in.MountInfo == nil {
		in.MountInfo = a.cachedMountInfo(loc.mount)
	}
	if slices.Contains(a.opts.KVv1Mounts, loc.mount) {
		in.Engine = "kv-v1"
	}
	return a.labels(in)
}

// Health implements stores.Adapter: the server is initialised and unsealed,
// and scrim's token is accepted.
func (a *Adapter) Health(ctx context.Context) error {
	resp, err := a.c.Do(ctx, vaultapi.Request{
		Op: stores.OpHealth, Method: http.MethodGet, NoAuth: true, Path: "sys/health",
		Query: url.Values{"standbyok": {"true"}, "perfstandbyok": {"true"}},
	})
	resp.Wipe()
	if err != nil {
		// sys/health answers 501 when uninitialised and 503 when sealed,
		// both classified as unavailable. A 404 or 400 means the address
		// is not a Vault API at all, which is an outage too.
		if se, ok := err.(*stores.Error); ok && (se.Kind == stores.ErrNotFound || se.Kind == stores.ErrInvalidRef) {
			se.Kind = stores.ErrUnavailable
			se.Detail = "no Vault API at the configured address"
		}
		return err
	}
	resp, err = a.c.Do(ctx, vaultapi.Request{Op: stores.OpHealth, Method: http.MethodGet, Path: "auth/token/lookup-self"})
	resp.Wipe()
	return err
}
