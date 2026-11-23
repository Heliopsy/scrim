// SPDX-License-Identifier: AGPL-3.0-only

// Package openbao is the store adapter for OpenBao and Vault-compatible KV
// version 2 secrets engines (specs/secret-stores, "OpenBao adapter").
//
// References name the mount and the secret path, and optionally one field
// and a version:
//
//	bao://kv/agents/github#token
//	bao://kv/agents/github?version=3#token
//
// The adapter authenticates with a token, an AppRole role and secret ID, or
// the pod's Kubernetes service account token, renewing login tokens before
// they expire (package vaultapi, shared with the vault adapter). It reads,
// lists and writes KV v2 secrets, and watches a prefix by polling its
// version metadata (one LIST of detailed-metadata per folder per interval on
// OpenBao, falling back to per-secret metadata reads on Vault). Paths listed
// in write-only-paths are written but never read back: scrim keeps only the
// value it wrote, and a policy without read on those paths is enough.
//
// Values never pass through Go strings on the way in or out: responses are
// decoded with package wire into secret.Value and request bodies are wiped
// after sending. The one exception is the token header, which net/http only
// accepts as a string; it lives for the duration of a request.
//
// The client is a small typed client over net/http rather than the
// openbao/api module, which decodes secret data into map[string]any of Go
// strings and so cannot keep values out of immutable memory.
package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
const Kind = "openbao"

// Caps is what the adapter supports.
const Caps = stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite

func init() {
	stores.DeclareMulti(Kind, multiAttrs...)
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		return New(inst)
	})
}

var _ stores.MetadataReader = (*Adapter)(nil)

// Adapter is one OpenBao instance.
type Adapter struct {
	c    *client
	opts Options
	// legacyWarned holds the legacy paths already warned about.
	legacyWarned sync.Map
	// detailed is false once the server has refused detailed-metadata
	// (Vault), so List stops trying it.
	detailed atomicBool
	jitter   func(time.Duration) time.Duration
	// agents caches the logins of agents' own identities (agent.go).
	agents *vaultapi.AgentLogins
	// mounts caches mount information for labels (labels.go).
	mounts vaultapi.MountCache
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
	a := &Adapter{c: c, opts: opts, jitter: defaultJitter, agents: vaultapi.NewAgentLogins()}
	a.detailed.Store(true)
	return a, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.c.Name() }

// Capabilities implements stores.Adapter.
func (a *Adapter) Capabilities() stores.Capabilities { return Caps }

// Credentials implements stores.CredentialHolder.
func (a *Adapter) Credentials() []secret.Value { return a.c.Credentials() }

// Close implements stores.Adapter.
func (a *Adapter) Close() error {
	a.agents.Close()
	a.c.Close()
	return nil
}

// split separates a reference path into its mount and the path inside it.
func (a *Adapter) split(p string) (mount, rest string) {
	best := ""
	for _, m := range a.opts.Mounts {
		if (p == m || strings.HasPrefix(p, m+"/")) && len(m) > len(best) {
			best = m
		}
	}
	if best == "" {
		best, _, _ = strings.Cut(p, "/")
	}
	return best, strings.TrimPrefix(strings.TrimPrefix(p, best), "/")
}

// writeOnly reports whether p is under a configured write-only prefix.
func (a *Adapter) writeOnly(p string) bool {
	for _, w := range a.opts.WriteOnly {
		if p == w || strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string) *stores.Error {
	e := stores.NewError(a.c.Name(), op, ref, kind, nil)
	e.Detail = detail
	return e
}

// versionSelector returns the `version` selector, refusing any other.
func (a *Adapter) versionSelector(op stores.Op, ref stores.Ref) (int, error) {
	if ref.Selectors == "" {
		return 0, nil
	}
	q, _ := url.ParseQuery(ref.Selectors)
	for k := range q {
		if k != "version" {
			return 0, a.err(op, ref, stores.ErrInvalidRef, fmt.Sprintf("unknown selector %q (OpenBao supports version)", k))
		}
	}
	n, err := strconv.Atoi(q.Get("version"))
	if err != nil || n <= 0 {
		return 0, a.err(op, ref, stores.ErrInvalidRef, "version must be a positive integer")
	}
	return n, nil
}

type versionMeta struct {
	CreatedTime    string            `json:"created_time"`
	CustomMetadata map[string]string `json:"custom_metadata"`
	DeletionTime   string            `json:"deletion_time"`
	Destroyed      bool              `json:"destroyed"`
	Version        int               `json:"version"`
}

type readResponse struct {
	Data *struct {
		Data     map[string]wire.Raw `json:"data"`
		Metadata versionMeta         `json:"metadata"`
	} `json:"data"`
}

func wipeRaw(m map[string]wire.Raw) {
	for _, r := range m {
		r.Wipe()
	}
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if a.writeOnly(ref.Path) {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrPermission,
			"write-only path: scrim does not read it back from the store")
	}
	version, err := a.versionSelector(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	mount, rest := a.split(ref.Path)
	if rest == "" {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	var q url.Values
	if version > 0 {
		q = url.Values{"version": {strconv.Itoa(version)}}
	}
	resp, at, err := a.get(ctx, request{Op: stores.OpRead, Ref: ref, Query: q}, mount, "data", rest)
	defer resp.Wipe()
	if err != nil {
		return stores.Secret{}, err
	}
	var rr readResponse
	if err := json.Unmarshal(resp.Body, &rr); err != nil {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "malformed response")
	}
	if rr.Data == nil || rr.Data.Data == nil {
		// Deleted or destroyed versions come back without data.
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	defer wipeRaw(rr.Data.Data)
	md := rr.Data.Metadata
	// A deletion time still to come was scheduled by delete_version_after;
	// the version is readable until then.
	if (md.DeletionTime != "" && !a.future(md.DeletionTime)) || md.Destroyed {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	destroyed := md.Destroyed
	in := labelInput{
		Mount: mount, Path: rest, Version: md.Version, Custom: md.CustomMetadata,
		VersionCreated: md.CreatedTime, Deletion: md.DeletionTime, Destroyed: &destroyed,
	}
	var createdAt time.Time
	if a.opts.LabelLookups {
		if m, err := a.optionalMetadata(ctx, ref, mount, at); err == nil {
			in.Meta = &m
			createdAt = parseTime(m.CreatedTime)
		}
		in.MountInfo = a.mount(ctx, ref, mount)
	}
	out := stores.Secret{
		Meta: stores.Metadata{
			Ref:       ref.Secret(),
			Version:   strconv.Itoa(md.Version),
			CreatedAt: createdAt,
			UpdatedAt: parseTime(md.CreatedTime),
			Labels:    a.labels(in),
		},
		Fields: map[string]secret.Value{},
	}
	for name := range rr.Data.Data {
		out.Meta.Fields = append(out.Meta.Fields, name)
	}
	sort.Strings(out.Meta.Fields)
	for name, raw := range rr.Data.Data {
		if ref.Field != "" && name != ref.Field {
			continue
		}
		v, err := raw.Value()
		if err != nil {
			out.Wipe()
			return stores.Secret{}, a.err(stores.OpRead, ref.WithField(name), stores.ErrInvalidRef, "field is not a usable value: "+err.Error())
		}
		out.Fields[name] = v
	}
	if ref.Field != "" && len(out.Fields) == 0 {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "no such field")
	}
	return out, nil
}

// get sends a GET for the data or metadata (kind) of the secret rest under
// mount, and returns where it was found: rest, or its legacy name.
//
// Releases up to 0.4 escaped secret paths twice, so OpenBao stored a secret
// written as "kv/git hub" under the name "git%20hub". When the store has no
// secret at rest and its legacy name differs, get asks for the legacy name
// and, if that exists, uses it and warns once per path so the operator moves
// it. A secret that exists at rest, even with its current version deleted,
// is never shadowed by a legacy one.
func (a *Adapter) get(ctx context.Context, r request, mount, kind, rest string) (resp *response, at string, err error) {
	r.Method = http.MethodGet
	r.Path = escapePath(mount) + "/" + kind + "/" + escapePath(rest)
	resp, err = a.c.Do(ctx, r)
	legacy := escapePath(rest)
	if !errorsIsNotFound(err) || legacy == rest || !noSecret(resp) {
		return resp, rest, err
	}
	r.Path = escapePath(mount) + "/" + kind + "/" + escapePath(legacy)
	lresp, lerr := a.c.Do(ctx, r)
	if lerr != nil {
		lresp.Wipe()
		return resp, rest, err
	}
	resp.Wipe()
	if _, warned := a.legacyWarned.LoadOrStore(mount+"/"+legacy, true); !warned {
		a.c.Log.Warn("OpenBao secret found only under its legacy double-escaped name; "+
			"move it to the reference's name, the legacy lookup will be removed",
			"store", a.c.Name(), "path", mount+"/"+rest, "legacy_path", mount+"/"+legacy)
	}
	return lresp, legacy, nil
}

// noSecret reports whether a 404 response says nothing exists at the path
// (no data object), as opposed to a secret whose version is deleted.
func noSecret(resp *response) bool {
	if resp == nil {
		return true
	}
	var b struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(resp.Body, &b)
	return len(b.Data) == 0 || string(b.Data) == "null"
}

// ReadMetadata implements stores.MetadataReader. It returns what Read
// would report about the secret, labels included, from its KV metadata
// alone (GET metadata/), so policy can label an existing secret without its
// value being read. Fields stays empty: KV v2 metadata does not name them.
//
// It refuses write-only paths, as Read does. When the store refuses the
// metadata read (a policy with read on data/ only), it falls back to Read
// and wipes the values, which is what stores.Set.Metadata does for an
// adapter without this method; every other error is returned as is.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	ref = ref.Secret()
	if a.writeOnly(ref.Path) {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrPermission,
			"write-only path: scrim does not read it back from the store")
	}
	version, err := a.versionSelector(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	mount, rest := a.split(ref.Path)
	if rest == "" {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	resp, _, err := a.get(ctx, request{Op: stores.OpRead, Ref: ref}, mount, "metadata", rest)
	defer resp.Wipe()
	if errors.Is(err, stores.ErrPermission) {
		s, rerr := a.Read(ctx, ref)
		s.Wipe()
		if rerr != nil {
			return stores.Metadata{}, rerr
		}
		return s.Meta, nil
	}
	if err != nil {
		return stores.Metadata{}, err
	}
	var mr struct {
		Data *secretMeta `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &mr); err != nil || mr.Data == nil {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "malformed response")
	}
	m := *mr.Data
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
	in := labelInput{
		Mount: mount, Path: rest, Version: version, Custom: m.CustomMetadata,
		VersionCreated: v.CreatedTime, Deletion: v.DeletionTime, Destroyed: &destroyed,
	}
	var createdAt time.Time
	if a.opts.LabelLookups {
		// Read gets these from optional lookups; here the metadata is at
		// hand already.
		in.Meta = &m
		createdAt = parseTime(m.CreatedTime)
		in.MountInfo = a.mount(ctx, ref, mount)
	}
	return stores.Metadata{
		Ref:       ref,
		Version:   strconv.Itoa(version),
		CreatedAt: createdAt,
		UpdatedAt: parseTime(v.CreatedTime),
		Labels:    a.labels(in),
	}, nil
}

// live reports whether the current version can be read.
func (a *Adapter) live(m secretMeta) bool {
	if m.CurrentVersion == 0 {
		return false
	}
	v, ok := m.Versions[strconv.Itoa(m.CurrentVersion)]
	return !ok || ((v.DeletionTime == "" || a.future(v.DeletionTime)) && !v.Destroyed)
}

func (a *Adapter) metadata(ref stores.Ref, mount, p string, m secretMeta, mi *mountInfo) stores.Metadata {
	return stores.Metadata{
		Ref:       ref,
		Version:   strconv.Itoa(m.CurrentVersion),
		CreatedAt: parseTime(m.CreatedTime),
		UpdatedAt: parseTime(m.UpdatedTime),
		Labels:    a.labels(labelInput{Mount: mount, Path: p, Meta: &m, MountInfo: mi}),
		WriteOnly: a.writeOnly(ref.Path),
	}
}

type listResponse struct {
	Data struct {
		Keys    []string              `json:"keys"`
		KeyInfo map[string]secretMeta `json:"key_info"`
	} `json:"data"`
}

// List implements stores.Adapter. The prefix is a folder; every live secret
// below it is returned, recursively.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	prefix = prefix.Secret()
	prefix.Path = strings.TrimSuffix(strings.TrimSuffix(prefix.Path, "*"), "/")
	if prefix.Selectors != "" {
		return nil, a.err(stores.OpList, prefix, stores.ErrInvalidRef, "selectors do not apply to a list")
	}
	mount, rest := a.split(prefix.Path)
	var out []stores.Metadata
	if err := a.listFolder(ctx, prefix, mount, rest, &out, 0); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref.Path < out[j].Ref.Path })
	return out, nil
}

// maxDepth bounds recursion against a pathological tree.
const maxDepth = 32

func (a *Adapter) listFolder(ctx context.Context, prefix stores.Ref, mount, folder string, out *[]stores.Metadata, depth int) error {
	if depth > maxDepth {
		return a.err(stores.OpList, prefix, stores.ErrInvalidRef, "folders nested too deeply")
	}
	if err := ctx.Err(); err != nil {
		return stores.NewError(a.c.Name(), stores.OpList, prefix, stores.ErrUnavailable, err)
	}
	keys, info, err := a.listKeys(ctx, prefix, mount, folder)
	if err != nil {
		return err
	}
	for _, k := range keys {
		child := strings.TrimSuffix(k, "/")
		if folder != "" {
			child = folder + "/" + child
		}
		if strings.HasSuffix(k, "/") {
			if err := a.listFolder(ctx, prefix, mount, child, out, depth+1); err != nil {
				return err
			}
			continue
		}
		ref := stores.Ref{Scheme: prefix.Scheme, Path: mount + "/" + child}
		m, ok := info[k]
		if !ok {
			if m, err = a.readMetadata(ctx, ref, mount, child); err != nil {
				if errorsIsNotFound(err) {
					continue
				}
				return err
			}
		}
		if a.live(m) {
			*out = append(*out, a.metadata(ref, mount, child, m, a.mount(ctx, prefix, mount)))
		}
	}
	return nil
}

// listKeys lists one folder. It uses OpenBao's detailed-metadata, which
// returns every key's metadata in one request, and falls back to plain
// metadata listing on servers without it.
func (a *Adapter) listKeys(ctx context.Context, prefix stores.Ref, mount, folder string) ([]string, map[string]secretMeta, error) {
	p := escapePath(folder)
	if p != "" {
		p += "/"
	}
	try := func(kind string) (*response, error) {
		return a.c.Do(ctx, request{
			Op: stores.OpList, Ref: prefix, Method: "LIST",
			Path: escapePath(mount) + "/" + kind + "/" + p,
		})
	}
	if a.detailed.Load() {
		resp, err := try("detailed-metadata")
		if err == nil || errorsIsNotFound(err) {
			defer resp.Wipe()
			if err != nil {
				return nil, nil, nil
			}
			var lr listResponse
			if err := json.Unmarshal(resp.Body, &lr); err != nil {
				return nil, nil, a.err(stores.OpList, prefix, stores.ErrUnavailable, "malformed response")
			}
			if lr.Data.KeyInfo == nil {
				lr.Data.KeyInfo = map[string]secretMeta{}
			}
			return lr.Data.Keys, lr.Data.KeyInfo, nil
		}
		// Vault has no detailed-metadata (invalid path), and a policy may
		// grant only metadata/ (permission denied): list metadata/ from now on.
		if !errorsIsInvalid(err) && !errors.Is(err, stores.ErrPermission) {
			return nil, nil, err
		}
		a.detailed.Store(false)
	}
	resp, err := try("metadata")
	defer resp.Wipe()
	if errorsIsNotFound(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var lr listResponse
	if err := json.Unmarshal(resp.Body, &lr); err != nil {
		return nil, nil, a.err(stores.OpList, prefix, stores.ErrUnavailable, "malformed response")
	}
	return lr.Data.Keys, map[string]secretMeta{}, nil
}

func (a *Adapter) readMetadata(ctx context.Context, ref stores.Ref, mount, p string) (secretMeta, error) {
	return a.getMetadata(ctx, ref, mount, p, false)
}

// optionalMetadata reads a secret's metadata for its labels on Read. A
// refusal is returned without logging in again; the caller ignores errors.
func (a *Adapter) optionalMetadata(ctx context.Context, ref stores.Ref, mount, p string) (secretMeta, error) {
	return a.getMetadata(ctx, ref, mount, p, true)
}

func (a *Adapter) getMetadata(ctx context.Context, ref stores.Ref, mount, p string, optional bool) (secretMeta, error) {
	resp, err := a.c.Do(ctx, request{
		Op: stores.OpList, Ref: ref, Method: http.MethodGet,
		Path:     escapePath(mount) + "/metadata/" + escapePath(p),
		Optional: optional,
	})
	defer resp.Wipe()
	if err != nil {
		return secretMeta{}, err
	}
	var mr struct {
		Data secretMeta `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &mr); err != nil {
		return secretMeta{}, a.err(stores.OpList, ref, stores.ErrUnavailable, "malformed response")
	}
	return mr.Data, nil
}

type writeResponse struct {
	Data *struct {
		CreatedTime string `json:"created_time"`
		Version     int    `json:"version"`
	} `json:"data"`
}

// Write implements stores.Adapter. It needs only create (new secret) or
// update (new version) on the data path, never read. Labels are written
// to the secret's custom metadata, which needs update on the metadata path.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if ref.Selectors != "" {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "selectors do not apply to a write")
	}
	if len(fields) == 0 {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "nothing to write")
	}
	mount, rest := a.split(ref.Path)
	if rest == "" {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	names := make([]string, 0, len(fields))
	involved := make([]secret.Value, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	buf := []byte(`{`)
	if opts.CreateOnly {
		buf = append(buf, `"options":{"cas":0},`...)
	}
	buf = append(buf, `"data":{`...)
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
			return stores.Metadata{}, a.err(stores.OpWrite, ref.WithField(n), stores.ErrInvalidRef, "value is not valid UTF-8 text")
		}
		involved = append(involved, fields[n])
	}
	body := wire.NewBody(append(buf, '}', '}'))
	defer body.Wipe()
	resp, err := a.c.Do(ctx, request{
		Op: stores.OpWrite, Ref: ref, Method: http.MethodPost,
		Path: escapePath(mount) + "/data/" + escapePath(rest),
		Body: body, Involved: involved,
	})
	defer resp.Wipe()
	if err != nil {
		return stores.Metadata{}, err
	}
	var wr writeResponse
	if err := json.Unmarshal(resp.Body, &wr); err != nil || wr.Data == nil {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrUnavailable, "write accepted but the response was malformed")
	}
	m := stores.Metadata{
		Ref:       ref,
		Fields:    names,
		Version:   strconv.Itoa(wr.Data.Version),
		UpdatedAt: parseTime(wr.Data.CreatedTime),
		WriteOnly: a.writeOnly(ref.Path),
	}
	if wr.Data.Version == 1 {
		m.CreatedAt = m.UpdatedAt
	}
	// Labels describe what is known without another request: the custom
	// metadata only once it is stored.
	in := labelInput{
		Mount: mount, Path: rest, Version: wr.Data.Version,
		VersionCreated: wr.Data.CreatedTime, MountInfo: a.cachedMount(mount),
	}
	if len(opts.Labels) > 0 {
		if err := a.writeLabels(ctx, ref, mount, rest, opts.Labels); err != nil {
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

func (a *Adapter) writeLabels(ctx context.Context, ref stores.Ref, mount, rest string, labels map[string]string) error {
	b, err := json.Marshal(map[string]any{"custom_metadata": labels})
	if err != nil {
		return a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "labels cannot be encoded")
	}
	resp, err := a.c.Do(ctx, request{
		Op: stores.OpWrite, Ref: ref, Method: http.MethodPost,
		Path: escapePath(mount) + "/metadata/" + escapePath(rest),
		Body: wire.NewBody(b),
	})
	resp.Wipe()
	return err
}

// Health implements stores.Adapter: the server is initialised and unsealed,
// and scrim's token is accepted.
func (a *Adapter) Health(ctx context.Context) error {
	resp, err := a.c.Do(ctx, request{
		Op: stores.OpHealth, Method: http.MethodGet, NoAuth: true, Path: "sys/health",
		Query: url.Values{"standbyok": {"true"}, "perfstandbyok": {"true"}},
	})
	resp.Wipe()
	if err != nil {
		// sys/health answers 501 when uninitialised and 503 when sealed,
		// both classified as unavailable. A 404 or 400 means the address
		// is not an OpenBao API at all, which is an outage too.
		if se, ok := err.(*stores.Error); ok && (se.Kind == stores.ErrNotFound || se.Kind == stores.ErrInvalidRef) {
			se.Kind = stores.ErrUnavailable
			se.Detail = "no OpenBao API at the configured address"
		}
		return err
	}
	resp, err = a.c.Do(ctx, request{Op: stores.OpHealth, Method: http.MethodGet, Path: "auth/token/lookup-self"})
	resp.Wipe()
	return err
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
