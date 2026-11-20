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
// they expire (see auth.go). It reads, lists and writes KV v2 secrets, and
// watches a prefix by polling its version metadata (one LIST of
// detailed-metadata per folder per interval on OpenBao, falling back to
// per-secret metadata reads on Vault). Paths listed
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
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Kind is the adapter kind this package registers.
const Kind = "openbao"

// Caps is what the adapter supports.
const Caps = stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite

func init() {
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		return New(inst)
	})
}

// Adapter is one OpenBao instance.
type Adapter struct {
	c *client
	// detailed is false once the server has refused detailed-metadata
	// (Vault), so List stops trying it.
	detailed atomicBool
	jitter   func(time.Duration) time.Duration
	// agents caches Kubernetes passthrough logins (agent.go).
	agents agentLogins
}

// New builds an adapter for inst without contacting the store.
func New(inst stores.Instance) (*Adapter, error) {
	opts, err := parseOptions(inst.Name, inst.Options)
	if err != nil {
		return nil, err
	}
	if inst.Resolve == nil {
		return nil, fmt.Errorf("store %s: no credential resolver", inst.Name)
	}
	hc, err := newHTTPClient(opts)
	if err != nil {
		return nil, fmt.Errorf("store %s: %w", inst.Name, err)
	}
	a := &Adapter{
		c:      &client{name: inst.Name, opts: opts, http: hc, resolve: inst.Resolve, now: time.Now},
		jitter: defaultJitter,
	}
	a.detailed.Store(true)
	return a, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.c.name }

// Capabilities implements stores.Adapter.
func (a *Adapter) Capabilities() stores.Capabilities { return Caps }

// Credentials implements stores.CredentialHolder.
func (a *Adapter) Credentials() []secret.Value { return a.c.credentials() }

// Close implements stores.Adapter.
func (a *Adapter) Close() error {
	a.agents.close()
	a.c.close()
	return nil
}

// split separates a reference path into its mount and the path inside it.
func (a *Adapter) split(p string) (mount, rest string) {
	best := ""
	for _, m := range a.c.opts.Mounts {
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
	for _, w := range a.c.opts.WriteOnly {
		if p == w || strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string) *stores.Error {
	e := stores.NewError(a.c.name, op, ref, kind, nil)
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
	resp, err := a.c.do(ctx, request{
		op: stores.OpRead, ref: ref, method: http.MethodGet,
		path: escapePath(mount) + "/data/" + escapePath(rest), query: q,
	})
	defer resp.wipe()
	if err != nil {
		return stores.Secret{}, err
	}
	var rr readResponse
	if err := json.Unmarshal(resp.body, &rr); err != nil {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "malformed response")
	}
	if rr.Data == nil || rr.Data.Data == nil {
		// Deleted or destroyed versions come back without data.
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	defer wipeRaw(rr.Data.Data)
	md := rr.Data.Metadata
	if md.DeletionTime != "" || md.Destroyed {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	out := stores.Secret{
		Meta: stores.Metadata{
			Ref:       ref.Secret(),
			Version:   strconv.Itoa(md.Version),
			UpdatedAt: parseTime(md.CreatedTime),
			Labels:    md.CustomMetadata,
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

type secretMeta struct {
	CreatedTime    string            `json:"created_time"`
	UpdatedTime    string            `json:"updated_time"`
	CurrentVersion int               `json:"current_version"`
	CustomMetadata map[string]string `json:"custom_metadata"`
	Versions       map[string]struct {
		DeletionTime string `json:"deletion_time"`
		Destroyed    bool   `json:"destroyed"`
	} `json:"versions"`
}

// live reports whether the current version can be read.
func (m secretMeta) live() bool {
	if m.CurrentVersion == 0 {
		return false
	}
	v, ok := m.Versions[strconv.Itoa(m.CurrentVersion)]
	return !ok || (v.DeletionTime == "" && !v.Destroyed)
}

func (a *Adapter) metadata(ref stores.Ref, m secretMeta) stores.Metadata {
	return stores.Metadata{
		Ref:       ref,
		Version:   strconv.Itoa(m.CurrentVersion),
		CreatedAt: parseTime(m.CreatedTime),
		UpdatedAt: parseTime(m.UpdatedTime),
		Labels:    m.CustomMetadata,
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
		return stores.NewError(a.c.name, stores.OpList, prefix, stores.ErrUnavailable, err)
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
		if m.live() {
			*out = append(*out, a.metadata(ref, m))
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
		return a.c.do(ctx, request{
			op: stores.OpList, ref: prefix, method: "LIST",
			path: escapePath(mount) + "/" + kind + "/" + p,
		})
	}
	if a.detailed.Load() {
		resp, err := try("detailed-metadata")
		if err == nil || errorsIsNotFound(err) {
			defer resp.wipe()
			if err != nil {
				return nil, nil, nil
			}
			var lr listResponse
			if err := json.Unmarshal(resp.body, &lr); err != nil {
				return nil, nil, a.err(stores.OpList, prefix, stores.ErrUnavailable, "malformed response")
			}
			if lr.Data.KeyInfo == nil {
				lr.Data.KeyInfo = map[string]secretMeta{}
			}
			return lr.Data.Keys, lr.Data.KeyInfo, nil
		}
		if !errorsIsInvalid(err) {
			return nil, nil, err
		}
		a.detailed.Store(false)
	}
	resp, err := try("metadata")
	defer resp.wipe()
	if errorsIsNotFound(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var lr listResponse
	if err := json.Unmarshal(resp.body, &lr); err != nil {
		return nil, nil, a.err(stores.OpList, prefix, stores.ErrUnavailable, "malformed response")
	}
	return lr.Data.Keys, map[string]secretMeta{}, nil
}

func (a *Adapter) readMetadata(ctx context.Context, ref stores.Ref, mount, p string) (secretMeta, error) {
	resp, err := a.c.do(ctx, request{
		op: stores.OpList, ref: ref, method: http.MethodGet,
		path: escapePath(mount) + "/metadata/" + escapePath(p),
	})
	defer resp.wipe()
	if err != nil {
		return secretMeta{}, err
	}
	var mr struct {
		Data secretMeta `json:"data"`
	}
	if err := json.Unmarshal(resp.body, &mr); err != nil {
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
	resp, err := a.c.do(ctx, request{
		op: stores.OpWrite, ref: ref, method: http.MethodPost,
		path: escapePath(mount) + "/data/" + escapePath(rest),
		body: body, involved: involved,
	})
	defer resp.wipe()
	if err != nil {
		return stores.Metadata{}, err
	}
	var wr writeResponse
	if err := json.Unmarshal(resp.body, &wr); err != nil || wr.Data == nil {
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
	if len(opts.Labels) > 0 {
		if err := a.writeLabels(ctx, ref, mount, rest, opts.Labels); err != nil {
			if se, ok := err.(*stores.Error); ok {
				se.Detail = strings.TrimSpace(fmt.Sprintf("secret written as version %d but its labels were not: %s", wr.Data.Version, se.Detail))
			}
			return m, err
		}
		m.Labels = opts.Labels
	}
	return m, nil
}

func (a *Adapter) writeLabels(ctx context.Context, ref stores.Ref, mount, rest string, labels map[string]string) error {
	b, err := json.Marshal(map[string]any{"custom_metadata": labels})
	if err != nil {
		return a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "labels cannot be encoded")
	}
	resp, err := a.c.do(ctx, request{
		op: stores.OpWrite, ref: ref, method: http.MethodPost,
		path: escapePath(mount) + "/metadata/" + escapePath(rest),
		body: wire.NewBody(b),
	})
	resp.wipe()
	return err
}

// Health implements stores.Adapter: the server is initialised and unsealed,
// and scrim's token is accepted.
func (a *Adapter) Health(ctx context.Context) error {
	resp, err := a.c.do(ctx, request{
		op: stores.OpHealth, method: http.MethodGet, noAuth: true, path: "sys/health",
		query: url.Values{"standbyok": {"true"}, "perfstandbyok": {"true"}},
	})
	resp.wipe()
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
	resp, err = a.c.do(ctx, request{op: stores.OpHealth, method: http.MethodGet, path: "auth/token/lookup-self"})
	resp.wipe()
	return err
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
