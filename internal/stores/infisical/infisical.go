// SPDX-License-Identifier: AGPL-3.0-only

// Package infisical is the store adapter for Infisical (specs/secret-stores,
// "Infisical adapter"), addressed as
//
//	<scheme>://<project>/<environment>/<folder>/.../<KEY>[?version=<n>][#value]
//
// where <project> is a project slug or ID. Infisical secrets hold one value,
// exposed as the field "value". scrim authenticates with a Universal Auth
// machine identity; Kubernetes Auth arrives with task 12.4.
//
// The adapter talks to the Infisical REST API with a small typed client
// instead of the official Go SDK: the SDK hands secret values around as Go
// strings, which cannot be wiped, and pulls in a large dependency tree for
// the handful of endpoints scrim needs. Values travel between the HTTP body
// and secret.Value through package wire and are never converted to strings.
// The access token is the one exception: net/http takes the Authorization
// header as a string, built for each request and dropped after it.
//
// Write-only behaviour toward agents is enforced by scrim, not by Infisical,
// so it works with the built-in roles of the free self-hosted edition.
package infisical

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Kind is the adapter kind this package registers.
const Kind = "infisical"

// Field is the name of the single field an Infisical secret holds.
const Field = "value"

func init() {
	stores.Register(Kind, New)
}

// Adapter is one configured Infisical instance.
type Adapter struct {
	name string
	s    *settings
	c    *client
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
)

// New builds an adapter from its configuration. It validates the options and
// does not resolve credentials or contact Infisical.
func New(ctx context.Context, inst stores.Instance) (stores.Adapter, error) {
	s, err := decodeSettings(ctx, inst)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	c, err := newClient(s)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	return &Adapter{name: inst.Name, s: s, c: c}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter.
func (a *Adapter) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite
}

// Credentials implements stores.CredentialHolder.
func (a *Adapter) Credentials() []secret.Value { return a.c.credentials() }

// Close implements stores.Adapter.
func (a *Adapter) Close() error {
	a.c.close()
	return nil
}

func (a *Adapter) fail(op stores.Op, ref stores.Ref, err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: ae.kind, Detail: ae.msg, Cause: ae.cause}
	}
	var se *stores.Error
	if errors.As(err, &se) {
		return se
	}
	return stores.NewError(a.name, op, ref, stores.ErrUnavailable, err)
}

func (a *Adapter) invalid(op stores.Op, ref stores.Ref, detail string) error {
	return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrInvalidRef, Detail: detail}
}

// location is a reference split into Infisical's coordinates.
type location struct {
	project string // as written in the reference: slug or ID
	env     string
	folder  string // "/" or "/a/b"
	key     string
}

func splitSecret(path string) (location, bool) {
	seg := strings.Split(path, "/")
	if len(seg) < 3 || slices.Contains(seg, "") {
		return location{}, false
	}
	return location{
		project: seg[0],
		env:     seg[1],
		folder:  "/" + strings.Join(seg[2:len(seg)-1], "/"),
		key:     seg[len(seg)-1],
	}, true
}

func splitPrefix(path string) (location, bool) {
	path = strings.TrimSuffix(strings.TrimSuffix(path, "*"), "/")
	seg := strings.Split(path, "/")
	if len(seg) < 2 || slices.Contains(seg, "") {
		return location{}, false
	}
	return location{project: seg[0], env: seg[1], folder: "/" + strings.Join(seg[2:], "/")}, true
}

// refFor renders the reference of a secret found at folder/key.
func (l location) refFor(scheme, folder, key string) stores.Ref {
	p := l.project + "/" + l.env
	if f := strings.Trim(folder, "/"); f != "" {
		p += "/" + f
	}
	return stores.Ref{Scheme: scheme, Path: p + "/" + key}
}

// apiSecret is a secret as the v4 API returns it. SecretValue is wire.Raw
// so it never becomes a Go string and prints as a marker.
type apiSecret struct {
	SecretKey      string    `json:"secretKey"`
	SecretValue    wire.Raw  `json:"secretValue"`
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	SecretPath     string    `json:"secretPath"`
	SecretMetadata []kv      `json:"secretMetadata"`
}

type kv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (s *apiSecret) meta(ref stores.Ref) stores.Metadata {
	m := stores.Metadata{
		Ref:       ref.Secret(),
		Fields:    []string{Field},
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
	if s.Version > 0 {
		m.Version = strconv.Itoa(s.Version)
	}
	if len(s.SecretMetadata) > 0 {
		m.Labels = make(map[string]string, len(s.SecretMetadata))
		for _, e := range s.SecretMetadata {
			m.Labels[e.Key] = e.Value
		}
	}
	return m
}

func (a *Adapter) baseQuery(ctx context.Context, l location) (url.Values, error) {
	id, err := a.c.projectID(ctx, l.project)
	if err != nil {
		return nil, err
	}
	return url.Values{"projectId": {id}, "environment": {l.env}, "secretPath": {l.folder}}, nil
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	l, ok := splitSecret(ref.Path)
	if !ok {
		return stores.Secret{}, a.invalid(stores.OpRead, ref, "want <project>/<environment>/[<folder>/...]<KEY>")
	}
	var version string
	if ref.Selectors != "" {
		q, _ := url.ParseQuery(ref.Selectors)
		for k := range q {
			if k != "version" {
				return stores.Secret{}, a.invalid(stores.OpRead, ref, "unknown selector "+strconv.Quote(k)+" (supported: version)")
			}
		}
		version = q.Get("version")
		if n, err := strconv.Atoi(version); err != nil || n < 1 {
			return stores.Secret{}, a.invalid(stores.OpRead, ref, "version must be a positive integer")
		}
	}
	if ref.Field != "" && ref.Field != Field {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrNotFound,
			Detail: "Infisical secrets hold a single field named " + Field}
	}
	q, err := a.baseQuery(ctx, l)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	q.Set("type", "shared")
	q.Set("viewSecretValue", "true")
	q.Set("expandSecretReferences", strconv.FormatBool(a.s.expandRefs))
	if version != "" {
		q.Set("version", version)
	}
	b, err := a.c.do(ctx, http.MethodGet, "/api/v4/secrets/"+url.PathEscape(l.key), q, nil, nil)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	defer secret.WipeBytes(b)
	var resp struct {
		Secret apiSecret `json:"secret"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		resp.Secret.SecretValue.Wipe()
		return stores.Secret{}, stores.NewError(a.name, stores.OpRead, ref, stores.ErrUnavailable, errors.New("malformed secret response"))
	}
	defer resp.Secret.SecretValue.Wipe()
	v, err := resp.Secret.SecretValue.Value()
	if err != nil {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrUnavailable, Detail: "secret value missing from the response"}
	}
	return stores.Secret{Meta: resp.Secret.meta(ref), Fields: map[string]secret.Value{Field: v}}, nil
}

// List implements stores.Adapter. It never asks Infisical for values.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	l, ok := splitPrefix(prefix.Path)
	if !ok {
		return nil, a.invalid(stores.OpList, prefix, "want <project>/<environment>[/<folder>...]")
	}
	q, err := a.baseQuery(ctx, l)
	if err != nil {
		return nil, a.fail(stores.OpList, prefix, err)
	}
	q.Set("recursive", "true")
	q.Set("viewSecretValue", "false")
	q.Set("expandSecretReferences", "false")
	q.Set("include_imports", "false")
	b, err := a.c.do(ctx, http.MethodGet, "/api/v4/secrets", q, nil, nil)
	if err != nil {
		if errors.Is(err, stores.ErrNotFound) || isNotFound(err) {
			// The folder does not exist: nothing under the prefix.
			return nil, nil
		}
		return nil, a.fail(stores.OpList, prefix, err)
	}
	defer secret.WipeBytes(b)
	var resp struct {
		Secrets []apiSecret `json:"secrets"`
	}
	err = json.Unmarshal(b, &resp)
	for i := range resp.Secrets {
		resp.Secrets[i].SecretValue.Wipe()
	}
	if err != nil {
		return nil, stores.NewError(a.name, stores.OpList, prefix, stores.ErrUnavailable, errors.New("malformed list response"))
	}
	out := make([]stores.Metadata, 0, len(resp.Secrets))
	for i := range resp.Secrets {
		s := &resp.Secrets[i]
		folder := s.SecretPath
		if folder == "" {
			folder = l.folder
		}
		out = append(out, s.meta(l.refFor(prefix.Scheme, folder, s.SecretKey)))
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out, nil
}

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.kind == stores.ErrNotFound
}

// Write implements stores.Adapter: create, or update when the secret exists
// and CreateOnly is not set. Missing folders are created when
// create-folders is on.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	l, ok := splitSecret(ref.Path)
	if !ok {
		return stores.Metadata{}, a.invalid(stores.OpWrite, ref, "want <project>/<environment>/[<folder>/...]<KEY>")
	}
	v, ok := fields[Field]
	if !ok || len(fields) != 1 {
		names := slices.Sorted(maps.Keys(fields))
		return stores.Metadata{}, &stores.Error{Store: a.name, Op: stores.OpWrite, Ref: ref, Kind: stores.ErrUnsupported,
			Detail: "Infisical secrets hold a single field named " + Field + ", got fields " + strings.Join(names, ",")}
	}
	if !storable(v) {
		return stores.Metadata{}, &stores.Error{Store: a.name, Op: stores.OpWrite, Ref: ref, Kind: stores.ErrUnsupported,
			Detail: "Infisical trims leading and trailing whitespace from values; refusing a value it would change"}
	}
	id, err := a.c.projectID(ctx, l.project)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	involved := []secret.Value{v}

	m, err := a.send(ctx, http.MethodPost, id, l, ref, v, opts.Labels, involved)
	if err != nil && isNotFound(err) && a.s.createFolders && l.folder != "/" {
		if ferr := a.ensureFolders(ctx, id, l); ferr != nil {
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, ferr)
		}
		m, err = a.send(ctx, http.MethodPost, id, l, ref, v, opts.Labels, involved)
	}
	if err != nil && errors.Is(err, stores.ErrConflict) && !opts.CreateOnly {
		m, err = a.send(ctx, http.MethodPatch, id, l, ref, v, opts.Labels, involved)
	}
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	return m, nil
}

func (a *Adapter) send(ctx context.Context, method, projectID string, l location, ref stores.Ref, v secret.Value, labels map[string]string, involved []secret.Value) (stores.Metadata, error) {
	head := map[string]any{
		"projectId":   projectID,
		"environment": l.env,
		"secretPath":  l.folder,
		"type":        "shared",
	}
	if labels != nil {
		md := make([]kv, 0, len(labels))
		for _, k := range slices.Sorted(maps.Keys(labels)) {
			md = append(md, kv{Key: k, Value: labels[k]})
		}
		head["secretMetadata"] = md
	}
	buf, err := wire.AppendJSON(nil, head)
	if err != nil {
		return stores.Metadata{}, &apiError{kind: stores.ErrInvalidRef, msg: "cannot encode request", cause: err}
	}
	buf = append(buf[:len(buf)-1], `,"secretValue":`...)
	buf, err = wire.AppendValue(buf, v)
	if err != nil {
		secret.WipeBytes(buf)
		return stores.Metadata{}, &apiError{kind: stores.ErrUnsupported, msg: "Infisical stores text: the value is not valid UTF-8"}
	}
	buf = append(buf, '}')
	body := wire.NewBody(buf)
	defer body.Wipe()

	b, err := a.c.do(ctx, method, "/api/v4/secrets/"+url.PathEscape(l.key), nil, body, involved)
	if err != nil {
		return stores.Metadata{}, err
	}
	defer secret.WipeBytes(b)
	var resp struct {
		Secret apiSecret `json:"secret"`
	}
	err = json.Unmarshal(b, &resp)
	resp.Secret.SecretValue.Wipe()
	if err != nil {
		return stores.Metadata{}, &apiError{kind: stores.ErrUnavailable, msg: "malformed write response"}
	}
	m := resp.Secret.meta(ref)
	if m.Labels == nil && labels != nil {
		m.Labels = maps.Clone(labels)
	}
	return m, nil
}

// storable reports whether Infisical stores v unchanged. Its API trims
// values like JavaScript's String.prototype.trim, keeping one trailing
// newline if the value ended with one. A value it would change is refused:
// scrim would otherwise redact and inject a value that differs from the
// stored one.
func storable(v secret.Value) bool {
	ok := false
	_ = v.Expose(func(b []byte) error {
		t := bytes.TrimFunc(b, jsSpace)
		if len(b) > 0 && b[len(b)-1] == '\n' {
			ok = len(t)+1 == len(b) && bytes.HasPrefix(b, t)
		} else {
			ok = len(t) == len(b)
		}
		return nil
	})
	return ok
}

// jsSpace approximates the characters JavaScript's trim removes.
func jsSpace(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' }

// ensureFolders creates every folder on the way to l.folder. A folder that
// already exists (created concurrently, or by someone else) is fine.
func (a *Adapter) ensureFolders(ctx context.Context, projectID string, l location) error {
	parent := "/"
	for _, name := range strings.Split(strings.Trim(l.folder, "/"), "/") {
		buf, err := wire.AppendJSON(nil, map[string]string{
			"workspaceId": projectID,
			"projectId":   projectID,
			"environment": l.env,
			"path":        parent,
			"name":        name,
		})
		if err != nil {
			return err
		}
		b, err := a.c.do(ctx, http.MethodPost, "/api/v1/folders", nil, wire.NewBody(buf), nil)
		secret.WipeBytes(b)
		if err != nil && !errors.Is(err, stores.ErrConflict) && !isConflict(err) {
			return err
		}
		parent = strings.TrimSuffix(parent, "/") + "/" + name
	}
	return nil
}

func isConflict(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.kind == stores.ErrConflict
}

// Health implements stores.Adapter: the server answers and the machine
// identity can log in.
func (a *Adapter) Health(ctx context.Context) error {
	if err := a.c.status(ctx); err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	if _, err := a.c.accessToken(ctx); err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}
