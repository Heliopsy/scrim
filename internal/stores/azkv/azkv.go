// SPDX-License-Identifier: AGPL-3.0-only

// Package azkv is the store adapter for Azure Key Vault secrets
// (specs/secret-stores, "Azure Key Vault adapter"), addressed as
//
//	<scheme>://<path>[?version=<id>][#<field>]
//
// where the path's segments, joined with the path separator ("--" by
// default), are the secret's name in the vault configured by vault-url:
// `kv://agents/github` is the secret `agents--github`.
//
// A secret holds one string. With format raw (the default) it is the single
// field "value"; with format json it is a JSON object whose members are the
// fields, written with content type application/json.
//
// scrim authenticates through azidentity (DefaultAzureCredential, workload
// identity, managed identity, a client secret or certificate) and learns
// the token scope and tenant from the vault's own 401 challenge, as the
// Azure SDK does, refusing a challenge for a resource the vault does not
// belong to. The vault is spoken to over REST with a small client instead
// of the azsecrets SDK, which hands secret values around as Go strings that
// cannot be wiped; values travel between the HTTP body and secret.Value
// through package wire. The access token, and the client secret azidentity
// keeps, are strings: net/http and azidentity take them that way.
package azkv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/flatname"
	"github.com/heliopsy/scrim/internal/stores/internal/poll"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Kind is the adapter kind this package registers.
const Kind = "azkv"

// Field is the single field of a secret in format raw.
const Field = "value"

const (
	jsonContentType = "application/json"
	// maxValue is Key Vault's limit on a secret value, in bytes.
	maxValue = 25 * 1024
	// maxName is Key Vault's limit on a secret name.
	maxName = 127
)

func init() {
	stores.Register(Kind, New)
}

// Adapter is one configured vault.
type Adapter struct {
	name  string
	s     *settings
	c     *client
	names flatname.Mapper
	polls atomic.Uint64
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.WriteLabeler     = (*Adapter)(nil)
)

// New builds an adapter from its configuration. It validates the options and
// neither resolves credentials nor contacts Azure.
func New(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
	s, err := decodeSettings(inst)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	c, err := newClient(s)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	return &Adapter{
		name: inst.Name, s: s, c: c,
		names: flatname.Mapper{Sep: s.sep, MaxLen: maxName, Valid: func(b byte) bool {
			return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-'
		}},
	}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter.
func (a *Adapter) Capabilities() stores.Capabilities {
	c := stores.CapRead | stores.CapList | stores.CapWatch | stores.CapGlob
	if !a.s.readOnly {
		c |= stores.CapWrite
	}
	return c
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

func (a *Adapter) errf(op stores.Op, ref stores.Ref, kind error, detail string) error {
	return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: kind, Detail: detail}
}

func (a *Adapter) writeOnly(p string) bool {
	for _, w := range a.s.writeOnly {
		if p == w || strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

// attributes are a secret version's attributes, times in Unix seconds.
type attributes struct {
	Enabled         *bool  `json:"enabled,omitempty"`
	NotBefore       *int64 `json:"nbf,omitempty"`
	Expires         *int64 `json:"exp,omitempty"`
	Created         *int64 `json:"created,omitempty"`
	Updated         *int64 `json:"updated,omitempty"`
	RecoveryLevel   string `json:"recoveryLevel,omitempty"`
	RecoverableDays *int   `json:"recoverableDays,omitempty"`
}

// props is a secret version without its value, as listings return it.
type props struct {
	ID          string            `json:"id"`
	ContentType *string           `json:"contentType,omitempty"`
	Attributes  attributes        `json:"attributes"`
	Tags        map[string]string `json:"tags,omitempty"`
	Managed     bool              `json:"managed,omitempty"`
}

// bundle is a secret version with its value. Value is wire.Raw so it never
// becomes a Go string and prints as a marker.
type bundle struct {
	props
	Value wire.Raw `json:"value"`
}

// version returns the version ID in the props' ID, "" when the ID names
// the secret only (listings of secrets).
func (p *props) version() string {
	u, err := url.Parse(p.ID)
	if err != nil {
		return ""
	}
	seg := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(seg) == 3 && seg[0] == "secrets" {
		return seg[2]
	}
	return ""
}

// secretName returns the secret name in the props' ID.
func (p *props) secretName() string {
	u, err := url.Parse(p.ID)
	if err != nil {
		return ""
	}
	seg := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(seg) >= 2 && seg[0] == "secrets" {
		return seg[1]
	}
	return ""
}

func unixTime(p *int64) time.Time {
	if p == nil {
		return time.Time{}
	}
	return time.Unix(*p, 0).UTC()
}

func (a *Adapter) meta(ref stores.Ref, name string, p *props, fields []string) stores.Metadata {
	return stores.Metadata{
		Ref:       stores.Ref{Scheme: ref.Scheme, Path: ref.Path},
		Fields:    fields,
		Version:   p.version(),
		CreatedAt: unixTime(p.Attributes.Created),
		UpdatedAt: unixTime(p.Attributes.Updated),
		Labels:    a.labels(name, p),
		WriteOnly: a.writeOnly(ref.Path),
	}
}

// locate maps ref to the secret name and the version its selectors pin.
func (a *Adapter) locate(op stores.Op, ref stores.Ref) (name, version string, err error) {
	name, nerr := a.names.Name(ref.Path)
	if nerr != nil {
		return "", "", a.errf(op, ref, stores.ErrInvalidRef, nerr.Error())
	}
	if ref.Selectors != "" {
		q, _ := url.ParseQuery(ref.Selectors)
		for k := range q {
			if k != "version" {
				return "", "", a.errf(op, ref, stores.ErrInvalidRef, "unknown selector "+strconv.Quote(k)+" (supported: version)")
			}
		}
		version = q.Get("version")
		if !validVersion(version) {
			return "", "", a.errf(op, ref, stores.ErrInvalidRef, "version must be a Key Vault version ID (letters and digits)")
		}
	}
	return name, version, nil
}

func validVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func secretPath(name, version string) string {
	p := "/secrets/" + url.PathEscape(name)
	if version != "" {
		p += "/" + url.PathEscape(version)
	}
	return p
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if a.writeOnly(ref.Path) {
		return stores.Secret{}, a.errf(stores.OpRead, ref, stores.ErrPermission, "the path is configured write-only; scrim never reads it back")
	}
	name, version, err := a.locate(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	if a.s.format == formatRaw && ref.Field != "" && ref.Field != Field {
		return stores.Secret{}, a.errf(stores.OpRead, ref, stores.ErrNotFound, "secrets in format raw hold a single field named "+Field)
	}
	resp, err := a.c.do(ctx, http.MethodGet, a.c.url(secretPath(name, version), nil), nil, nil)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	defer secret.WipeBytes(resp.body)
	var b bundle
	err = json.Unmarshal(resp.body, &b)
	defer b.Value.Wipe()
	if err != nil {
		return stores.Secret{}, stores.NewError(a.name, stores.OpRead, ref, stores.ErrUnavailable, errors.New("malformed secret response"))
	}
	fields, err := a.decodeFields(b.Value)
	if err != nil {
		return stores.Secret{}, a.errf(stores.OpRead, ref, stores.ErrUnsupported, err.Error())
	}
	names := slices.Sorted(maps.Keys(fields))
	if ref.Field != "" {
		v, ok := fields[ref.Field]
		delete(fields, ref.Field)
		for _, o := range fields {
			o.Wipe()
		}
		if !ok {
			return stores.Secret{}, a.errf(stores.OpRead, ref, stores.ErrNotFound, "the secret has no field "+strconv.Quote(ref.Field))
		}
		fields = map[string]secret.Value{ref.Field: v}
	}
	return stores.Secret{Meta: a.meta(ref, name, &b.props, names), Fields: fields}, nil
}

// decodeFields turns a secret's value into fields according to the format.
func (a *Adapter) decodeFields(raw wire.Raw) (map[string]secret.Value, error) {
	v, err := raw.Value()
	if err != nil {
		return nil, errors.New("secret value missing from the response")
	}
	if a.s.format == formatRaw {
		return map[string]secret.Value{Field: v}, nil
	}
	defer v.Wipe()
	var m map[string]wire.Raw
	err = v.Expose(func(b []byte) error { return json.Unmarshal(b, &m) })
	defer func() {
		for _, r := range m {
			r.Wipe()
		}
	}()
	if err != nil || m == nil {
		// json's error can quote the input; it is not kept.
		return nil, errors.New("format is json but the secret value is not a JSON object")
	}
	out := make(map[string]secret.Value, len(m))
	for k, r := range m {
		fv, err := r.Value()
		if err != nil {
			for _, o := range out {
				o.Wipe()
			}
			return nil, errors.New("field " + strconv.Quote(k) + " of the JSON object is null or invalid")
		}
		out[k] = fv
	}
	return out, nil
}

// ReadMetadata implements stores.MetadataReader. It lists the secret's
// versions, which Key Vault returns without values, and takes the pinned
// version or the current one (the most recently created). When two versions
// were created in the same second the current one cannot be told apart, and
// the version is left out of the metadata and labels. A disabled version
// reads as not found, as a read of it does.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	ref = ref.Secret()
	name, version, err := a.locate(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	vs, err := a.versions(ctx, name)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpRead, ref, err)
	}
	var p *props
	ambiguous := false
	if version != "" {
		for i := range vs {
			if strings.EqualFold(vs[i].version(), version) {
				p = &vs[i]
			}
		}
	} else {
		p, ambiguous = current(vs)
	}
	if p == nil {
		return stores.Metadata{}, a.errf(stores.OpRead, ref, stores.ErrNotFound, "no such secret version")
	}
	if p.Attributes.Enabled != nil && !*p.Attributes.Enabled {
		return stores.Metadata{}, a.errf(stores.OpRead, ref, stores.ErrNotFound, "the secret version is disabled")
	}
	q := *p
	if ambiguous {
		q.ID = ""
	}
	var fields []string
	if a.s.format == formatRaw {
		fields = []string{Field}
	}
	m := a.meta(ref, name, &q, fields)
	return m, nil
}

// current picks the most recently created version. ambiguous is set when
// another version shares its creation second.
func current(vs []props) (*props, bool) {
	var best *props
	ambiguous := false
	for i := range vs {
		c := vs[i].Attributes.Created
		if c == nil {
			continue
		}
		switch {
		case best == nil || *c > *best.Attributes.Created:
			best, ambiguous = &vs[i], false
		case *c == *best.Attributes.Created:
			ambiguous = true
		}
	}
	return best, ambiguous
}

// versions lists every version of a secret, without values.
func (a *Adapter) versions(ctx context.Context, name string) ([]props, error) {
	var out []props
	next := a.c.url(secretPath(name, "")+"/versions", url.Values{"maxresults": {"25"}})
	for next != "" {
		page, link, _, err := a.page(ctx, next)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		next = link
	}
	return out, nil
}

// page fetches one page of a listing and checks its nextLink stays on the
// vault, so the token never follows a link elsewhere.
func (a *Adapter) page(ctx context.Context, u string) ([]props, string, time.Time, error) {
	resp, err := a.c.do(ctx, http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	defer secret.WipeBytes(resp.body)
	var body struct {
		Value    []props `json:"value"`
		NextLink *string `json:"nextLink"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil {
		return nil, "", time.Time{}, &apiError{kind: stores.ErrUnavailable, msg: "malformed listing response"}
	}
	next := ""
	if body.NextLink != nil && *body.NextLink != "" {
		nu, err := url.Parse(*body.NextLink)
		if err != nil || nu.Scheme != a.c.base.Scheme || !strings.EqualFold(nu.Host, a.c.base.Host) {
			return nil, "", time.Time{}, &apiError{kind: stores.ErrUnavailable, msg: "the listing's next page points outside the vault"}
		}
		next = nu.String()
	}
	return body.Value, next, resp.date, nil
}

// listing lists every secret in the vault under prefix, with the server's
// time of the first page.
func (a *Adapter) listing(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, map[string]props, time.Time, error) {
	pf := flatname.ParsePrefix(prefix.Path)
	var (
		out   []stores.Metadata
		all   = map[string]props{}
		first time.Time
	)
	next := a.c.url("/secrets", url.Values{"maxresults": {"25"}})
	for next != "" {
		page, link, date, err := a.page(ctx, next)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		if first.IsZero() {
			first = date
		}
		for i := range page {
			p := &page[i]
			name := p.secretName()
			path, ok := a.names.Path(name)
			if !ok || !pf.Match(path) {
				continue
			}
			var fields []string
			if a.s.format == formatRaw {
				fields = []string{Field}
			}
			ref := stores.Ref{Scheme: prefix.Scheme, Path: path}
			out = append(out, a.meta(ref, name, p, fields))
			all[path] = *p
		}
		next = link
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out, all, first, nil
}

// List implements stores.Adapter. It never asks Key Vault for values.
//
// Metadata.Version stays empty: a secrets listing names no version, and
// telling the current version from a versions listing is ambiguous when two
// were created in the same second. The refresher therefore reads every
// listed secret on each full refresh (one request each); Watch detects
// changes from the listing alone.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	out, _, _, err := a.listing(ctx, prefix)
	if err != nil {
		return nil, a.fail(stores.OpList, prefix, err)
	}
	return out, nil
}

// Watch implements stores.Adapter by polling the secrets listing (no
// values) every watch.interval. A secret's fingerprint is its current
// version's update time, enabled flag, content type and tags. Key Vault
// times have one-second resolution, so a version written in the same
// second as the one before would leave the fingerprint unchanged: while a
// secret's update time is within two seconds of the vault's own clock (the
// listing's Date header), each poll gives it a fresh fingerprint, so it is
// reported again until it settles. A spurious change costs one read; a
// missed one would keep a rotated value out of the redaction set until the
// next full refresh.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	return poll.Watch(ctx, prefix.Scheme, a.s.watchInterval, a.s.watchBackoff, func(ctx context.Context) (map[string]string, error) {
		_, all, date, err := a.listing(ctx, prefix)
		if err != nil {
			return nil, a.fail(stores.OpWatch, prefix, err)
		}
		n := a.polls.Add(1)
		out := make(map[string]string, len(all))
		for path, p := range all {
			out[path] = fingerprint(&p, date, n)
		}
		return out, nil
	})
}

func fingerprint(p *props, now time.Time, poll uint64) string {
	h := sha256.New()
	for _, k := range slices.Sorted(maps.Keys(p.Tags)) {
		_, _ = fmt.Fprintf(h, "%q=%q;", k, p.Tags[k])
	}
	ct, upd, en := "", int64(0), ""
	if p.ContentType != nil {
		ct = *p.ContentType
	}
	if p.Attributes.Updated != nil {
		upd = *p.Attributes.Updated
	}
	if p.Attributes.Enabled != nil {
		en = strconv.FormatBool(*p.Attributes.Enabled)
	}
	fp := fmt.Sprintf("%d|%s|%q|%x", upd, en, ct, h.Sum(nil))
	if !now.IsZero() && upd >= now.Unix()-2 {
		fp += "|unsettled:" + strconv.FormatUint(poll, 10)
	}
	return fp
}

// Write implements stores.Adapter: a new version of the secret. With
// CreateOnly, an existing secret is a conflict; Key Vault has no
// conditional create, so a secret created by someone else between the
// check and the write is overwritten with a new version (older versions
// stay). Without labels, the current version's tags and content type are
// carried over, because Key Vault keeps them per version.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if a.s.readOnly {
		return stores.Metadata{}, a.errf(stores.OpWrite, ref, stores.ErrUnsupported, "the store is configured read-only")
	}
	if ref.Selectors != "" {
		return stores.Metadata{}, a.errf(stores.OpWrite, ref, stores.ErrInvalidRef, "a write takes no selectors; it always creates a new version")
	}
	name, err := a.names.Name(ref.Path)
	if err != nil {
		return stores.Metadata{}, a.errf(stores.OpWrite, ref, stores.ErrInvalidRef, err.Error())
	}
	value, err := a.encodeValue(fields)
	if err != nil {
		return stores.Metadata{}, a.errf(stores.OpWrite, ref, stores.ErrUnsupported, err.Error())
	}
	defer secret.WipeBytes(value)

	tags := writable(opts.Labels)
	var existing *props
	if opts.CreateOnly || tags == nil {
		vs, err := a.versions(ctx, name)
		switch {
		case err == nil:
			existing, _ = current(vs)
			if existing == nil && len(vs) > 0 {
				existing = &vs[len(vs)-1]
			}
		case errors.Is(err, stores.ErrNotFound):
		default:
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
		}
	}
	if opts.CreateOnly && existing != nil {
		return stores.Metadata{}, a.errf(stores.OpWrite, ref, stores.ErrConflict, "the secret already exists")
	}
	head := map[string]any{}
	if tags == nil && existing != nil && existing.Tags != nil {
		tags = existing.Tags
	}
	if tags != nil {
		head["tags"] = tags
	}
	switch {
	case a.s.format == formatJSON:
		head["contentType"] = jsonContentType
	case existing != nil && existing.ContentType != nil:
		head["contentType"] = *existing.ContentType
	}
	buf := append(make([]byte, 0, len(value)+256), `{"value":`...)
	buf, err = wire.AppendQuoted(buf, value)
	if err != nil {
		secret.WipeBytes(buf)
		return stores.Metadata{}, a.errf(stores.OpWrite, ref, stores.ErrUnsupported, "Key Vault stores text: the value is not valid UTF-8")
	}
	if len(head) > 0 {
		hb, err := wire.AppendJSON(nil, head)
		if err != nil {
			secret.WipeBytes(buf)
			return stores.Metadata{}, a.errf(stores.OpWrite, ref, stores.ErrInvalidRef, "cannot encode tags")
		}
		buf = append(append(buf, ','), hb[1:]...)
	} else {
		buf = append(buf, '}')
	}
	body := wire.NewBody(buf)
	defer body.Wipe()

	involved := slices.Collect(maps.Values(fields))
	resp, err := a.c.do(ctx, http.MethodPut, a.c.url(secretPath(name, ""), nil), body, involved)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	defer secret.WipeBytes(resp.body)
	var b bundle
	err = json.Unmarshal(resp.body, &b)
	b.Value.Wipe()
	if err != nil {
		return stores.Metadata{}, stores.NewError(a.name, stores.OpWrite, ref, stores.ErrUnavailable, errors.New("malformed write response"))
	}
	return a.meta(ref, name, &b.props, slices.Sorted(maps.Keys(fields))), nil
}

// encodeValue builds the secret's value from fields. The caller wipes it.
func (a *Adapter) encodeValue(fields map[string]secret.Value) ([]byte, error) {
	var out []byte
	if a.s.format == formatRaw {
		v, ok := fields[Field]
		if !ok || len(fields) != 1 {
			return nil, errors.New("secrets in format raw hold a single field named " + Field + ", got fields " + strings.Join(slices.Sorted(maps.Keys(fields)), ","))
		}
		_ = v.Expose(func(b []byte) error { out = append([]byte(nil), b...); return nil })
	} else {
		if len(fields) == 0 {
			return nil, errors.New("no fields to write")
		}
		out = append(out, '{')
		for i, k := range slices.Sorted(maps.Keys(fields)) {
			if i > 0 {
				out = append(out, ',')
			}
			kb, _ := wire.AppendJSON(nil, k)
			out = append(append(out, kb...), ':')
			var err error
			if out, err = wire.AppendValue(out, fields[k]); err != nil {
				secret.WipeBytes(out)
				return nil, errors.New("Key Vault stores text: field " + strconv.Quote(k) + " is not valid UTF-8")
			}
		}
		out = append(out, '}')
	}
	if len(out) > maxValue {
		secret.WipeBytes(out)
		return nil, fmt.Errorf("the value is larger than Key Vault's limit of %d bytes", maxValue)
	}
	return out, nil
}

// writable drops tags in the azkv. namespace from a write: they are derived
// from Key Vault's own attributes and could only pose as native keys. An
// empty, non-nil map still clears the tags; a map of only derived keys
// leaves them as they are.
func writable(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if !isReserved(k) {
			out[k] = v
		}
	}
	if len(out) == 0 && len(labels) > 0 {
		return nil
	}
	return out
}

// Health implements stores.Adapter: the vault answers and scrim's identity
// may list secrets.
func (a *Adapter) Health(ctx context.Context) error {
	resp, err := a.c.do(ctx, http.MethodGet, a.c.url("/secrets", url.Values{"maxresults": {"1"}}), nil, nil)
	if err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	secret.WipeBytes(resp.body)
	return nil
}
