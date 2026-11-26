// SPDX-License-Identifier: AGPL-3.0-only

// Package doppler is the store adapter for Doppler (specs/secret-stores,
// "Doppler adapter"), addressed as
//
//	<scheme>://<project>/<config>/<NAME>[#value]
//
// where <project> is the project slug and <config> a root or branch config
// name. A Doppler secret holds one value, exposed as the field "value". With
// Doppler's Permissive secret naming a name may contain '/', so everything
// after the config is the name: `dop://billing/prd/payments/stripe.key` is the
// secret `payments/stripe.key`.
//
// Read returns the computed value, the one Doppler hands to applications
// (`doppler run`, the download endpoint, integrations), with secret
// references such as ${USER} resolved: that is the value an agent can come
// across, so it is the one scrim redacts and injects. The raw value is never
// read on its own.
//
// scrim authenticates with one static bearer token: a service token (read or
// read/write on one config), a service account token, or a personal token.
// There is no login and nothing to renew.
//
// Per-agent store identity (agent.go): an agent's own Doppler token, held
// by scrim (identity.store-credentials) or obtained by presenting an
// identity token scrim signs for the agent to a service account identity's
// OIDC authentication (identity.store-login method doppler-oidc), is used
// to read the secret before scrim's own token does, so Doppler's access
// rules for that token decide too.
//
// The adapter talks to the Doppler v3 REST API with a small typed client
// instead of an SDK, so values travel between the HTTP body and secret.Value
// through package wire and never become Go strings. The token is the one
// exception: net/http takes the Authorization header as a string, built for
// each request and dropped after it.
package doppler

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

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/agentcache"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Kind is the adapter kind this package registers.
const Kind = "doppler"

// Field is the name of the single field a Doppler secret holds.
const Field = "value"

func init() {
	stores.Register(Kind, New)
}

// Adapter is one configured Doppler instance.
type Adapter struct {
	name string
	s    *settings
	c    *client
	// agents caches the tokens agents' service account identities
	// obtained with OIDC (agent.go).
	agents *agentcache.Cache[secret.Value]
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.WriteLabeler     = (*Adapter)(nil)
)

// New builds an adapter from its configuration. It validates the options and
// neither resolves the token nor contacts Doppler.
func New(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
	s, err := decodeSettings(inst)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	c, err := newClient(s)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	return &Adapter{name: inst.Name, s: s, c: c, agents: agentcache.New(copyValue, secret.Value.Wipe)}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter.
func (a *Adapter) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite | stores.CapGlob
}

// Credentials implements stores.CredentialHolder.
func (a *Adapter) Credentials() []secret.Value { return a.c.credentials() }

// Close implements stores.Adapter.
func (a *Adapter) Close() error {
	a.agents.Close()
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

func (a *Adapter) refuse(op stores.Op, ref stores.Ref, kind error, detail string) error {
	return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: kind, Detail: detail}
}

const (
	secretForm = "want <project>/<config>/<NAME>"
	prefixForm = "want <project>/<config>[/<name prefix>][*]"
)

// location is a reference split into Doppler's coordinates.
type location struct {
	project string
	config  string
	name    string
}

// maxName is Doppler's limit on secret name length.
const maxName = 200

// validName reports whether name can be a Doppler secret name in either
// naming mode: letters, digits and _ / : . - (Permissive naming; Classic
// naming is a subset, which Doppler itself enforces).
func validName(name string) bool {
	if name == "" || len(name) > maxName {
		return false
	}
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '/', c == ':', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

func splitSecret(path string) (location, bool) {
	seg := strings.SplitN(path, "/", 3)
	if len(seg) < 3 || seg[0] == "" || seg[1] == "" || !validName(seg[2]) {
		return location{}, false
	}
	return location{project: seg[0], config: seg[1], name: seg[2]}, true
}

// match is a listing prefix: a config and a test on secret names in it.
type match struct {
	project, config string
	prefix          string
	glob            bool
}

// splitPrefix parses a listing prefix. `p/c` matches the whole config,
// `p/c/a` matches the secret a and secrets named a/..., and a trailing `*`
// (stores.CapGlob) matches names by plain string prefix: `p/c/APP_*`, `p/c/*`.
func splitPrefix(path string) (match, bool) {
	body, glob := strings.CutSuffix(path, "*")
	seg := strings.SplitN(body, "/", 3)
	if len(seg) < 2 || seg[0] == "" || seg[1] == "" {
		return match{}, false
	}
	m := match{project: seg[0], config: seg[1], glob: glob}
	if len(seg) == 3 {
		m.prefix = seg[2]
	} else if glob {
		// `p/c*` would glob config names, which a listing cannot do.
		return match{}, false
	}
	if m.prefix != "" && strings.ContainsAny(m.prefix, "*?[") {
		return match{}, false
	}
	return m, true
}

func (m match) matches(name string) bool {
	switch {
	case m.prefix == "":
		return true
	case m.glob:
		return strings.HasPrefix(name, m.prefix)
	}
	p := strings.TrimSuffix(m.prefix, "/")
	return name == p || strings.HasPrefix(name, p+"/")
}

func (m match) ref(scheme, name string) stores.Ref {
	return stores.Ref{Scheme: scheme, Path: m.project + "/" + m.config + "/" + name}
}

// visibility is a Doppler visibility (unmasked, masked, restricted). The
// documented examples spell it {"type": "masked"}, the Doppler CLI decodes it
// as a plain string; both are accepted.
type visibility string

func (v *visibility) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = visibility(s)
		return nil
	}
	var o struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	*v = visibility(o.Type)
	return nil
}

type valueType struct {
	Type string `json:"type"`
}

// apiSecret is one secret as GET /v3/configs/config/secret returns it. Raw
// and Computed are wire.Raw so they never become Go strings and print as a
// marker. The note is free text that may quote a value, so it is not decoded
// at all.
type apiSecret struct {
	Name  string `json:"name"`
	Value struct {
		Raw                wire.Raw   `json:"raw"`
		Computed           wire.Raw   `json:"computed"`
		RawVisibility      visibility `json:"rawVisibility"`
		ComputedVisibility visibility `json:"computedVisibility"`
		RawValueType       valueType  `json:"rawValueType"`
	} `json:"value"`
}

func (s *apiSecret) wipe() {
	s.Value.Raw.Wipe()
	s.Value.Computed.Wipe()
}

// checkSelectors refuses every selector: Doppler has no per-secret version
// that a reference could pin.
func (a *Adapter) checkSelectors(op stores.Op, ref stores.Ref) error {
	if ref.Selectors == "" {
		return nil
	}
	q, _ := url.ParseQuery(ref.Selectors)
	names := slices.Sorted(maps.Keys(q))
	return a.refuse(op, ref, stores.ErrInvalidRef, "unknown selector "+strconv.Quote(names[0])+" (Doppler references take no selectors)")
}

// Read implements stores.Adapter. It returns the computed value.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	l, ok := splitSecret(ref.Path)
	if !ok {
		return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrInvalidRef, secretForm)
	}
	if err := a.checkSelectors(stores.OpRead, ref); err != nil {
		return stores.Secret{}, err
	}
	if ref.Field != "" && ref.Field != Field {
		return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrNotFound, "Doppler secrets hold a single field named "+Field)
	}
	q := url.Values{"project": {l.project}, "config": {l.config}, "name": {l.name}}
	b, err := a.c.do(ctx, http.MethodGet, "/v3/configs/config/secret", q, nil, nil)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	defer secret.WipeBytes(b)
	var s apiSecret
	err = json.Unmarshal(b, &s)
	defer s.wipe()
	if err != nil {
		return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrUnavailable, "malformed secret response")
	}
	computed := bytes.TrimSpace(s.Value.Computed)
	switch {
	case len(computed) == 0:
		return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrUnavailable, "secret response holds no computed value")
	case bytes.Equal(computed, []byte("null")):
		// Doppler withholds a restricted value from personal and CLI
		// tokens, and the computed value of a secret that references a
		// restricted one. Null is never a value.
		return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrPermission,
			"Doppler withheld the value (restricted visibility); only service and service account tokens may read it")
	case computed[0] != '"':
		return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrUnavailable, "computed value is not a JSON string")
	}
	v, err := s.Value.Computed.Value()
	if err != nil {
		return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrUnavailable, "malformed computed value")
	}
	labels := a.locationLabels(ctx, l)
	stores.SetNative(labels, Kind, "visibility", string(s.Value.RawVisibility))
	stores.SetNative(labels, Kind, "computed-visibility", string(s.Value.ComputedVisibility))
	stores.SetNative(labels, Kind, "value-type", s.Value.RawValueType.Type)
	return stores.Secret{Meta: meta(ref, labels), Fields: map[string]secret.Value{Field: v}}, nil
}

func meta(ref stores.Ref, labels map[string]string) stores.Metadata {
	return stores.Metadata{Ref: ref.Secret(), Fields: []string{Field}, Labels: labels}
}

// ReadMetadata implements stores.MetadataReader. Doppler returns a secret's
// value with everything else it says about the secret, so the lookup goes
// through the names endpoint instead, which carries no value: the secret
// exists when its config lists the name. The labels are the location labels
// a read reports, without the visibility and value type, which Doppler only
// returns next to the value.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	l, ok := splitSecret(ref.Path)
	if !ok {
		return stores.Metadata{}, a.refuse(stores.OpRead, ref, stores.ErrInvalidRef, secretForm)
	}
	if err := a.checkSelectors(stores.OpRead, ref); err != nil {
		return stores.Metadata{}, err
	}
	names, err := a.c.names(ctx, l.project, l.config, true)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpRead, ref, err)
	}
	if !slices.Contains(names, l.name) {
		return stores.Metadata{}, a.refuse(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	return meta(ref, a.locationLabels(ctx, l)), nil
}

// List implements stores.Adapter. It reads names only, never values, and
// leaves out Doppler's managed DOPPLER_* secrets, whose values (the project,
// config and environment names) are not secret and would make scrim redact
// ordinary words.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	m, ok := splitPrefix(prefix.Path)
	if !ok {
		return nil, a.refuse(stores.OpList, prefix, stores.ErrInvalidRef, prefixForm)
	}
	names, err := a.c.names(ctx, m.project, m.config, false)
	if err != nil {
		return nil, a.fail(stores.OpList, prefix, err)
	}
	var out []stores.Metadata
	for _, n := range names {
		if managedNames[n] || !m.matches(n) {
			continue
		}
		ref := m.ref(prefix.Scheme, n)
		out = append(out, meta(ref, a.locationLabels(ctx, location{project: m.project, config: m.config, name: n})))
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out, nil
}

// referenceMarker starts a Doppler secret reference. A written value holding
// it would be stored as given but computed differently.
var referenceMarker = []byte("${")

// storable reports whether Doppler hands v back unchanged as the computed
// value. A value holding "${" is refused: Doppler would resolve it as a
// secret reference (now, or later once the referenced secret appears), so
// scrim would redact and inject a value that differs from the one
// applications get.
func storable(v secret.Value) bool {
	ok := false
	_ = v.Expose(func(b []byte) error {
		ok = !bytes.Contains(b, referenceMarker)
		return nil
	})
	return ok
}

// Write implements stores.Adapter: create, or update when the secret exists
// and CreateOnly is not set. Doppler has no create-only operation, so the
// adapter checks the names first. The change request marks a new secret as
// new (originalName null); what Doppler does when one of that name appeared
// since the check is not documented, so docs/stores/doppler.md treats that
// race as a possible overwrite.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	l, ok := splitSecret(ref.Path)
	if !ok {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrInvalidRef, secretForm)
	}
	if err := a.checkSelectors(stores.OpWrite, ref); err != nil {
		return stores.Metadata{}, err
	}
	v, ok := fields[Field]
	if !ok || len(fields) != 1 {
		names := slices.Sorted(maps.Keys(fields))
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnsupported,
			"Doppler secrets hold a single field named "+Field+", got fields "+strings.Join(names, ","))
	}
	if !storable(v) {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnsupported,
			`the value contains "${", which Doppler would resolve as a secret reference; refusing a value it would change`)
	}
	names, err := a.c.names(ctx, l.project, l.config, true)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	exists := slices.Contains(names, l.name)
	if exists && opts.CreateOnly {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrConflict, "the secret already exists")
	}
	body, err := changeRequest(l, v, exists)
	if err != nil {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnsupported, "Doppler stores text: the value is not valid UTF-8")
	}
	defer body.Wipe()
	b, err := a.c.do(ctx, http.MethodPost, "/v3/configs/config/secrets", nil, body, []secret.Value{v})
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	// The response echoes every secret of the config with its values.
	secret.WipeBytes(b)
	return meta(ref, a.locationLabels(ctx, l)), nil
}

// changeRequest encodes one change request: a new secret (originalName
// null) or a new value for an existing one, leaving its visibility and value
// type alone. The caller wipes the body.
func changeRequest(l location, v secret.Value, exists bool) (*wire.Body, error) {
	var original any
	if exists {
		original = l.name
	}
	head, err := wire.AppendJSON(nil, map[string]any{"project": l.project, "config": l.config})
	if err != nil {
		return nil, err
	}
	cr, err := wire.AppendJSON(nil, map[string]any{"name": l.name, "originalName": original})
	if err != nil {
		return nil, err
	}
	buf := head[:len(head)-1]
	buf = append(buf, `,"change_requests":[`...)
	buf = append(buf, cr[:len(cr)-1]...)
	buf = append(buf, `,"value":`...)
	buf, err = wire.AppendValue(buf, v)
	if err != nil {
		secret.WipeBytes(buf)
		return nil, err
	}
	return wire.NewBody(append(buf, "}]}"...)), nil
}

// Health implements stores.Adapter: Doppler answers and accepts the token.
func (a *Adapter) Health(ctx context.Context) error {
	if _, err := a.c.whoami(ctx); err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}
