// SPDX-License-Identifier: AGPL-3.0-only

// Package infisical is the store adapter for Infisical (specs/secret-stores,
// "Infisical adapter"), addressed as
//
//	<scheme>://<project>/<environment>/<folder>/.../<KEY>[?version=<n>][#value]
//
// where <project> is a project slug or ID. Infisical secrets hold one value,
// exposed as the field "value". scrim authenticates with a Universal Auth
// machine identity, or in a cluster with a Kubernetes Auth identity and its
// pod's service account token, read at every login.
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
	"github.com/heliopsy/scrim/internal/stores/internal/agentcache"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Kind is the adapter kind this package registers.
const Kind = "infisical"

// Field is the name of the single field an Infisical secret holds.
const Field = "value"

func init() {
	stores.DeclareMulti(Kind, multiAttrs...)
	stores.Register(Kind, New)
}

// Adapter is one configured Infisical instance.
type Adapter struct {
	name string
	s    *settings
	c    *client
	// agents caches the access tokens agents' own identities logged in
	// with (agent.go).
	agents *agentcache.Cache[secret.Value]
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.WriteLabeler     = (*Adapter)(nil)
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
	return &Adapter{name: inst.Name, s: s, c: c, agents: agentcache.New(copyValue, secret.Value.Wipe)}, nil
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
// so it never becomes a Go string and prints as a marker. secretComment and
// secretReminderNote are free text that may quote a value, so they are not
// decoded at all.
type apiSecret struct {
	Name        string   `json:"secretKey"`
	SecretValue wire.Raw `json:"secretValue"`
	// SecretValueHidden is set when SecretValue holds Infisical's mask
	// instead of the value.
	SecretValueHidden bool      `json:"secretValueHidden"`
	Version           int       `json:"version"`
	Type              string    `json:"type"`
	Environment       string    `json:"environment"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
	SecretPath        string    `json:"secretPath"`
	SecretMetadata    []kv      `json:"secretMetadata"`
	// Tags is nil when the response has no tags field, empty when the
	// secret has none.
	Tags            []apiTag `json:"tags"`
	IsRotatedSecret *bool    `json:"isRotatedSecret"`
	RotationID      string   `json:"rotationId"`
	ReminderDays    optInt   `json:"secretReminderRepeatDays"`
}

// kv is one secret metadata entry. An encrypted entry (Infisical's
// "encrypted metadata", meant for sensitive text) is returned decrypted, so
// its value is never put in a label.
type kv struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	IsEncrypted bool   `json:"isEncrypted,omitempty"`
}

type apiTag struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// optInt is a nullable number that remembers whether the field was present.
type optInt struct {
	set bool
	n   *int
}

func (o *optInt) UnmarshalJSON(b []byte) error {
	o.set = true
	return json.Unmarshal(b, &o.n)
}

func (s *apiSecret) meta(ref stores.Ref, labels map[string]string) stores.Metadata {
	m := stores.Metadata{
		Ref:       ref.Secret(),
		Fields:    []string{Field},
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
		Labels:    labels,
	}
	if s.Version > 0 {
		m.Version = strconv.Itoa(s.Version)
	}
	return m
}

// labels builds the labels of s, found at folder of l (docs/stores/
// infisical.md, "Policy labels"). Unencrypted secret metadata is copied as
// is, as before native labels existed, minus keys in the infisical.
// namespace; native attributes follow, then the metadata again under
// infisical.meta., which never overwrites a key, so metadata cannot forge a
// native label.
func (a *Adapter) labels(p projectInfo, projectID string, l location, folder string, s *apiSecret) map[string]string {
	out := map[string]string{}
	var encrypted []string
	for _, e := range s.SecretMetadata {
		switch {
		case e.IsEncrypted:
			encrypted = append(encrypted, e.Key)
		case !isReserved(e.Key):
			out[e.Key] = e.Value
		}
	}
	nativeLocation(out, p, projectID, l, folder, s.Name)
	stores.SetNative(out, Kind, "encrypted-meta", encrypted...)
	if s.Type != "" {
		stores.SetNative(out, Kind, "type", s.Type)
	}
	if s.Version > 0 {
		stores.SetNative(out, Kind, "version", strconv.Itoa(s.Version))
	}
	setTime(out, "created", s.CreatedAt)
	setTime(out, "updated", s.UpdatedAt)
	slugs := make([]string, 0, len(s.Tags))
	for _, t := range s.Tags {
		slugs = append(slugs, t.Slug)
	}
	stores.SetNative(out, Kind, "tag", slugs...)
	if s.IsRotatedSecret != nil {
		setBool(out, "rotation", *s.IsRotatedSecret)
		if *s.IsRotatedSecret && s.RotationID != "" {
			stores.SetNative(out, Kind, "rotation.id", s.RotationID)
		}
	}
	if s.ReminderDays.set {
		on := s.ReminderDays.n != nil && *s.ReminderDays.n > 0
		setBool(out, "reminder", on)
		if on {
			stores.SetNative(out, Kind, "reminder.days", strconv.Itoa(*s.ReminderDays.n))
		}
	}
	// A secret Infisical served through a secret import carries the
	// environment and folder it was imported from.
	srcEnv, srcPath := s.Environment, "/"+strings.Trim(s.SecretPath, "/")
	imported := (srcEnv != "" && srcEnv != l.env) || (s.SecretPath != "" && srcPath != "/"+strings.Trim(folder, "/"))
	setBool(out, "imported", imported)
	if imported {
		if srcEnv == "" {
			srcEnv = l.env
		}
		stores.SetNative(out, Kind, "import.environment", srcEnv)
		stores.SetNative(out, Kind, "import.path", srcPath)
	}
	for _, e := range s.SecretMetadata {
		if !e.IsEncrypted {
			stores.UserMeta(out, Kind, e.Key, e.Value)
		}
	}
	return out
}

// nativeLocation sets the labels that follow from where a secret is: the
// organisation, project and environment (names where the identity may read
// the project), the folder and its ancestors, the key and the full path.
func nativeLocation(out map[string]string, p projectInfo, projectID string, l location, folder, key string) {
	switch {
	case p.ok:
		stores.SetNative(out, Kind, "project", p.Slug)
		stores.SetNative(out, Kind, "project.id", p.ID)
		stores.SetNative(out, Kind, "project.slug", p.Slug)
		stores.SetNative(out, Kind, "project.name", p.Name)
		if p.OrgID != "" {
			stores.SetNative(out, Kind, "org.id", p.OrgID)
		}
	case uuidPattern.MatchString(l.project):
		stores.SetNative(out, Kind, "project", l.project)
		stores.SetNative(out, Kind, "project.id", l.project)
	default:
		stores.SetNative(out, Kind, "project", l.project)
		stores.SetNative(out, Kind, "project.slug", l.project)
		if projectID != "" {
			stores.SetNative(out, Kind, "project.id", projectID)
		}
	}
	stores.SetNative(out, Kind, "environment", l.env)
	if name, id := p.env(l.env); name != "" {
		stores.SetNative(out, Kind, "environment.name", name)
		stores.SetNative(out, Kind, "environment.id", id)
	}
	folderKeys(out, folder)
	stores.SetNative(out, Kind, "key", key)
	stores.SetNative(out, Kind, "path", strings.TrimSuffix("/"+strings.Trim(folder, "/"), "/")+"/"+key)
}

// WriteLabels returns the native labels a secret written at ref would get,
// without contacting Infisical, so store.write rules can match on project,
// environment and folder before the secret exists. Project names come from
// what earlier calls cached; until then the reference's own project segment
// is used.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	l, ok := splitSecret(ref.Path)
	if !ok {
		return nil
	}
	p := a.c.cachedProject(l.project)
	out := map[string]string{}
	nativeLocation(out, p, p.ID, l, l.folder, l.key)
	stores.SetNative(out, Kind, "type", "shared")
	return out
}

func (a *Adapter) baseQuery(ctx context.Context, l location) (url.Values, string, error) {
	id, err := a.c.projectID(ctx, l.project)
	if err != nil {
		return nil, "", err
	}
	return url.Values{"projectId": {id}, "environment": {l.env}, "secretPath": {l.folder}}, id, nil
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	got, err := a.get(ctx, ref, true)
	if err != nil {
		return stores.Secret{}, err
	}
	defer got.secret.SecretValue.Wipe()
	// Infisical answers an identity that may describe the secret but not
	// read it with a mask in place of the value. The mask is never a value.
	if got.secret.SecretValueHidden {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrPermission,
			Detail: "Infisical hid the value (secretValueHidden); the identity may describe this secret but not read its value"}
	}
	v, err := got.secret.SecretValue.Value()
	if err != nil {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrUnavailable, Detail: "secret value missing from the response"}
	}
	return stores.Secret{Meta: got.secret.meta(ref, got.labels), Fields: map[string]secret.Value{Field: v}}, nil
}

// ReadMetadata implements stores.MetadataReader. It makes the request Read
// makes with viewSecretValue=false, so Infisical answers with its hidden
// value mask in place of the value, and without expanding secret
// references, which only change the value. Whatever stands in the value
// field (the mask, or the value from a server that ignores the option) is
// wiped unread. The labels are the ones Read builds from the same
// response, and errors are Read's.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	got, err := a.get(ctx, ref, false)
	if err != nil {
		return stores.Metadata{}, err
	}
	got.secret.SecretValue.Wipe()
	return got.secret.meta(ref, got.labels), nil
}

// fetched is one secret as GET /api/v4/secrets/{key} returned it, with its
// labels. The caller wipes secret.SecretValue.
type fetched struct {
	secret apiSecret
	labels map[string]string
}

// secretQuery builds the single-secret read of ref: the API path and query,
// the project ID and the location. Errors are store errors.
func (a *Adapter) secretQuery(ctx context.Context, ref stores.Ref, withValue bool) (string, url.Values, string, location, error) {
	l, ok := splitSecret(ref.Path)
	if !ok {
		return "", nil, "", l, a.invalid(stores.OpRead, ref, "want <project>/<environment>/[<folder>/...]<KEY>")
	}
	var version string
	if ref.Selectors != "" {
		q, _ := url.ParseQuery(ref.Selectors)
		for k := range q {
			if k != "version" {
				return "", nil, "", l, a.invalid(stores.OpRead, ref, "unknown selector "+strconv.Quote(k)+" (supported: version)")
			}
		}
		version = q.Get("version")
		if n, err := strconv.Atoi(version); err != nil || n < 1 {
			return "", nil, "", l, a.invalid(stores.OpRead, ref, "version must be a positive integer")
		}
	}
	if ref.Field != "" && ref.Field != Field {
		return "", nil, "", l, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrNotFound,
			Detail: "Infisical secrets hold a single field named " + Field}
	}
	q, id, err := a.baseQuery(ctx, l)
	if err != nil {
		return "", nil, "", l, a.fail(stores.OpRead, ref, err)
	}
	q.Set("type", "shared")
	q.Set("viewSecretValue", strconv.FormatBool(withValue))
	q.Set("expandSecretReferences", strconv.FormatBool(withValue && a.s.expandRefs))
	if version != "" {
		q.Set("version", version)
	}
	return "/api/v4/secrets/" + url.PathEscape(l.key), q, id, l, nil
}

// get fetches the secret ref names, with its value when withValue is set.
func (a *Adapter) get(ctx context.Context, ref stores.Ref, withValue bool) (fetched, error) {
	path, q, id, l, err := a.secretQuery(ctx, ref, withValue)
	if err != nil {
		return fetched{}, err
	}
	b, err := a.c.do(ctx, http.MethodGet, path, q, nil, nil)
	if err != nil {
		return fetched{}, a.fail(stores.OpRead, ref, err)
	}
	defer secret.WipeBytes(b)
	var resp struct {
		Secret apiSecret `json:"secret"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		resp.Secret.SecretValue.Wipe()
		return fetched{}, stores.NewError(a.name, stores.OpRead, ref, stores.ErrUnavailable, errors.New("malformed secret response"))
	}
	// A single read reports no reminder whether or not one is set
	// (Infisical v0.167 joins reminders into listings only), so the
	// reminder labels come from listings alone rather than say "false".
	resp.Secret.ReminderDays = optInt{}
	labels := a.labels(a.c.projectDetails(ctx, id), id, l, l.folder, &resp.Secret)
	return fetched{secret: resp.Secret, labels: labels}, nil
}

// List implements stores.Adapter. It never asks Infisical for values.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	l, ok := splitPrefix(prefix.Path)
	if !ok {
		return nil, a.invalid(stores.OpList, prefix, "want <project>/<environment>[/<folder>...]")
	}
	q, id, err := a.baseQuery(ctx, l)
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
	p := a.c.projectDetails(ctx, id)
	out := make([]stores.Metadata, 0, len(resp.Secrets))
	for i := range resp.Secrets {
		s := &resp.Secrets[i]
		folder := s.SecretPath
		if folder == "" {
			folder = l.folder
		}
		out = append(out, s.meta(l.refFor(prefix.Scheme, folder, s.Name), a.labels(p, id, l, folder, s)))
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
	labels := writable(opts.Labels)

	m, err := a.send(ctx, http.MethodPost, id, l, ref, v, labels, involved)
	if err != nil && isNotFound(err) && a.s.createFolders && l.folder != "/" {
		if ferr := a.ensureFolders(ctx, id, l); ferr != nil {
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, ferr)
		}
		m, err = a.send(ctx, http.MethodPost, id, l, ref, v, labels, involved)
	}
	if err != nil && errors.Is(err, stores.ErrConflict) && !opts.CreateOnly {
		m, err = a.send(ctx, http.MethodPatch, id, l, ref, v, labels, involved)
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
	if resp.Secret.SecretMetadata == nil && labels != nil {
		// The response does not echo metadata: report what was written.
		for _, k := range slices.Sorted(maps.Keys(labels)) {
			resp.Secret.SecretMetadata = append(resp.Secret.SecretMetadata, kv{Key: k, Value: labels[k]})
		}
	}
	if resp.Secret.Name == "" {
		resp.Secret.Name = l.key
	}
	resp.Secret.ReminderDays = optInt{} // as in Read
	return resp.Secret.meta(ref, a.labels(a.c.projectDetails(ctx, projectID), projectID, l, l.folder, &resp.Secret)), nil
}

// writable drops labels in the infisical. namespace from a write: they are
// derived from Infisical's own attributes on every read and are not stored
// as secret metadata, where they could only pose as native keys. An empty,
// non-nil map still means "clear the metadata", as before.
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
		// Only derived keys: leave the stored metadata alone rather than
		// replace it with nothing.
		return nil
	}
	return out
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
	tok, err := a.c.accessToken(ctx)
	if err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	tok.Wipe()
	return nil
}
