// SPDX-License-Identifier: AGPL-3.0-only

// Package bws is the store adapter for Bitwarden Secrets Manager
// (specs/secret-stores, "Bitwarden Secrets Manager adapter"), addressed as
//
//	<scheme>://<project>/<key>[#value|#note]
//	<scheme>://<secret-id>[#value|#note]
//
// where <project> is a project name or ID and <key> is the secret's key,
// which may itself contain slashes. scrim logs in as a machine account with
// its access token.
//
// Secrets Manager encrypts every key, value, note and project name on the
// client with the organisation key; the server only ever sees ciphertext.
// The official Go SDK (github.com/bitwarden/sdk-go) links the Rust core
// through cgo and prebuilt static libraries, which a CGO_ENABLED=0 build
// cannot use, and hands values around as Go strings. So the adapter speaks
// the protocol itself: the access token key derivation and login of
// bitwarden-core, the AES-256-CBC-HMAC-SHA256 encrypted strings of
// bitwarden-crypto (through package bwcrypto, shared with the Vaultwarden
// adapter), and the REST endpoints bitwarden-sm calls. Known-answer tests
// pin each step to vectors from the official SDK's own tests and fake server.
//
// Values are decrypted straight into secret.Value and never become Go
// strings. The bearer token is the one exception: net/http takes the
// Authorization header as a string, built for each request and dropped after
// it.
//
// Per-agent identity: an agent's store credential is an access token of a
// machine account of scrim's organisation. Before scrim uses a secret for
// the agent, AgentCan logs in as that machine account (the login is cached
// per agent and token) and fetches the secret, or for a new secret its
// project, with the agent's bearer token: the server's own answer (404, or
// the read and write flags it returns) decides, and the ciphertext it sends
// is wiped without being decrypted. Bitwarden logs these fetches under the
// agent's machine account (Secret_Retrieved, Project_Retrieved), so its
// event log names the agent. Bitwarden has no token exchange; Kubernetes
// passthrough and federation are unsupported.
package bws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/agentcache"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// Kind is the adapter kind this package registers.
const Kind = "bws"

// Field names. A secret's value is "value"; its note, free text that may
// itself hold a secret, is readable only when asked for by name.
const (
	FieldValue = "value"
	FieldNote  = "note"
)

// Limits the official SDK validates before it encrypts (bitwarden-sm
// secrets/create.rs), in characters.
const (
	maxKeyLen   = 500
	maxValueLen = 25000
	maxNoteLen  = 7000
)

// Limits the server puts on the encrypted strings it accepts
// (EncryptedStringLength in SecretCreateRequestModel).
const (
	maxKeyEnc   = 1000
	maxValueEnc = 35000
	maxNoteEnc  = 10000
)

func init() {
	stores.DeclareMulti(Kind, multiAttrs...)
	stores.Register(Kind, New)
}

// Adapter is one configured Secrets Manager instance.
type Adapter struct {
	name string
	s    *settings
	c    *client
	// writeMu serialises this adapter's writes, so two writes of a new key
	// cannot both find it absent and create it twice. Secrets Manager
	// allows duplicate keys, so writers in other processes can still race;
	// see docs/stores/bws.md.
	writeMu sync.Mutex
	// agents caches the bearer tokens agents' own machine accounts logged
	// in with (AgentCan).
	agents *agentcache.Cache[secret.Value]
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.WriteLabeler     = (*Adapter)(nil)
)

// New builds an adapter from its configuration. It validates the options and
// does not resolve the access token or contact Bitwarden.
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
	a.c.close()
	a.agents.Close()
	return nil
}

func (a *Adapter) fail(op stores.Op, ref stores.Ref, err error) error {
	var se *stores.Error
	if errors.As(err, &se) {
		return se
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: ae.kind, Detail: ae.msg, Cause: ae.cause}
	}
	return stores.NewError(a.name, op, ref, stores.ErrUnavailable, err)
}

func (a *Adapter) errorf(op stores.Op, ref stores.Ref, kind error, format string, args ...any) error {
	return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

// --- API models (bitwarden-api-api) ---

type apiProject struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
}

type apiProjects struct {
	Data []apiProject `json:"data"`
}

type apiInnerProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// apiIdentifier is one entry of GET /organizations/{id}/secrets
// (SecretsWithProjectsInnerSecret): no value, no note.
type apiIdentifier struct {
	ID             string            `json:"id"`
	OrganizationID string            `json:"organizationId"`
	Key            string            `json:"key"`
	CreationDate   apiTime           `json:"creationDate"`
	RevisionDate   apiTime           `json:"revisionDate"`
	Projects       []apiInnerProject `json:"projects"`
}

type apiIdentifiers struct {
	Secrets []apiIdentifier `json:"secrets"`
}

// apiSecret is SecretResponseModel. Value and Note are ciphertext.
type apiSecret struct {
	ID             string            `json:"id"`
	OrganizationID string            `json:"organizationId"`
	Key            string            `json:"key"`
	Value          string            `json:"value"`
	Note           string            `json:"note"`
	CreationDate   apiTime           `json:"creationDate"`
	RevisionDate   apiTime           `json:"revisionDate"`
	Projects       []apiInnerProject `json:"projects"`
}

// apiSecretWrite is SecretCreateRequestModel and SecretUpdateRequestModel:
// every text field is an encrypted string.
type apiSecretWrite struct {
	Key          string   `json:"key"`
	Value        string   `json:"value"`
	Note         string   `json:"note"`
	ProjectIDs   []string `json:"projectIds"`
	ValueChanged *bool    `json:"valueChanged,omitempty"`
}

// --- index: what the machine account can see, without values ---

type project struct {
	id, name string
}

type entry struct {
	id         string
	org        string
	key        string
	keyEnc     string
	projectIDs []string
	created    time.Time
	revised    time.Time
}

type index struct {
	org      string
	projects map[string]project // by ID
	secrets  []entry
}

// loadIndex lists the organisation's projects and secret identifiers the
// machine account can see. Neither call returns a value or a note. Key and
// project names are decrypted: they are names, not values.
func (a *Adapter) loadIndex(ctx context.Context) (*index, error) {
	_, org, err := a.c.session(ctx, false)
	if err != nil {
		return nil, err
	}
	key := a.c.key()
	var ps apiProjects
	if err := a.c.call(ctx, "GET", "/organizations/"+org+"/projects", nil, nil, &ps); err != nil {
		return nil, err
	}
	ix := &index{org: org, projects: map[string]project{}}
	for _, p := range ps.Data {
		name, err := key.DecryptMetadata(p.Name)
		if err != nil {
			return nil, &apiError{kind: stores.ErrUnavailable, msg: "cannot decrypt a project name with the organization key", cause: err}
		}
		ix.projects[strings.ToLower(p.ID)] = project{id: strings.ToLower(p.ID), name: name}
	}
	var ids apiIdentifiers
	if err := a.c.call(ctx, "GET", "/organizations/"+org+"/secrets", nil, nil, &ids); err != nil {
		return nil, err
	}
	for _, s := range ids.Secrets {
		k, err := key.DecryptMetadata(s.Key)
		if err != nil {
			return nil, &apiError{kind: stores.ErrUnavailable, msg: "cannot decrypt a secret key with the organization key", cause: err}
		}
		e := entry{id: strings.ToLower(s.ID), org: strings.ToLower(s.OrganizationID), key: k, keyEnc: s.Key, created: s.CreationDate.Time, revised: s.RevisionDate.Time}
		for _, p := range s.Projects {
			pid := strings.ToLower(p.ID)
			e.projectIDs = append(e.projectIDs, pid)
			// A machine account with access to a secret but not to its
			// project sees the project only here.
			if _, ok := ix.projects[pid]; !ok {
				if n, err := key.DecryptMetadata(p.Name); err == nil {
					ix.projects[pid] = project{id: pid, name: n}
				}
			}
		}
		ix.secrets = append(ix.secrets, e)
	}
	return ix, nil
}

func (ix *index) byID(id string) (entry, bool) {
	id = strings.ToLower(id)
	for _, e := range ix.secrets {
		if e.id == id {
			return e, true
		}
	}
	return entry{}, false
}

// findProject resolves a project ID or name. ok is false when no project
// matches; ambiguous lists the IDs when several projects share the name.
func (ix *index) findProject(sel string) (p project, ok bool, ambiguous []string) {
	if uuidPattern.MatchString(sel) {
		if p, ok := ix.projects[strings.ToLower(sel)]; ok {
			return p, true, nil
		}
	}
	var hits []project
	for _, p := range ix.projects {
		if p.name == sel {
			hits = append(hits, p)
		}
	}
	switch len(hits) {
	case 0:
		return project{}, false, nil
	case 1:
		return hits[0], true, nil
	}
	for _, h := range hits {
		ambiguous = append(ambiguous, h.id)
	}
	slices.Sort(ambiguous)
	return project{}, false, ambiguous
}

func (ix *index) inProject(pid string) []entry {
	var out []entry
	for _, e := range ix.secrets {
		if slices.Contains(e.projectIDs, pid) {
			out = append(out, e)
		}
	}
	return out
}

// location is a parsed reference.
type location struct {
	id         string // set for <scheme>://<secret-id>
	projectSel string // project name or ID as written
	key        string
}

func parseLocation(path string) (location, bool) {
	sel, key, ok := strings.Cut(path, "/")
	if !ok {
		if uuidPattern.MatchString(path) {
			return location{id: strings.ToLower(path)}, true
		}
		return location{}, false
	}
	return location{projectSel: sel, key: key}, true
}

const refForms = "want <project>/<key> or <secret-id>"

// resolve finds the one secret ref names. A missing project or key is
// ErrNotFound; a name several projects or secrets share is ErrInvalidRef,
// naming the IDs to use instead.
func (a *Adapter) resolve(op stores.Op, ref stores.Ref, ix *index) (entry, error) {
	loc, ok := parseLocation(ref.Path)
	if !ok {
		return entry{}, a.errorf(op, ref, stores.ErrInvalidRef, refForms)
	}
	if loc.id != "" {
		e, ok := ix.byID(loc.id)
		if !ok {
			return entry{}, a.errorf(op, ref, stores.ErrNotFound, "no secret with this ID is visible to the machine account")
		}
		return e, nil
	}
	p, err := a.project(op, ref, ix, loc.projectSel)
	if err != nil {
		return entry{}, err
	}
	var hits []entry
	for _, e := range ix.inProject(p.id) {
		if e.key == loc.key {
			hits = append(hits, e)
		}
	}
	switch len(hits) {
	case 0:
		return entry{}, a.errorf(op, ref, stores.ErrNotFound, "no secret with this key in project %s", p.id)
	case 1:
		return hits[0], nil
	}
	ids := make([]string, 0, len(hits))
	for _, h := range hits {
		ids = append(ids, h.id)
	}
	slices.Sort(ids)
	return entry{}, a.errorf(op, ref, stores.ErrInvalidRef, "%d secrets in project %s share this key; address one by ID (%s)", len(hits), p.id, strings.Join(ids, ", "))
}

func (a *Adapter) project(op stores.Op, ref stores.Ref, ix *index, sel string) (project, error) {
	p, ok, amb := ix.findProject(sel)
	switch {
	case len(amb) > 0:
		return project{}, a.errorf(op, ref, stores.ErrInvalidRef, "%d projects share the name %q; use a project ID (%s)", len(amb), sel, strings.Join(amb, ", "))
	case !ok:
		return project{}, a.errorf(op, ref, stores.ErrNotFound, "no project %q is visible to the machine account", sel)
	}
	return p, nil
}

// refOf is the reference an entry is listed under: <sel>/<key> with the
// project written as in sel, or <secret-id> when the key is shared by
// another secret in the project or would not survive a round trip through a
// reference (a '#' or '?', empty segments).
func (a *Adapter) refOf(scheme, sel string, e entry, ix *index, pid string) stores.Ref {
	byID := stores.Ref{Scheme: scheme, Path: e.id}
	if sel == "" {
		return byID
	}
	n := 0
	for _, o := range ix.inProject(pid) {
		if o.key == e.key {
			n++
		}
	}
	if n != 1 {
		return byID
	}
	r := stores.Ref{Scheme: scheme, Path: sel + "/" + e.key}
	if p, err := stores.ParseRef(r.String()); err != nil || p != r {
		return byID
	}
	return r
}

func (a *Adapter) meta(ref stores.Ref, e entry, ix *index) stores.Metadata {
	return stores.Metadata{
		Ref:       ref,
		Fields:    []string{FieldValue},
		Version:   version(e.revised),
		CreatedAt: e.created,
		UpdatedAt: e.revised,
		Labels:    labelsFor(e, ix),
	}
}

func version(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func noSelectors(ref stores.Ref) bool { return ref.Selectors == "" }

// Read implements stores.Adapter. It resolves the reference through the
// identifier list, then fetches that one secret and decrypts the field asked
// for: the value by default, the note only with #note.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if !noSelectors(ref) {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrInvalidRef, "Secrets Manager references take no selectors")
	}
	switch ref.Field {
	case "", FieldValue, FieldNote:
	default:
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrNotFound, "a Secrets Manager secret has the fields %s and %s", FieldValue, FieldNote)
	}
	ix, err := a.loadIndex(ctx)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	e, err := a.resolve(stores.OpRead, ref, ix)
	if err != nil {
		return stores.Secret{}, err
	}
	var s apiSecret
	if err := a.c.call(ctx, "GET", "/secrets/"+e.id, nil, nil, &s); err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	if !strings.EqualFold(s.ID, e.id) {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrUnavailable, "the server answered with another secret")
	}
	field, enc := FieldValue, s.Value
	if ref.Field == FieldNote {
		field, enc = FieldNote, s.Note
	}
	v, err := a.c.key().DecryptString(enc)
	if err != nil {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrUnavailable, "cannot decrypt the secret with the organization key: %v", err)
	}
	e.revised, e.created = s.RevisionDate.Time, s.CreationDate.Time
	m := a.meta(ref.Secret(), e, ix)
	if field == FieldNote {
		m.Fields = []string{FieldValue, FieldNote}
	}
	return stores.Secret{Meta: m, Fields: map[string]secret.Value{field: v}}, nil
}

// ReadMetadata implements stores.MetadataReader from the identifier list
// alone: no value or note is fetched.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	ix, err := a.loadIndex(ctx)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpRead, ref, err)
	}
	e, err := a.resolve(stores.OpRead, ref, ix)
	if err != nil {
		return stores.Metadata{}, err
	}
	return a.meta(ref.Secret(), e, ix), nil
}

// listing is a parsed List or Watch prefix.
type listing struct {
	id      string // a single secret by ID
	sel     string // project as written
	key     string // key prefix
	glob    bool   // key is a name prefix (`APP_*`), not a folder
	allKeys bool
}

func parseListing(path string) (listing, bool) {
	path = strings.TrimSuffix(path, "/*")
	sel, rest, hasRest := strings.Cut(path, "/")
	if sel == "" || strings.Contains(sel, "*") {
		return listing{}, false
	}
	if !hasRest {
		if uuidPattern.MatchString(sel) {
			return listing{sel: sel, id: strings.ToLower(sel), allKeys: true}, true
		}
		return listing{sel: sel, allKeys: true}, true
	}
	if strings.HasSuffix(rest, "*") {
		k := strings.TrimSuffix(rest, "*")
		if strings.Contains(k, "*") {
			return listing{}, false
		}
		return listing{sel: sel, key: k, glob: true}, true
	}
	if strings.Contains(rest, "*") {
		return listing{}, false
	}
	return listing{sel: sel, key: rest}, true
}

func (l listing) matches(key string) bool {
	switch {
	case l.allKeys:
		return true
	case l.glob:
		return strings.HasPrefix(key, l.key)
	}
	return key == l.key || strings.HasPrefix(key, l.key+"/")
}

// List implements stores.Adapter: the secrets of one project, optionally
// under a key prefix (`proj/app` lists `app` and `app/...`; `proj/APP_*`
// every key starting with `APP_`). No value is fetched.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	l, ok := parseListing(prefix.Path)
	if !ok {
		return nil, a.errorf(stores.OpList, prefix, stores.ErrInvalidRef, "want <project>[/<key prefix>][*] or <secret-id>")
	}
	ix, err := a.loadIndex(ctx)
	if err != nil {
		return nil, a.fail(stores.OpList, prefix, err)
	}
	return a.list(prefix, l, ix), nil
}

func (a *Adapter) list(prefix stores.Ref, l listing, ix *index) []stores.Metadata {
	var out []stores.Metadata
	if l.id != "" {
		// A bare UUID names a project first, then a secret.
		if _, isProject := ix.projects[l.id]; !isProject {
			if e, ok := ix.byID(l.id); ok {
				return []stores.Metadata{a.meta(stores.Ref{Scheme: prefix.Scheme, Path: e.id}, e, ix)}
			}
			return nil
		}
	}
	p, ok, amb := ix.findProject(l.sel)
	if !ok || len(amb) > 0 {
		// An unknown project lists nothing, like an empty folder; an
		// ambiguous name lists nothing rather than guess.
		return nil
	}
	for _, e := range ix.inProject(p.id) {
		if l.matches(e.key) {
			out = append(out, a.meta(a.refOf(prefix.Scheme, l.sel, e, ix, p.id), e, ix))
		}
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out
}

// Health implements stores.Adapter: a login and a project listing.
func (a *Adapter) Health(ctx context.Context) error {
	_, org, err := a.c.session(ctx, false)
	if err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	if err := a.c.call(ctx, "GET", "/organizations/"+org+"/projects", nil, nil, &apiProjects{}); err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}

// storable reports why v cannot be stored as a value, or "" if it can:
// Secrets Manager values are non-empty UTF-8 text of at most 25 000
// characters, as the official clients validate.
func storable(v secret.Value, maxLen int, allowEmpty bool) string {
	reason := ""
	_ = v.Expose(func(b []byte) error {
		switch {
		case len(b) == 0 && !allowEmpty:
			reason = "Secrets Manager does not store an empty value"
		case !utf8.Valid(b):
			reason = "Secrets Manager stores text; the value is not valid UTF-8"
		case utf8.RuneCount(b) > maxLen:
			reason = fmt.Sprintf("Secrets Manager stores at most %d characters here", maxLen)
		}
		return nil
	})
	return reason
}

// validKey reports why key cannot be a new secret's key, or "".
func validKey(key string) string {
	switch {
	case strings.TrimSpace(key) == "":
		return "the key is empty or only whitespace"
	case strings.TrimFunc(key, unicode.IsSpace) != key:
		return "the key starts or ends with whitespace, which Bitwarden clients trim"
	case utf8.RuneCountInString(key) > maxKeyLen:
		return fmt.Sprintf("the key is longer than %d characters", maxKeyLen)
	}
	return ""
}

// Write implements stores.Adapter. The value (and the note, if given) are
// encrypted with the organisation key before they leave scrim. An existing
// secret keeps its key, note and project unless a note is given; a new one
// is created in the project the reference names.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if !noSelectors(ref) {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrInvalidRef, "Secrets Manager references take no selectors")
	}
	val, ok := fields[FieldValue]
	if !ok {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrInvalidRef, "a write needs the field %s", FieldValue)
	}
	note, hasNote := fields[FieldNote]
	for f := range fields {
		if f != FieldValue && f != FieldNote {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrInvalidRef, "a Secrets Manager secret has only the fields %s and %s", FieldValue, FieldNote)
		}
	}
	if why := storable(val, maxValueLen, false); why != "" {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnsupported, "%s", why)
	}
	if hasNote {
		if why := storable(note, maxNoteLen, true); why != "" {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnsupported, "note: %s", why)
		}
	}
	loc, ok := parseLocation(ref.Path)
	if !ok {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrInvalidRef, refForms)
	}

	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	ix, err := a.loadIndex(ctx)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	key := a.c.key()
	encVal, err := key.Encrypt(val)
	if err != nil {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnavailable, "cannot encrypt: %v", err)
	}
	if tooLong(encVal, maxValueEnc) {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnsupported, "the encrypted value would exceed the server's %d-character limit", maxValueEnc)
	}
	var encNote string
	if hasNote {
		en, err := key.Encrypt(note)
		if err != nil {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnavailable, "cannot encrypt: %v", err)
		}
		if tooLong(en, maxNoteEnc) {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnsupported, "the encrypted note would exceed the server's %d-character limit", maxNoteEnc)
		}
		encNote = en.String()
	}

	existing, err := a.resolve(stores.OpWrite, ref, ix)
	var resp apiSecret
	switch {
	case err == nil:
		if opts.CreateOnly {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrConflict, "the secret exists")
		}
		// The update replaces every field, so the current key and note
		// ciphertexts are sent back unchanged; neither is decrypted.
		var cur apiSecret
		if err := a.c.call(ctx, "GET", "/secrets/"+existing.id, nil, nil, &cur); err != nil {
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
		}
		if !hasNote {
			encNote = cur.Note
		}
		pids := make([]string, 0, len(cur.Projects))
		for _, p := range cur.Projects {
			pids = append(pids, p.ID)
		}
		changed := true
		body := apiSecretWrite{Key: cur.Key, Value: encVal.String(), Note: encNote, ProjectIDs: pids, ValueChanged: &changed}
		if err := a.c.call(ctx, "PUT", "/secrets/"+existing.id, nil, body, &resp); err != nil {
			return stores.Metadata{}, a.writeFail(ref, err)
		}
		if len(resp.Projects) == 0 {
			// The server leaves a secret's project alone when the update
			// names the same one, and then answers without projects.
			resp.Projects = cur.Projects
		}
	case errors.Is(err, stores.ErrNotFound) && loc.id == "":
		p, perr := a.project(stores.OpWrite, ref, ix, loc.projectSel)
		if perr != nil {
			return stores.Metadata{}, perr
		}
		if why := validKey(loc.key); why != "" {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrInvalidRef, "%s", why)
		}
		encKey, kerr := key.EncryptMetadata(loc.key)
		if kerr != nil {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnavailable, "cannot encrypt: %v", kerr)
		}
		if tooLong(encKey, maxKeyEnc) {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrInvalidRef, "the encrypted key would exceed the server's %d-character limit", maxKeyEnc)
		}
		if !hasNote {
			en, nerr := key.EncryptMetadata("")
			if nerr != nil {
				return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnavailable, "cannot encrypt: %v", nerr)
			}
			encNote = en.String()
		}
		body := apiSecretWrite{Key: encKey.String(), Value: encVal.String(), Note: encNote, ProjectIDs: []string{p.id}}
		if err := a.c.call(ctx, "POST", "/organizations/"+ix.org+"/secrets", nil, body, &resp); err != nil {
			return stores.Metadata{}, a.writeFail(ref, err)
		}
	default:
		return stores.Metadata{}, err
	}
	e := entry{id: strings.ToLower(resp.ID), org: strings.ToLower(resp.OrganizationID), created: resp.CreationDate.Time, revised: resp.RevisionDate.Time}
	if e.key, err = key.DecryptMetadata(resp.Key); err != nil {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnavailable, "the secret was written but its key does not decrypt: %v", err)
	}
	for _, p := range resp.Projects {
		e.projectIDs = append(e.projectIDs, strings.ToLower(p.ID))
	}
	return a.meta(ref, e, ix), nil
}

// writeFail classifies a failed create or update. The server answers 404
// when the machine account may not write (SecretsController throws
// NotFoundException on a failed authorisation), but the project or secret
// was just seen in the index, so a 404 here is a permission refusal.
func (a *Adapter) writeFail(ref stores.Ref, err error) error {
	if errors.Is(err, stores.ErrNotFound) {
		return a.errorf(stores.OpWrite, ref, stores.ErrPermission, "the machine account may not write here (Bitwarden answered not found)")
	}
	return a.fail(stores.OpWrite, ref, err)
}

// tooLong reports whether an encrypted string exceeds the server's limit.
func tooLong(e bwcrypto.EncString, limit int) bool { return len(e.String()) > limit }

// apiTime is a server timestamp. The API sends RFC 3339 with an offset;
// one without is read as UTC rather than refused.
type apiTime struct{ time.Time }

func (t *apiTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if v, err := time.Parse(layout, s); err == nil {
			t.Time = v.UTC()
			return nil
		}
	}
	return fmt.Errorf("bws: bad timestamp %q", s)
}

// key returns the organisation key. It is valid once a session exists.
func (c *client) key() bwcrypto.SymmetricKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.orgKey
}
