// SPDX-License-Identifier: AGPL-3.0-only

// Package gcpsm is the store adapter for Google Secret Manager
// (specs/secret-stores, "Google Secret Manager adapter"), addressed as
//
//	<scheme>://<path>[?version=<n|latest|alias>][#field]
//
// The path's segments, joined with the path separator ("--" by default),
// form the secret ID in the configured project (and region, for regional
// secrets): `gsm://agents/github` is the secret `agents--github`. A secret
// holds one payload, exposed as the field "value", or with format json as
// the string fields of a JSON object.
//
// The adapter talks to the Secret Manager REST API with a small typed
// client instead of the Google Cloud Go SDK: the SDK pulls in gRPC
// transports, generated protobuf types and the google.golang.org/api tree
// for the handful of calls scrim needs. Payloads travel between the HTTP
// body and secret.Value through package wire and are never converted to
// strings. Tokens come from golang.org/x/oauth2/google, which implements
// Application Default Credentials (service account keys, workload identity
// federation, GKE workload identity through the metadata server, gcloud
// user credentials and impersonated service accounts); x/oauth2 holds the
// access token as a string, which is the one exception.
package gcpsm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/agentcache"
	"github.com/heliopsy/scrim/internal/stores/internal/flatname"
	"github.com/heliopsy/scrim/internal/stores/internal/poll"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Kind is the adapter kind this package registers.
const Kind = "gcpsm"

// Field is the name of the single field of a raw-format secret.
const Field = "value"

// maxPayload is Secret Manager's payload limit.
const maxPayload = 64 << 10

var errMaxPayload = errors.New("payloads are at most 64 KiB in Secret Manager")

// listConcurrency bounds the version lookups a listing makes at once.
const listConcurrency = 8

func init() {
	stores.DeclareMulti(Kind, multiAttrs...)
	stores.DeclareAgentWriteCheck(Kind)
	stores.Register(Kind, New)
}

var (
	// versionPattern is a version number, "latest" or a version alias.
	versionPattern = regexp.MustCompile(`^([1-9][0-9]{0,18}|[A-Za-z][A-Za-z0-9_-]{0,62})$`)
	castagnoli     = crc32.MakeTable(crc32.Castagnoli)
)

// Adapter is one configured Google Secret Manager instance.
type Adapter struct {
	name  string
	s     *settings
	c     *client
	names flatname.Mapper
	// agents caches the access tokens agents' own identities were
	// exchanged for (agent.go).
	agents *agentcache.Cache[secret.Value]
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.WriteLabeler     = (*Adapter)(nil)
)

// New builds an adapter from its configuration. It validates the options and
// neither resolves credentials nor contacts Google.
func New(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
	return newAdapter(inst, nil, "")
}

// newAdapter builds an adapter; tests pass a transport and an IAM
// Credentials endpoint that reach fakes.
func newAdapter(inst stores.Instance, rt http.RoundTripper, iam string) (*Adapter, error) {
	s, err := decodeSettings(inst)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	if rt == nil {
		rt = http.DefaultTransport.(*http.Transport).Clone()
	}
	hc := &http.Client{Transport: rt, Timeout: s.timeout}
	auth := newAuthenticator(s, hc)
	if iam != "" {
		auth.iam = iam
	}
	return &Adapter{
		name:   inst.Name,
		s:      s,
		c:      &client{base: s.endpoint, http: hc, auth: auth},
		names:  flatname.Mapper{Sep: s.sep, Valid: validIDByte, MaxLen: 255},
		agents: agentcache.New(clone, secret.Value.Wipe),
	}, nil
}

// validIDByte: secret IDs are ASCII letters, digits, '-' and '_'.
func validIDByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
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
func (a *Adapter) Credentials() []secret.Value { return a.c.auth.credentials() }

// Close implements stores.Adapter.
func (a *Adapter) Close() error {
	a.c.auth.close()
	a.agents.Close()
	a.c.http.CloseIdleConnections()
	return nil
}

func (a *Adapter) fail(op stores.Op, ref stores.Ref, err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: ae.kind, Detail: ae.msg, Cause: ae.cause}
	}
	var au *authError
	if errors.As(err, &au) {
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: au.kind, Detail: au.msg}
	}
	var se *stores.Error
	if errors.As(err, &se) {
		return se
	}
	return stores.NewError(a.name, op, ref, stores.ErrUnavailable, err)
}

func (a *Adapter) errorf(op stores.Op, ref stores.Ref, kind error, detail string) error {
	return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: kind, Detail: detail}
}

// writeOnly reports whether p is under a configured write-only prefix.
func (a *Adapter) writeOnly(p string) bool {
	for _, w := range a.s.writeOnly {
		if p == w || strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

// project returns the project secrets live in: the configured one, or the
// one the credentials name.
func (a *Adapter) project(ctx context.Context) (string, error) {
	if a.s.project != "" {
		return a.s.project, nil
	}
	p, err := a.c.auth.projectID(ctx)
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", &apiError{kind: stores.ErrInvalidRef, msg: "option " + optProject + " is required: the credentials name no project"}
	}
	return p, nil
}

// parent is the collection secrets live in: projects/<p> or
// projects/<p>/locations/<l>.
func (a *Adapter) parent(ctx context.Context) (string, string, error) {
	p, err := a.project(ctx)
	if err != nil {
		return "", "", err
	}
	if a.s.location != "" {
		return "projects/" + p + "/locations/" + a.s.location, p, nil
	}
	return "projects/" + p, p, nil
}

// apiSecret is a Secret resource. It holds no value.
type apiSecret struct {
	Name        string            `json:"name"`
	CreateTime  time.Time         `json:"createTime"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Replication *struct {
		Automatic *struct {
			CustomerManagedEncryption *cmek `json:"customerManagedEncryption"`
		} `json:"automatic"`
		UserManaged *struct {
			Replicas []struct {
				Location                  string `json:"location"`
				CustomerManagedEncryption *cmek  `json:"customerManagedEncryption"`
			} `json:"replicas"`
		} `json:"userManaged"`
	} `json:"replication"`
	// CustomerManagedEncryption is set on regional secrets.
	CustomerManagedEncryption *cmek `json:"customerManagedEncryption"`
	Topics                    []struct {
		Name string `json:"name"`
	} `json:"topics"`
	ExpireTime time.Time `json:"expireTime"`
	Etag       string    `json:"etag"`
	Rotation   *struct {
		NextRotationTime time.Time `json:"nextRotationTime"`
		RotationPeriod   string    `json:"rotationPeriod"`
	} `json:"rotation"`
	VersionAliases map[string]int64Str `json:"versionAliases"`
}

type cmek struct {
	KmsKeyName string `json:"kmsKeyName"`
}

// int64Str is an int64 that proto3 JSON writes as a string.
type int64Str string

func (n *int64Str) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*n = int64Str(s)
		return nil
	}
	var i json.Number
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	*n = int64Str(i.String())
	return nil
}

// apiVersion is a SecretVersion resource. It holds no value.
type apiVersion struct {
	Name       string    `json:"name"`
	CreateTime time.Time `json:"createTime"`
	State      string    `json:"state"`
}

// lastSegment is the part of a resource name after its last '/'.
func lastSegment(name string) string { return name[strings.LastIndexByte(name, '/')+1:] }

// target is a secret reference resolved to Secret Manager names.
type target struct {
	id      string // secret ID
	path    string // projects/<p>[/locations/<l>]/secrets/<id>
	project string
	version string // "latest", a number or an alias
}

// resolve checks ref's path, selector and field for op.
func (a *Adapter) resolve(ctx context.Context, op stores.Op, ref stores.Ref) (target, error) {
	id, err := a.names.Name(ref.Path)
	if err != nil {
		return target{}, a.errorf(op, ref, stores.ErrInvalidRef, err.Error()+" (secret IDs are letters, digits, '-' and '_'; path segments are joined with "+a.s.sep+")")
	}
	t := target{id: id, version: "latest"}
	if ref.Selectors != "" {
		q, _ := url.ParseQuery(ref.Selectors)
		for k := range q {
			if k != "version" {
				return target{}, a.errorf(op, ref, stores.ErrInvalidRef, "unknown selector "+strconv.Quote(k)+" (supported: version)")
			}
		}
		t.version = q.Get("version")
		if !versionPattern.MatchString(t.version) {
			return target{}, a.errorf(op, ref, stores.ErrInvalidRef, "version must be a version number, latest or a version alias")
		}
	}
	parent, project, err := a.parent(ctx)
	if err != nil {
		return target{}, a.fail(op, ref, err)
	}
	t.path, t.project = parent+"/secrets/"+id, project
	return t, nil
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if a.writeOnly(ref.Path) {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrPermission, "the path is configured write-only; scrim never reads it back")
	}
	if a.s.format == formatRaw && ref.Field != "" && ref.Field != Field {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrNotFound, "raw secrets hold a single field named "+Field)
	}
	t, err := a.resolve(ctx, stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	var sec apiSecret
	if err := a.c.getJSON(ctx, http.MethodGet, t.path, nil, &sec); err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	b, err := a.c.do(ctx, http.MethodGet, t.path+"/versions/"+t.version+":access", nil, nil, nil)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	defer secret.WipeBytes(b)
	var resp struct {
		Name    string `json:"name"`
		Payload struct {
			Data       wire.Raw  `json:"data"`
			DataCrc32c *int64Str `json:"dataCrc32c"`
		} `json:"payload"`
	}
	err = json.Unmarshal(b, &resp)
	defer resp.Payload.Data.Wipe()
	if err != nil {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrUnavailable, "malformed access response")
	}
	payload, err := decodePayload(resp.Payload.Data, resp.Payload.DataCrc32c)
	if err != nil {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrUnavailable, err.Error())
	}
	defer secret.WipeBytes(payload)
	fields, err := a.fields(payload)
	if err != nil {
		return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrUnsupported, err.Error())
	}
	version := lastSegment(resp.Name)
	ver := &apiVersion{Name: resp.Name, State: "ENABLED"}
	m := a.meta(ref, t, &sec, ver, version)
	m.Fields = slices.Sorted(maps.Keys(fields))
	if ref.Field != "" {
		v, ok := fields[ref.Field]
		for k, o := range fields {
			if k != ref.Field {
				o.Wipe()
			}
		}
		if !ok {
			return stores.Secret{}, a.errorf(stores.OpRead, ref, stores.ErrNotFound, "the secret has no field "+strconv.Quote(ref.Field))
		}
		fields = map[string]secret.Value{ref.Field: v}
	}
	return stores.Secret{Meta: m, Fields: fields}, nil
}

// decodePayload turns the base64 payload of an access response into bytes
// and checks its CRC32C when Google sent one.
func decodePayload(data wire.Raw, crc *int64Str) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	q, err := wire.Unquote(data)
	if err != nil {
		return nil, errors.New("malformed payload")
	}
	defer secret.WipeBytes(q)
	out, err := base64.StdEncoding.AppendDecode(make([]byte, 0, base64.StdEncoding.DecodedLen(len(q))), q)
	if err != nil {
		secret.WipeBytes(out)
		return nil, errors.New("payload is not base64")
	}
	if crc != nil {
		want, err := strconv.ParseInt(string(*crc), 10, 64)
		if err != nil || uint32(want) != crc32.Checksum(out, castagnoli) || want>>32 != 0 {
			secret.WipeBytes(out)
			return nil, errors.New("payload failed its CRC32C check")
		}
	}
	return out, nil
}

// fields splits a payload into fields according to the format.
func (a *Adapter) fields(payload []byte) (map[string]secret.Value, error) {
	if a.s.format == formatRaw {
		return map[string]secret.Value{Field: secret.New(payload)}, nil
	}
	var obj map[string]wire.Raw
	err := json.Unmarshal(payload, &obj)
	defer func() {
		for _, r := range obj {
			r.Wipe()
		}
	}()
	if err != nil || obj == nil {
		return nil, errors.New("the payload is not a JSON object (format json); use format raw for this store")
	}
	out := make(map[string]secret.Value, len(obj))
	for k, r := range obj {
		v, err := r.Value()
		if err != nil {
			// A null field holds no value to redact or inject.
			continue
		}
		out[k] = v
	}
	return out, nil
}

// meta builds the metadata of the secret at ref.
func (a *Adapter) meta(ref stores.Ref, t target, sec *apiSecret, ver *apiVersion, version string) stores.Metadata {
	m := stores.Metadata{
		Ref:       ref.Secret(),
		Version:   version,
		CreatedAt: sec.CreateTime,
		Labels:    a.labels(t.project, ref.Path, sec, ver, version),
		WriteOnly: a.writeOnly(ref.Path),
	}
	if ver != nil {
		m.UpdatedAt = ver.CreateTime
	}
	if m.Ref.Selectors != "" {
		m.Ref.Selectors = ""
	}
	if a.s.format == formatRaw {
		m.Fields = []string{Field}
	}
	return m
}

// ReadMetadata implements stores.MetadataReader with the Secret and
// SecretVersion resources (secrets.get and versions.get), which never carry
// the payload. The labels are the ones Read reports for an enabled version,
// and errors are Read's.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	t, err := a.resolve(ctx, stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	var sec apiSecret
	if err := a.c.getJSON(ctx, http.MethodGet, t.path, nil, &sec); err != nil {
		return stores.Metadata{}, a.fail(stores.OpRead, ref, err)
	}
	var ver apiVersion
	if err := a.c.getJSON(ctx, http.MethodGet, t.path+"/versions/"+t.version, nil, &ver); err != nil {
		return stores.Metadata{}, a.fail(stores.OpRead, ref, err)
	}
	if ver.State != "ENABLED" {
		return stores.Metadata{}, a.errorf(stores.OpRead, ref, stores.ErrNotFound, "version "+lastSegment(ver.Name)+" is "+strings.ToLower(ver.State))
	}
	return a.meta(ref, t, &sec, &ver, lastSegment(ver.Name)), nil
}

// List implements stores.Adapter. It lists secrets (no payloads) and looks
// up the latest version of each one under the prefix, so the refresher and
// the watch see rotations without reading values. Secrets whose latest
// version is not enabled, or that have none, are left out: there is
// nothing to read.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	pfx := flatname.ParsePrefix(prefix.Path)
	parent, project, err := a.parent(ctx)
	if err != nil {
		return nil, a.fail(stores.OpList, prefix, err)
	}
	type item struct {
		path string
		sec  apiSecret
		ver  apiVersion
		ok   bool
	}
	var items []*item
	q := url.Values{"pageSize": {"250"}}
	for {
		var page struct {
			Secrets       []apiSecret `json:"secrets"`
			NextPageToken string      `json:"nextPageToken"`
		}
		if err := a.c.getJSON(ctx, http.MethodGet, parent+"/secrets", q, &page); err != nil {
			return nil, a.fail(stores.OpList, prefix, err)
		}
		for _, s := range page.Secrets {
			p, ok := a.names.Path(lastSegment(s.Name))
			if ok && pfx.Match(p) {
				items = append(items, &item{path: p, sec: s})
			}
		}
		if page.NextPageToken == "" {
			break
		}
		q.Set("pageToken", page.NextPageToken)
	}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
		sem   = make(chan struct{}, listConcurrency)
	)
	for _, it := range items {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			var v apiVersion
			err := a.c.getJSON(ctx, http.MethodGet, parent+"/secrets/"+lastSegment(it.sec.Name)+"/versions/latest", nil, &v)
			switch {
			case err == nil:
				it.ver, it.ok = v, v.State == "ENABLED"
			case errors.Is(err, stores.ErrNotFound):
				// Deleted since the listing, or no version yet.
			default:
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if first != nil {
		return nil, a.fail(stores.OpList, prefix, first)
	}
	out := make([]stores.Metadata, 0, len(items))
	for _, it := range items {
		if !it.ok {
			continue
		}
		ref := stores.Ref{Scheme: prefix.Scheme, Path: it.path}
		t := target{id: lastSegment(it.sec.Name), project: project}
		out = append(out, a.meta(ref, t, &it.sec, &it.ver, lastSegment(it.ver.Name)))
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out, nil
}

// Watch implements stores.Adapter by polling the listing (names, versions
// and labels, never payloads) every watch.interval. A new version, a
// deleted secret and a change of labels or annotations are reported.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	return poll.Watch(ctx, prefix.Scheme, a.s.watchInterval, a.s.watchBackoff, func(ctx context.Context) (map[string]string, error) {
		ms, err := a.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		out := make(map[string]string, len(ms))
		for _, m := range ms {
			out[m.Ref.Path] = m.Version + "@" + fingerprint(m.Labels)
		}
		return out, nil
	})
}

// Write implements stores.Adapter: a new version of the secret, creating
// the secret first when it does not exist. WriteOptions.Labels replace the
// secret's annotations (keys under gcpsm. are dropped); nil leaves them.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if ref.Selectors != "" {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrInvalidRef, "a write takes no selector")
	}
	if a.s.readOnly {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnsupported, "the store is configured read-only")
	}
	payload, err := a.encode(fields)
	if err != nil {
		return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnsupported, err.Error())
	}
	defer secret.WipeBytes(payload)
	t, err := a.resolve(ctx, stores.OpWrite, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	involved := slices.Collect(maps.Values(fields))
	annotations := writable(opts.Labels)

	created := false
	if opts.CreateOnly {
		if err := a.create(ctx, t, annotations); err != nil {
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
		}
		created = true
	}
	ver, err := a.addVersion(ctx, t, payload, involved)
	if !created && errors.Is(err, stores.ErrNotFound) {
		cerr := a.create(ctx, t, annotations)
		switch {
		case cerr == nil:
			created = true
			ver, err = a.addVersion(ctx, t, payload, involved)
		case errors.Is(cerr, stores.ErrConflict):
			// Created concurrently: add the version to it.
			ver, err = a.addVersion(ctx, t, payload, involved)
		default:
			err = cerr
		}
	}
	if err != nil {
		if created {
			// Leave no empty secret behind a refused version.
			_ = a.c.getJSON(ctx, http.MethodDelete, t.path, nil, nil)
		}
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	var sec apiSecret
	if annotations != nil && !created {
		body, _ := json.Marshal(map[string]any{"annotations": annotations})
		b, err := a.c.do(ctx, http.MethodPatch, t.path, url.Values{"updateMask": {"annotations"}}, wire.NewBody(body), nil)
		if err != nil {
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
		}
		err = json.Unmarshal(b, &sec)
		secret.WipeBytes(b)
		if err != nil {
			return stores.Metadata{}, a.errorf(stores.OpWrite, ref, stores.ErrUnavailable, "malformed update response")
		}
	} else if err := a.c.getJSON(ctx, http.MethodGet, t.path, nil, &sec); err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	m := a.meta(ref, t, &sec, &ver, lastSegment(ver.Name))
	m.Fields = slices.Sorted(maps.Keys(fields))
	return m, nil
}

// encode builds the payload of fields according to the format.
func (a *Adapter) encode(fields map[string]secret.Value) ([]byte, error) {
	if a.s.format == formatRaw {
		v, ok := fields[Field]
		if !ok || len(fields) != 1 {
			return nil, errors.New("raw secrets hold a single field named " + Field + ", got fields " + strings.Join(slices.Sorted(maps.Keys(fields)), ","))
		}
		var out []byte
		_ = v.Expose(func(b []byte) error { out = append([]byte{}, b...); return nil })
		if len(out) > maxPayload {
			secret.WipeBytes(out)
			return nil, errMaxPayload
		}
		return out, nil
	}
	if len(fields) == 0 {
		return nil, errors.New("a JSON secret needs at least one field")
	}
	buf := []byte{'{'}
	for i, k := range slices.Sorted(maps.Keys(fields)) {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf, _ = wire.AppendJSON(buf, k)
		buf = append(buf, ':')
		var err error
		if buf, err = wire.AppendValue(buf, fields[k]); err != nil {
			secret.WipeBytes(buf)
			return nil, errors.New("format json stores text: field " + strconv.Quote(k) + " is not valid UTF-8")
		}
	}
	buf = append(buf, '}')
	if len(buf) > maxPayload {
		secret.WipeBytes(buf)
		return nil, errMaxPayload
	}
	return buf, nil
}

// create creates the secret with no version.
func (a *Adapter) create(ctx context.Context, t target, annotations map[string]string) error {
	body := map[string]any{}
	if a.s.location == "" {
		if len(a.s.replicas) > 0 {
			rs := make([]map[string]string, len(a.s.replicas))
			for i, l := range a.s.replicas {
				rs[i] = map[string]string{"location": l}
			}
			body["replication"] = map[string]any{"userManaged": map[string]any{"replicas": rs}}
		} else {
			body["replication"] = map[string]any{"automatic": map[string]any{}}
		}
	}
	if len(annotations) > 0 {
		body["annotations"] = annotations
	}
	b, _ := json.Marshal(body)
	parent := strings.TrimSuffix(t.path, "/secrets/"+t.id)
	out, err := a.c.do(ctx, http.MethodPost, parent+"/secrets", url.Values{"secretId": {t.id}}, wire.NewBody(b), nil)
	secret.WipeBytes(out)
	return err
}

// addVersion adds payload as a new version, with its CRC32C so Google can
// refuse a corrupted upload.
func (a *Adapter) addVersion(ctx context.Context, t target, payload []byte, involved []secret.Value) (apiVersion, error) {
	buf := make([]byte, 0, 64+base64.StdEncoding.EncodedLen(len(payload)))
	buf = append(buf, `{"payload":{"data":"`...)
	buf = base64.StdEncoding.AppendEncode(buf, payload)
	buf = append(buf, `","dataCrc32c":"`...)
	buf = strconv.AppendUint(buf, uint64(crc32.Checksum(payload, castagnoli)), 10)
	buf = append(buf, `"}}`...)
	body := wire.NewBody(buf)
	defer body.Wipe()
	b, err := a.c.do(ctx, http.MethodPost, t.path+":addVersion", nil, body, involved)
	if err != nil {
		return apiVersion{}, err
	}
	defer secret.WipeBytes(b)
	var v apiVersion
	if err := json.Unmarshal(b, &v); err != nil || v.Name == "" {
		return apiVersion{}, &apiError{kind: stores.ErrUnavailable, msg: "malformed addVersion response"}
	}
	return v, nil
}

// writable drops labels in the gcpsm. namespace from a write: they are
// derived from Secret Manager's own attributes and are not stored as
// annotations, where they could only pose as native keys.
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

// Health implements stores.Adapter: Google answers and accepts the
// credentials. A listing refused with 403 still proves both (the identity
// may only access some secrets); 401 does not.
func (a *Adapter) Health(ctx context.Context) error {
	parent, _, err := a.parent(ctx)
	if err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	err = a.c.getJSON(ctx, http.MethodGet, parent+"/secrets", url.Values{"pageSize": {"1"}}, nil)
	var ae *apiError
	if errors.As(err, &ae) && ae.status == http.StatusForbidden {
		return nil
	}
	if err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}
