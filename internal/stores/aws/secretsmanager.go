// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// SecretsManager is one configured AWS Secrets Manager instance.
//
// A reference path is the secret's name (or its ARN). A secret whose
// string is a JSON object has one field per member; any other string, and a
// binary secret, has the single field "value". `?version=<id>` reads a
// version by its version ID, `?stage=<label>` by a staging label
// (AWSCURRENT, AWSPREVIOUS, AWSPENDING or a label of your own).
type SecretsManager struct{ base }

var (
	_ stores.Adapter          = (*SecretsManager)(nil)
	_ stores.CredentialHolder = (*SecretsManager)(nil)
	_ stores.MetadataReader   = (*SecretsManager)(nil)
	_ stores.WriteLabeler     = (*SecretsManager)(nil)
)

// NewSecretsManager builds an awssm adapter. It validates the options and
// does not resolve credentials or contact AWS.
func NewSecretsManager(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
	s, err := decodeSettings(inst, KindSecretsManager)
	if err != nil {
		return nil, configError(inst.Name, err)
	}
	return &SecretsManager{base{name: inst.Name, kind: KindSecretsManager, s: s, c: newClient(s, "secretsmanager", "secretsmanager"), agents: newAgentCache()}}, nil
}

// smName matches a secret name, or a secret ARN.
var smName = regexp.MustCompile(`^([A-Za-z0-9/_+=.@-]{1,512}|arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+)$`)

const (
	stageCurrent = "AWSCURRENT"
	smMaxValue   = 65536
)

// smSecret is a secret as ListSecrets and DescribeSecret return it.
// Description is free text and is not decoded.
type smSecret struct {
	ARN               string              `json:"ARN"`
	Name              string              `json:"Name"`
	KmsKeyID          string              `json:"KmsKeyId"`
	RotationEnabled   *bool               `json:"RotationEnabled"`
	RotationLambdaARN string              `json:"RotationLambdaARN"`
	OwningService     string              `json:"OwningService"`
	PrimaryRegion     string              `json:"PrimaryRegion"`
	CreatedDate       epoch               `json:"CreatedDate"`
	LastChangedDate   epoch               `json:"LastChangedDate"`
	LastRotatedDate   epoch               `json:"LastRotatedDate"`
	DeletedDate       epoch               `json:"DeletedDate"`
	Tags              []tag               `json:"Tags"`
	VersionIDsStages  map[string][]string `json:"VersionIdsToStages"`     // DescribeSecret
	VersionsToStages  map[string][]string `json:"SecretVersionsToStages"` // ListSecrets
}

func (x *smSecret) stages() map[string][]string {
	if x.VersionIDsStages != nil {
		return x.VersionIDsStages
	}
	return x.VersionsToStages
}

// versionWith returns the version holding stage, or "".
func (x *smSecret) versionWith(stage string) string {
	for v, st := range x.stages() {
		if slices.Contains(st, stage) {
			return v
		}
	}
	return ""
}

// selection is what a reference's selectors ask for.
type selection struct {
	version, stage string
}

func (a *SecretsManager) selectors(op stores.Op, ref stores.Ref) (selection, error) {
	var sel selection
	if ref.Selectors == "" {
		return sel, nil
	}
	q, _ := url.ParseQuery(ref.Selectors)
	for k := range q {
		switch k {
		case "version":
			sel.version = q.Get(k)
		case "stage":
			sel.stage = q.Get(k)
		default:
			return sel, a.invalid(op, ref, "unknown selector "+strconv.Quote(k)+" (supported: version, stage)")
		}
	}
	return sel, nil
}

func (a *SecretsManager) secretName(op stores.Op, ref stores.Ref) (string, error) {
	if !smName.MatchString(ref.Path) {
		return "", a.invalid(op, ref, "a secret name is 1 to 512 letters, digits and /_+=.@- (or a secret ARN)")
	}
	return ref.Path, nil
}

// describe returns the secret's metadata. A secret scheduled for deletion
// reads as not found.
func (a *SecretsManager) describe(ctx context.Context, op stores.Op, ref stores.Ref, name string) (*smSecret, error) {
	body, err := jsonBody(map[string]any{"SecretId": name}, "", nil, false)
	if err != nil {
		return nil, a.invalid(op, ref, "cannot encode the request")
	}
	b, err := a.c.call(ctx, "DescribeSecret", body, false)
	if err != nil {
		return nil, a.fail(op, ref, err)
	}
	var x smSecret
	err = json.Unmarshal(b, &x)
	secret.WipeBytes(b)
	if err != nil {
		return nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrUnavailable, Detail: "cannot decode DescribeSecret", Cause: err}
	}
	if !x.DeletedDate.IsZero() {
		return nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrNotFound, Detail: "the secret is scheduled for deletion"}
	}
	return &x, nil
}

// labels builds the labels of x with stages as the staging labels of the
// version addressed.
func (a *SecretsManager) labels(x *smSecret, stages []string) map[string]string {
	out := map[string]string{}
	k := KindSecretsManager
	stores.SetNative(out, k, "name", x.Name)
	stores.SetNative(out, k, "arn", x.ARN)
	stores.SetNative(out, k, "account", accountOf(x.ARN))
	stores.SetNative(out, k, "region", regionOf(x.ARN, a.region()))
	stores.SetNative(out, k, "stage", stages...)
	stores.SetNative(out, k, "kms-key", x.KmsKeyID)
	if x.RotationEnabled != nil {
		setBool(out, k, "rotation", *x.RotationEnabled)
		if *x.RotationEnabled {
			stores.SetNative(out, k, "rotation.lambda", x.RotationLambdaARN)
		}
	}
	setTime(out, k, "rotated", x.LastRotatedDate.Time)
	stores.SetNative(out, k, "owning-service", x.OwningService)
	stores.SetNative(out, k, "primary-region", x.PrimaryRegion)
	setTime(out, k, "created", x.CreatedDate.Time)
	setTime(out, k, "changed", x.LastChangedDate.Time)
	tagLabels(out, k, x.Tags)
	return out
}

// regionOf returns the region of an ARN, or def.
func regionOf(arn, def string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[3] != "" {
		return parts[3]
	}
	return def
}

// resolve finds the version a selection addresses in x, and its staging
// labels. A version ID that Secrets Manager no longer lists (deprecated,
// no staging label) is returned with no labels; GetSecretValue decides.
func (a *SecretsManager) resolve(op stores.Op, ref stores.Ref, x *smSecret, sel selection) (string, []string, error) {
	versions := x.stages()
	switch {
	case sel.version != "":
		// Version IDs are 32 to 64 characters; anything else names no
		// version.
		if n := len(sel.version); n < 32 || n > 64 {
			return "", nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrNotFound, Detail: "no such version"}
		}
		st := versions[sel.version]
		if sel.stage != "" && !slices.Contains(st, sel.stage) {
			return "", nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrNotFound, Detail: "the version does not hold that staging label"}
		}
		return sel.version, st, nil
	default:
		stage := sel.stage
		if stage == "" {
			stage = stageCurrent
		}
		v := x.versionWith(stage)
		if v == "" {
			return "", nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrNotFound, Detail: "no version holds staging label " + strconv.Quote(stage)}
		}
		return v, versions[v], nil
	}
}

func (x *smSecret) meta(ref stores.Ref, version string, labels map[string]string) stores.Metadata {
	return stores.Metadata{Ref: ref.Secret(), Version: version, CreatedAt: x.CreatedDate.Time, UpdatedAt: x.LastChangedDate.Time, Labels: labels}
}

// ReadMetadata implements stores.MetadataReader with DescribeSecret only:
// the labels Read reports, without asking for a value.
func (a *SecretsManager) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	sel, err := a.selectors(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	name, err := a.secretName(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	x, err := a.describe(ctx, stores.OpRead, ref, name)
	if err != nil {
		return stores.Metadata{}, err
	}
	v, stages, err := a.resolve(stores.OpRead, ref, x, sel)
	if err != nil {
		return stores.Metadata{}, err
	}
	return x.meta(ref, v, a.labels(x, stages)), nil
}

// smValue is GetSecretValue's answer. SecretString and SecretBinary stay
// raw JSON, never Go strings, and print as a marker.
type smValue struct {
	ARN           string   `json:"ARN"`
	Name          string   `json:"Name"`
	VersionID     string   `json:"VersionId"`
	VersionStages []string `json:"VersionStages"`
	CreatedDate   epoch    `json:"CreatedDate"`
	SecretString  wire.Raw `json:"SecretString"`
	SecretBinary  wire.Raw `json:"SecretBinary"`
}

func (v *smValue) wipe() {
	v.SecretString.Wipe()
	v.SecretBinary.Wipe()
}

// Read implements stores.Adapter: DescribeSecret for the labels, then
// GetSecretValue for the version addressed.
func (a *SecretsManager) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	sel, err := a.selectors(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	name, err := a.secretName(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	x, err := a.describe(ctx, stores.OpRead, ref, name)
	if err != nil {
		return stores.Secret{}, err
	}
	vid, _, err := a.resolve(stores.OpRead, ref, x, sel)
	if err != nil {
		return stores.Secret{}, err
	}
	head := map[string]any{"SecretId": name, "VersionId": vid}
	body, err := jsonBody(head, "", nil, false)
	if err != nil {
		return stores.Secret{}, a.invalid(stores.OpRead, ref, "cannot encode the request")
	}
	b, err := a.c.call(ctx, "GetSecretValue", body, false)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	var got smValue
	err = json.Unmarshal(b, &got)
	secret.WipeBytes(b)
	defer got.wipe()
	if err != nil {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrUnavailable, Detail: "cannot decode GetSecretValue"}
	}
	fields, err := smFields(&got)
	if err != nil {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrUnavailable, Detail: err.Error()}
	}
	sec := stores.Secret{Meta: x.meta(ref, got.VersionID, a.labels(x, got.VersionStages)), Fields: fields}
	sec.Meta.Fields = slices.Sorted(maps.Keys(fields))
	if !got.CreatedDate.IsZero() {
		sec.Meta.CreatedAt = got.CreatedDate.Time
	}
	if ref.Field != "" {
		v, ok := fields[ref.Field]
		if !ok {
			sec.Wipe()
			return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrNotFound, Detail: "the secret has no field " + strconv.Quote(ref.Field)}
		}
		for f, other := range fields {
			if f != ref.Field {
				other.Wipe()
			}
		}
		sec.Fields = map[string]secret.Value{ref.Field: v}
	}
	return sec, nil
}

type smError string

func (e smError) Error() string { return string(e) }

// smFields splits a secret into fields: the members of a JSON object, or
// the whole string or binary as "value". Member values that are not JSON
// strings keep their JSON text.
func smFields(v *smValue) (map[string]secret.Value, error) {
	switch {
	case len(v.SecretString) > 0 && !bytes.Equal(bytes.TrimSpace(v.SecretString), []byte("null")):
		s, err := wire.Unquote(bytes.TrimSpace(v.SecretString))
		if err != nil {
			return nil, smError("cannot decode SecretString")
		}
		defer secret.WipeBytes(s)
		if obj, ok := jsonObject(s); ok {
			return obj, nil
		}
		return map[string]secret.Value{Field: secret.New(s)}, nil
	case len(v.SecretBinary) > 0:
		q, err := wire.Unquote(bytes.TrimSpace(v.SecretBinary))
		if err != nil {
			return nil, smError("cannot decode SecretBinary")
		}
		defer secret.WipeBytes(q)
		out := make([]byte, base64.StdEncoding.DecodedLen(len(q)))
		n, err := base64.StdEncoding.Decode(out, q)
		if err != nil {
			secret.WipeBytes(out)
			return nil, smError("SecretBinary is not base64")
		}
		return map[string]secret.Value{Field: secret.Adopt(out[:n])}, nil
	}
	return nil, smError("the version holds neither SecretString nor SecretBinary")
}

// jsonObject decodes s as a JSON object of fields. It reports false for
// anything else (a plain string, an array, invalid JSON).
func jsonObject(s []byte) (map[string]secret.Value, bool) {
	t := bytes.TrimSpace(s)
	if len(t) < 2 || t[0] != '{' || !json.Valid(t) {
		return nil, false
	}
	var raw map[string]wire.Raw
	if err := json.Unmarshal(t, &raw); err != nil {
		return nil, false
	}
	out := make(map[string]secret.Value, len(raw))
	for k, r := range raw {
		v, err := r.Value()
		r.Wipe()
		if err != nil {
			// JSON null: no value to redact or inject.
			continue
		}
		out[k] = v
	}
	return out, true
}

// List implements stores.Adapter with ListSecrets: names, version IDs,
// staging labels and tags, never values.
func (a *SecretsManager) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	xs, err := a.list(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]stores.Metadata, 0, len(xs))
	for _, x := range xs {
		ref := stores.Ref{Scheme: prefix.Scheme, Path: x.Name}
		v := x.versionWith(stageCurrent)
		out = append(out, x.meta(ref, v, a.labels(x, x.stages()[v])))
	}
	return out, nil
}

func (a *SecretsManager) list(ctx context.Context, prefix stores.Ref) ([]*smSecret, error) {
	match, _ := listPrefix(prefix.Path)
	var out []*smSecret
	next := ""
	for {
		head := map[string]any{"MaxResults": 100}
		if match != "" {
			head["Filters"] = []map[string]any{{"Key": "name", "Values": []string{match}}}
		}
		if next != "" {
			head["NextToken"] = next
		}
		body, err := jsonBody(head, "", nil, false)
		if err != nil {
			return nil, a.invalid(stores.OpList, prefix, "cannot encode the request")
		}
		b, err := a.c.call(ctx, "ListSecrets", body, false)
		if err != nil {
			return nil, a.fail(stores.OpList, prefix, err)
		}
		var page struct {
			SecretList []*smSecret `json:"SecretList"`
			NextToken  string      `json:"NextToken"`
		}
		err = json.Unmarshal(b, &page)
		secret.WipeBytes(b)
		if err != nil {
			return nil, &stores.Error{Store: a.name, Op: stores.OpList, Ref: prefix, Kind: stores.ErrUnavailable, Detail: "cannot decode ListSecrets", Cause: err}
		}
		for _, x := range page.SecretList {
			// The name filter is a prefix match that AWS may apply without
			// regard to case; the listing is exact.
			if strings.HasPrefix(x.Name, match) && x.DeletedDate.IsZero() {
				out = append(out, x)
			}
		}
		if page.NextToken == "" || page.NextToken == next {
			return out, nil
		}
		next = page.NextToken
	}
}

// Watch implements stores.Adapter by polling ListSecrets.
func (a *SecretsManager) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	return a.watch(ctx, prefix, func(ctx context.Context, p stores.Ref) (map[string]string, error) {
		xs, err := a.list(ctx, p)
		if err != nil {
			return nil, err
		}
		out := make(map[string]string, len(xs))
		for _, x := range xs {
			out[x.Name] = x.versionWith(stageCurrent) + "@" + x.LastChangedDate.Format(time.RFC3339Nano)
		}
		return out, nil
	})
}

// WriteLabels implements stores.WriteLabeler: the name and region a secret
// written at ref would get.
func (a *SecretsManager) WriteLabels(ref stores.Ref) map[string]string {
	if !smName.MatchString(ref.Path) || strings.HasPrefix(ref.Path, "arn:") {
		return nil
	}
	out := map[string]string{}
	stores.SetNative(out, KindSecretsManager, "name", ref.Path)
	stores.SetNative(out, KindSecretsManager, "region", a.region())
	return out
}

// encodeSecret renders fields as the SecretString (or SecretBinary) of a
// new version: a single field named "value" is stored as it is, unless it
// is itself a JSON object (which would read back as fields) or not UTF-8
// (stored as binary); any other set of fields becomes a JSON object. The
// caller wipes the result.
func encodeSecret(fields map[string]secret.Value) (buf []byte, binary bool, err error) {
	if v, ok := fields[Field]; ok && len(fields) == 1 {
		var plain, utf bool
		_ = v.Expose(func(b []byte) error {
			utf = utf8.Valid(b)
			_, isObj := jsonObject(b)
			plain = !isObj && len(b) > 0
			if plain {
				buf = append([]byte(nil), b...)
			}
			return nil
		})
		if plain {
			return buf, !utf, nil
		}
	}
	buf = append(buf, '{')
	for i, name := range slices.Sorted(maps.Keys(fields)) {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf, _ = wire.AppendQuoted(buf, []byte(name))
		buf = append(buf, ':')
		if buf, err = wire.AppendValue(buf, fields[name]); err != nil {
			secret.WipeBytes(buf)
			return nil, false, smError("field " + strconv.Quote(name) + " is not valid UTF-8; only a single field named value may hold binary data")
		}
	}
	return append(buf, '}'), false, nil
}

// Write implements stores.Adapter: PutSecretValue for a new version of an
// existing secret, CreateSecret for a new one (unless create-secrets is
// off), and TagResource for the labels.
func (a *SecretsManager) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	ref.Selectors = ""
	name, err := a.secretName(stores.OpWrite, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	if len(fields) == 0 {
		return stores.Metadata{}, a.invalid(stores.OpWrite, ref, "no fields to write")
	}
	tags, bad := writeTags(KindSecretsManager, opts.Labels)
	if bad != "" {
		return stores.Metadata{}, a.unsupported(stores.OpWrite, ref, "label "+strconv.Quote(bad)+" cannot be an AWS tag key (at most 128 letters, digits, spaces and _.:/=+-@)")
	}
	val, binary, err := encodeSecret(fields)
	if err != nil {
		return stores.Metadata{}, a.unsupported(stores.OpWrite, ref, err.Error())
	}
	defer secret.WipeBytes(val)
	if len(val) > smMaxValue {
		return stores.Metadata{}, a.unsupported(stores.OpWrite, ref, "Secrets Manager holds at most 64 KiB per secret")
	}
	valField := "SecretString"
	if binary {
		valField = "SecretBinary"
	}

	var vid string
	if opts.CreateOnly {
		vid, err = a.create(ctx, name, valField, val, tags)
	} else {
		vid, err = a.put(ctx, name, valField, val)
		if isKind(err, stores.ErrNotFound) && a.s.createSecrets {
			vid, err = a.create(ctx, name, valField, val, tags)
			if isKind(err, stores.ErrConflict) {
				// Created concurrently: add a version instead.
				vid, err = a.put(ctx, name, valField, val)
			}
			tags = nil
		}
		if err == nil && len(tags) > 0 {
			err = a.tag(ctx, name, tags)
		}
	}
	if err != nil {
		e := a.fail(stores.OpWrite, ref, err)
		if isKind(err, stores.ErrNotFound) && !a.s.createSecrets {
			e.(*stores.Error).Detail = "the secret does not exist and create-secrets is off"
		}
		return stores.Metadata{}, e
	}
	return stores.Metadata{Ref: ref, Version: vid, Fields: slices.Sorted(maps.Keys(fields)), UpdatedAt: time.Now().UTC(), Labels: a.WriteLabels(ref)}, nil
}

func isKind(err, kind error) bool {
	ae, ok := err.(*apiError)
	return ok && ae.kind == kind && !ae.deleted
}

func (a *SecretsManager) put(ctx context.Context, name, valField string, val []byte) (string, error) {
	body, err := jsonBody(map[string]any{"SecretId": name, "ClientRequestToken": newToken()}, valField, val, valField == "SecretBinary")
	if err != nil {
		return "", &apiError{kind: stores.ErrUnsupported, msg: "cannot encode the value"}
	}
	defer body.Wipe()
	return a.versionCall(ctx, "PutSecretValue", body)
}

func (a *SecretsManager) create(ctx context.Context, name, valField string, val []byte, tags []tag) (string, error) {
	head := map[string]any{"Name": name, "ClientRequestToken": newToken()}
	if a.s.kmsKey != "" {
		head["KmsKeyId"] = a.s.kmsKey
	}
	if len(tags) > 0 {
		head["Tags"] = tags
	}
	body, err := jsonBody(head, valField, val, valField == "SecretBinary")
	if err != nil {
		return "", &apiError{kind: stores.ErrUnsupported, msg: "cannot encode the value"}
	}
	defer body.Wipe()
	return a.versionCall(ctx, "CreateSecret", body)
}

func (a *SecretsManager) versionCall(ctx context.Context, op string, body *wire.Body) (string, error) {
	b, err := a.c.call(ctx, op, body, true)
	if err != nil {
		return "", err
	}
	defer secret.WipeBytes(b)
	var out struct {
		VersionID string `json:"VersionId"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", &apiError{kind: stores.ErrUnavailable, msg: "cannot decode " + op, cause: err}
	}
	return out.VersionID, nil
}

func (a *SecretsManager) tag(ctx context.Context, name string, tags []tag) error {
	body, err := jsonBody(map[string]any{"SecretId": name, "Tags": tags}, "", nil, false)
	if err != nil {
		return &apiError{kind: stores.ErrInvalidRef, msg: "cannot encode the tags"}
	}
	b, err := a.c.call(ctx, "TagResource", body, false)
	secret.WipeBytes(b)
	return err
}

// Health implements stores.Adapter: Secrets Manager answers a signed
// request. An access denied answer still proves the endpoint is reachable
// and the credentials are valid; permissions on single secrets show on
// read.
func (a *SecretsManager) Health(ctx context.Context) error {
	body, _ := jsonBody(map[string]any{"MaxResults": 1}, "", nil, false)
	b, err := a.c.call(ctx, "ListSecrets", body, false)
	secret.WipeBytes(b)
	if err != nil {
		if ae, ok := err.(*apiError); ok && (ae.code == "AccessDeniedException" || ae.code == "AccessDenied") {
			return nil
		}
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}
