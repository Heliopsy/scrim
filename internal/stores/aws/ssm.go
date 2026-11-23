// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// ParameterStore is one configured AWS SSM Parameter Store instance.
//
// A reference path is the parameter's hierarchical name without its leading
// slash: ssm://app/prod/db-password is /app/prod/db-password. A parameter
// holds one value, the field "value"; a StringList is its comma-joined text
// and a SecureString is decrypted. `?version=<n>` and `?label=<label>`
// select a version, as does the native suffix (`app/db:3`, `app/db:prod`).
type ParameterStore struct{ base }

var (
	_ stores.Adapter          = (*ParameterStore)(nil)
	_ stores.CredentialHolder = (*ParameterStore)(nil)
	_ stores.MetadataReader   = (*ParameterStore)(nil)
	_ stores.WriteLabeler     = (*ParameterStore)(nil)
)

// NewParameterStore builds an ssm adapter. It validates the options and
// does not resolve credentials or contact AWS.
func NewParameterStore(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
	s, err := decodeSettings(inst, KindParameterStore)
	if err != nil {
		return nil, configError(inst.Name, err)
	}
	return &ParameterStore{base{name: inst.Name, kind: KindParameterStore, s: s, c: newClient(s, "ssm", "AmazonSSM"), agents: newAgentCache()}}, nil
}

var (
	ssmSegment = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	// ssmLabel is a parameter label: letters, digits, '.', '-' and '_', not
	// starting with a digit (that would read as a version).
	ssmLabel = regexp.MustCompile(`^[A-Za-z_.-][A-Za-z0-9_.-]{0,99}$`)
)

const ssmMaxName = 1011

// parameter splits a reference into the parameter name ("/a/b") and the
// selector suffix GetParameter takes (":3", ":prod" or "").
func (a *ParameterStore) parameter(op stores.Op, ref stores.Ref) (name, suffix string, err error) {
	path := ref.Path
	if i := strings.LastIndexByte(path, ':'); i >= 0 && !strings.Contains(path[i:], "/") {
		path, suffix = path[:i], path[i+1:]
		if suffix == "" || ref.Selectors != "" {
			return "", "", a.invalid(op, ref, "use either a :<version|label> suffix or a selector, not both")
		}
	}
	if ref.Selectors != "" {
		q, _ := url.ParseQuery(ref.Selectors)
		for k := range q {
			switch k {
			case "version", "label":
			default:
				return "", "", a.invalid(op, ref, "unknown selector "+strconv.Quote(k)+" (supported: version, label)")
			}
		}
		if len(q) > 1 {
			return "", "", a.invalid(op, ref, "use one of the selectors version and label")
		}
		if suffix = q.Get("version"); suffix != "" {
			if n, err := strconv.ParseUint(suffix, 10, 63); err != nil || n == 0 {
				return "", "", a.invalid(op, ref, "version must be a positive number")
			}
		} else {
			suffix = q.Get("label")
		}
	}
	if suffix != "" {
		if _, err := strconv.ParseUint(suffix, 10, 63); err != nil && !ssmLabel.MatchString(suffix) {
			return "", "", a.invalid(op, ref, "a label is up to 100 letters, digits and ._- and does not start with a digit")
		}
		suffix = ":" + suffix
	}
	name, err = a.paramName(op, ref, path)
	return name, suffix, err
}

func (a *ParameterStore) paramName(op stores.Op, ref stores.Ref, path string) (string, error) {
	segs := strings.Split(path, "/")
	for _, s := range segs {
		if !ssmSegment.MatchString(s) {
			return "", a.invalid(op, ref, "a parameter path is made of segments of letters, digits and ._-")
		}
	}
	first := strings.ToLower(segs[0])
	if strings.HasPrefix(first, "aws") || strings.HasPrefix(first, "ssm") {
		if op != stores.OpRead || !strings.HasPrefix(path, "aws/") {
			return "", a.invalid(op, ref, "names starting with aws or ssm are reserved by AWS")
		}
	}
	name := "/" + path
	if len(name) > ssmMaxName {
		return "", a.invalid(op, ref, "a parameter name is at most 1011 characters")
	}
	return name, nil
}

// ssmParam is a parameter as DescribeParameters returns it. Description and
// AllowedPattern are free text and are not decoded.
type ssmParam struct {
	ARN              string `json:"ARN"`
	Name             string `json:"Name"`
	Type             string `json:"Type"`
	KeyID            string `json:"KeyId"`
	Tier             string `json:"Tier"`
	DataType         string `json:"DataType"`
	Version          int64  `json:"Version"`
	LastModifiedDate epoch  `json:"LastModifiedDate"`
	LastModifiedUser string `json:"LastModifiedUser"`
	Policies         []struct {
		PolicyType string `json:"PolicyType"`
	} `json:"Policies"`
}

// describe finds one parameter by exact name; nil when there is none.
func (a *ParameterStore) describe(ctx context.Context, op stores.Op, ref stores.Ref, name string) (*ssmParam, error) {
	ps, err := a.describeFiltered(ctx, op, ref, map[string]any{"Key": "Name", "Option": "Equals", "Values": []string{name}}, 1)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, nil
}

// describeFiltered pages through DescribeParameters with one filter. limit
// stops after that many results (0: all).
func (a *ParameterStore) describeFiltered(ctx context.Context, op stores.Op, ref stores.Ref, filter map[string]any, limit int) ([]*ssmParam, error) {
	var out []*ssmParam
	next := ""
	for {
		head := map[string]any{"MaxResults": 50, "ParameterFilters": []map[string]any{filter}}
		if next != "" {
			head["NextToken"] = next
		}
		body, err := jsonBody(head, "", nil, false)
		if err != nil {
			return nil, a.invalid(op, ref, "cannot encode the request")
		}
		b, err := a.c.call(ctx, "DescribeParameters", body, false)
		if err != nil {
			return nil, a.fail(op, ref, err)
		}
		var page struct {
			Parameters []*ssmParam `json:"Parameters"`
			NextToken  string      `json:"NextToken"`
		}
		err = json.Unmarshal(b, &page)
		secret.WipeBytes(b)
		if err != nil {
			return nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrUnavailable, Detail: "cannot decode DescribeParameters", Cause: err}
		}
		out = append(out, page.Parameters...)
		if page.NextToken == "" || page.NextToken == next || (limit > 0 && len(out) >= limit) {
			return out, nil
		}
		next = page.NextToken
	}
}

func (a *ParameterStore) tags(ctx context.Context, op stores.Op, ref stores.Ref, name string) ([]tag, error) {
	body, err := jsonBody(map[string]any{"ResourceType": "Parameter", "ResourceId": name}, "", nil, false)
	if err != nil {
		return nil, a.invalid(op, ref, "cannot encode the request")
	}
	b, err := a.c.call(ctx, "ListTagsForResource", body, false)
	if err != nil {
		return nil, a.fail(op, ref, err)
	}
	var out struct {
		TagList []tag `json:"TagList"`
	}
	err = json.Unmarshal(b, &out)
	secret.WipeBytes(b)
	if err != nil {
		return nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrUnavailable, Detail: "cannot decode ListTagsForResource", Cause: err}
	}
	return out.TagList, nil
}

// labels builds the labels of p (docs/stores/aws.md, "Policy labels").
func (a *ParameterStore) labels(p *ssmParam, tags []tag) map[string]string {
	out := map[string]string{}
	k := KindParameterStore
	stores.SetNative(out, k, "name", p.Name)
	container := "/"
	if i := strings.LastIndexByte(p.Name, '/'); i > 0 {
		container = p.Name[:i]
	}
	stores.SetNative(out, k, "path", container)
	stores.SetNative(out, k, "type", p.Type)
	stores.SetNative(out, k, "tier", p.Tier)
	stores.SetNative(out, k, "data-type", p.DataType)
	if p.Type == "SecureString" {
		stores.SetNative(out, k, "kms-key", p.KeyID)
	}
	stores.SetNative(out, k, "arn", p.ARN)
	stores.SetNative(out, k, "account", accountOf(p.ARN))
	stores.SetNative(out, k, "region", regionOf(p.ARN, a.region()))
	setTime(out, k, "modified", p.LastModifiedDate.Time)
	stores.SetNative(out, k, "modified-by", p.LastModifiedUser)
	policies := make([]string, 0, len(p.Policies))
	for _, pol := range p.Policies {
		policies = append(policies, pol.PolicyType)
	}
	stores.SetNative(out, k, "policy", policies...)
	tagLabels(out, k, tags)
	return out
}

func (a *ParameterStore) meta(ref stores.Ref, p *ssmParam, labels map[string]string) stores.Metadata {
	m := stores.Metadata{Ref: ref.Secret(), Fields: []string{Field}, UpdatedAt: p.LastModifiedDate.Time, Labels: labels}
	if p.Version > 0 {
		m.Version = strconv.FormatInt(p.Version, 10)
	}
	return m
}

// lookup returns the parameter's description and tags, or ErrNotFound.
func (a *ParameterStore) lookup(ctx context.Context, op stores.Op, ref stores.Ref, name string) (*ssmParam, map[string]string, error) {
	p, err := a.describe(ctx, op, ref, name)
	if err != nil {
		return nil, nil, err
	}
	if p == nil {
		return nil, nil, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrNotFound}
	}
	tags, err := a.tags(ctx, op, ref, name)
	if err != nil {
		return nil, nil, err
	}
	return p, a.labels(p, tags), nil
}

// ReadMetadata implements stores.MetadataReader with DescribeParameters and
// ListTagsForResource: the labels Read reports, without asking for the
// value. With a selector, Version is the current version's.
func (a *ParameterStore) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	name, _, err := a.parameter(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	p, labels, err := a.lookup(ctx, stores.OpRead, ref, name)
	if err != nil {
		return stores.Metadata{}, err
	}
	return a.meta(ref, p, labels), nil
}

// Read implements stores.Adapter: GetParameter with decryption for the
// value, then the parameter's description and tags for the labels.
func (a *ParameterStore) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	name, suffix, err := a.parameter(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	if ref.Field != "" && ref.Field != Field {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrNotFound,
			Detail: "a parameter holds the single field " + Field}
	}
	body, err := jsonBody(map[string]any{"Name": name + suffix, "WithDecryption": true}, "", nil, false)
	if err != nil {
		return stores.Secret{}, a.invalid(stores.OpRead, ref, "cannot encode the request")
	}
	b, err := a.c.call(ctx, "GetParameter", body, false)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	var got struct {
		Parameter struct {
			Version          int64    `json:"Version"`
			Value            wire.Raw `json:"Value"`
			LastModifiedDate epoch    `json:"LastModifiedDate"`
		} `json:"Parameter"`
	}
	err = json.Unmarshal(b, &got)
	secret.WipeBytes(b)
	defer got.Parameter.Value.Wipe()
	if err != nil {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrUnavailable, Detail: "cannot decode GetParameter"}
	}
	p, labels, err := a.lookup(ctx, stores.OpRead, ref, name)
	if err != nil {
		return stores.Secret{}, err
	}
	v, err := got.Parameter.Value.Value()
	if err != nil {
		return stores.Secret{}, &stores.Error{Store: a.name, Op: stores.OpRead, Ref: ref, Kind: stores.ErrUnavailable, Detail: "parameter value missing from the response"}
	}
	m := a.meta(ref, p, labels)
	m.Version = strconv.FormatInt(got.Parameter.Version, 10)
	if !got.Parameter.LastModifiedDate.IsZero() {
		m.UpdatedAt = got.Parameter.LastModifiedDate.Time
	}
	return stores.Secret{Meta: m, Fields: map[string]secret.Value{Field: v}}, nil
}

// listFilter is the DescribeParameters filter for a listing prefix.
func listFilter(path string) (map[string]any, string) {
	match, glob := listPrefix(path)
	if glob {
		return map[string]any{"Key": "Name", "Option": "BeginsWith", "Values": []string{"/" + match}}, "/" + match
	}
	return map[string]any{"Key": "Path", "Option": "Recursive", "Values": []string{"/" + strings.TrimSuffix(match, "/")}}, "/" + match
}

func (a *ParameterStore) list(ctx context.Context, prefix stores.Ref) ([]*ssmParam, error) {
	filter, match := listFilter(prefix.Path)
	ps, err := a.describeFiltered(ctx, stores.OpList, prefix, filter, 0)
	if err != nil {
		return nil, err
	}
	out := ps[:0]
	for _, p := range ps {
		if strings.HasPrefix(p.Name, match) {
			out = append(out, p)
		}
	}
	return out, nil
}

// List implements stores.Adapter with DescribeParameters and one
// ListTagsForResource per parameter: names, versions and tags, never
// values.
func (a *ParameterStore) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	ps, err := a.list(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]stores.Metadata, 0, len(ps))
	for _, p := range ps {
		ref := stores.Ref{Scheme: prefix.Scheme, Path: strings.TrimPrefix(p.Name, "/")}
		tags, err := a.tags(ctx, stores.OpList, ref, p.Name)
		if err != nil {
			if isNotFound(err) {
				continue // deleted since the listing
			}
			return nil, err
		}
		out = append(out, a.meta(ref, p, a.labels(p, tags)))
	}
	return out, nil
}

func isNotFound(err error) bool {
	se, ok := err.(*stores.Error)
	return ok && se.Kind == stores.ErrNotFound
}

// Watch implements stores.Adapter by polling DescribeParameters (no tags,
// no values).
func (a *ParameterStore) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	return a.watch(ctx, prefix, func(ctx context.Context, p stores.Ref) (map[string]string, error) {
		ps, err := a.list(ctx, p)
		if err != nil {
			return nil, err
		}
		out := make(map[string]string, len(ps))
		for _, x := range ps {
			out[strings.TrimPrefix(x.Name, "/")] = strconv.FormatInt(x.Version, 10) + "@" + x.LastModifiedDate.Format(time.RFC3339Nano)
		}
		return out, nil
	})
}

// WriteLabels implements stores.WriteLabeler: what a parameter written at
// ref would carry, from the reference and the write settings.
func (a *ParameterStore) WriteLabels(ref stores.Ref) map[string]string {
	ref.Selectors = ""
	name, err := a.paramName(stores.OpWrite, ref, ref.Path)
	if err != nil {
		return nil
	}
	p := &ssmParam{Name: name, Type: a.s.paramType, Tier: a.s.tier, KeyID: a.s.kmsKey}
	out := a.labels(p, nil)
	return out
}

// Write implements stores.Adapter: PutParameter without overwrite creates
// the parameter (type parameter-type, with tier, KMS key and tags); an
// existing one gets a new version with Overwrite, keeping its type, and
// AddTagsToResource for the labels.
func (a *ParameterStore) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if ref.Selectors != "" || strings.Contains(ref.Path, ":") {
		return stores.Metadata{}, a.invalid(stores.OpWrite, ref, "a write names the parameter, without a version or label")
	}
	name, err := a.paramName(stores.OpWrite, ref, ref.Path)
	if err != nil {
		return stores.Metadata{}, err
	}
	v, ok := fields[Field]
	if !ok || len(fields) != 1 {
		return stores.Metadata{}, a.unsupported(stores.OpWrite, ref, "a parameter holds a single field named "+Field)
	}
	var valid bool
	_ = v.Expose(func(b []byte) error { valid = len(b) > 0 && utf8.Valid(b); return nil })
	if !valid {
		return stores.Metadata{}, a.unsupported(stores.OpWrite, ref, "a parameter value is non-empty UTF-8 text")
	}
	tags, bad := writeTags(KindParameterStore, opts.Labels)
	if bad != "" {
		return stores.Metadata{}, a.unsupported(stores.OpWrite, ref, "label "+strconv.Quote(bad)+" cannot be an AWS tag key (at most 128 letters, digits, spaces and _.:/=+-@)")
	}
	head := map[string]any{"Name": name, "Overwrite": false, "Type": a.s.paramType}
	if a.s.kmsKey != "" {
		head["KeyId"] = a.s.kmsKey
	}
	if a.s.tier != "" {
		head["Tier"] = a.s.tier
	}
	if len(tags) > 0 {
		head["Tags"] = tags
	}
	version, err := a.put(ctx, head, v)
	if isKind(err, stores.ErrConflict) && !opts.CreateOnly {
		over := map[string]any{"Name": name, "Overwrite": true}
		if a.s.tier != "" {
			over["Tier"] = a.s.tier
		}
		version, err = a.put(ctx, over, v)
		if err == nil && len(tags) > 0 {
			err = a.addTags(ctx, name, tags)
		}
	}
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	return stores.Metadata{Ref: ref, Version: version, Fields: []string{Field}, UpdatedAt: time.Now().UTC(), Labels: a.WriteLabels(ref)}, nil
}

func (a *ParameterStore) put(ctx context.Context, head map[string]any, v secret.Value) (string, error) {
	var body *wire.Body
	err := v.Expose(func(b []byte) error {
		var err error
		body, err = jsonBody(head, "Value", b, false)
		return err
	})
	if err != nil {
		return "", &apiError{kind: stores.ErrUnsupported, msg: "cannot encode the value"}
	}
	defer body.Wipe()
	b, err := a.c.call(ctx, "PutParameter", body, true)
	if err != nil {
		return "", err
	}
	defer secret.WipeBytes(b)
	var out struct {
		Version int64 `json:"Version"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", &apiError{kind: stores.ErrUnavailable, msg: "cannot decode PutParameter", cause: err}
	}
	return strconv.FormatInt(out.Version, 10), nil
}

func (a *ParameterStore) addTags(ctx context.Context, name string, tags []tag) error {
	body, err := jsonBody(map[string]any{"ResourceType": "Parameter", "ResourceId": name, "Tags": tags}, "", nil, false)
	if err != nil {
		return &apiError{kind: stores.ErrInvalidRef, msg: "cannot encode the tags"}
	}
	b, err := a.c.call(ctx, "AddTagsToResource", body, false)
	secret.WipeBytes(b)
	return err
}

// Health implements stores.Adapter: Parameter Store answers a signed
// request (access denied included, as for Secrets Manager).
func (a *ParameterStore) Health(ctx context.Context) error {
	body, _ := jsonBody(map[string]any{"MaxResults": 1}, "", nil, false)
	b, err := a.c.call(ctx, "DescribeParameters", body, false)
	secret.WipeBytes(b)
	if err != nil {
		if ae, ok := err.(*apiError); ok && (ae.code == "AccessDeniedException" || ae.code == "AccessDenied") {
			return nil
		}
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}
