// SPDX-License-Identifier: AGPL-3.0-only

// Package kubernetes is the Kubernetes Secrets store adapter: Secrets in a
// configured set of namespaces, addressed as
// `<instance>://<namespace>/<name>[#key]` (or `<instance>://<name>[#key]`
// when the instance is confined to one namespace). Each data key of a Secret
// is a field. See paths.go for how names map to paths, labels.go for labels
// and watch.go for change notification.
//
// Authentication is the pod's service account (auth.method in-cluster) or
// one named context of one named kubeconfig file (auth.method kubeconfig).
// KUBECONFIG, ~/.kube/config and a kubeconfig's current-context are never
// consulted, so scrim cannot end up on whatever cluster a shell last
// pointed at.
//
// The source is read-only unless the option writable is true: without it
// the adapter does not declare stores.CapWrite and a write is refused with
// stores.ErrUnsupported ("kubernetes source is read-only") before any API
// call.
//
// Values: a Secret's data arrives from client-go as map[string][]byte. Each
// slice is adopted into a secret.Value without a copy, and the map is
// cleared, so the adapter keeps no other reference. What it cannot wipe:
// the HTTP response buffer the object was decoded from (protobuf is
// requested, so values are not passed through base64 strings, but the
// buffer itself is owned by client-go and released to the garbage
// collector), and on writes the encoded request body. List, ReadMetadata,
// Watch and Health use the metadata-only forms of the API (server-side
// tables and PartialObjectMetadata), so no value crosses the wire for them
// at all; only Read and Write carry values.
//
// Errors never keep the API server's error as their cause: a Status message
// can quote request data (an admission webhook may echo a field). They carry
// the HTTP code and reason instead.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Kind is the adapter kind this package registers.
const Kind = "kubernetes"

const readOnly = "kubernetes source is read-only; set writable: true to allow writes"

var secretsGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

func init() {
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		cfg, err := ParseOptions(inst.Name, inst.Options)
		if err != nil {
			return nil, err
		}
		return New(inst.Name, cfg), nil
	})
}

// Clients are the API clients the adapter uses. Tests inject their own.
type Clients struct {
	// Secrets reads and writes Secrets with their data.
	Secrets SecretsAPI
	// Meta lists and watches Secrets without their data.
	Meta metadata.Interface
	// REST fetches server-side tables (metadata and type, no data).
	REST rest.Interface
}

// Option tunes an Adapter.
type Option func(*Adapter)

// WithClients replaces the clients built from the configuration.
func WithClients(c Clients) Option { return func(a *Adapter) { a.clients = &c } }

// Adapter is one Kubernetes source.
type Adapter struct {
	name string
	cfg  Config

	mu      sync.Mutex
	clients *Clients
	initErr error
}

// New returns a Kubernetes source named name. It does not contact the API
// server; clients are built on first use, so a bad kubeconfig is reported by
// Health and the first operation, naming the file.
func New(name string, cfg Config, opts ...Option) *Adapter {
	a := &Adapter{name: name, cfg: cfg}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter: read, list, watch and glob, plus
// write when the instance is writable.
func (a *Adapter) Capabilities() stores.Capabilities {
	c := stores.CapRead | stores.CapList | stores.CapWatch | stores.CapGlob
	if a.cfg.Writable {
		c |= stores.CapWrite
	}
	return c
}

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string) error {
	e := stores.NewError(a.name, op, ref, kind, nil)
	e.Detail = detail
	return e
}

// client returns the clients, building them on first use.
func (a *Adapter) client(op stores.Op, ref stores.Ref) (*Clients, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clients == nil && a.initErr == nil {
		a.clients, a.initErr = build(a.cfg)
	}
	if a.initErr != nil {
		return nil, a.err(op, ref, stores.ErrUnavailable, a.initErr.Error())
	}
	return a.clients, nil
}

// ctx bounds a request by the configured timeout.
func (a *Adapter) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, a.cfg.Timeout)
}

// apiErr maps an API or transport error to a store error. The cause is not
// kept (see the package comment); the detail is the HTTP code and reason,
// or the transport failure.
func (a *Adapter) apiErr(op stores.Op, ref stores.Ref, err error) error {
	var st apierrors.APIStatus
	if errors.As(err, &st) {
		s := st.Status()
		detail := fmt.Sprintf("API server answered %d %s", s.Code, s.Reason)
		switch {
		case apierrors.IsNotFound(err):
			return a.err(op, ref, stores.ErrNotFound, "")
		case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
			return a.err(op, ref, stores.ErrPermission, detail)
		case apierrors.IsAlreadyExists(err), apierrors.IsConflict(err):
			return a.err(op, ref, stores.ErrConflict, detail)
		case apierrors.IsInvalid(err), apierrors.IsRequestEntityTooLargeError(err), apierrors.IsBadRequest(err):
			return a.err(op, ref, stores.ErrUnsupported, detail)
		}
		return a.err(op, ref, stores.ErrUnavailable, detail)
	}
	if errors.Is(err, context.Canceled) {
		return a.err(op, ref, stores.ErrUnavailable, "request cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return a.err(op, ref, stores.ErrUnavailable, "request timed out")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		var ne net.Error
		var oe *net.OpError
		switch {
		case errors.As(ue.Err, &oe):
			return a.err(op, ref, stores.ErrUnavailable, "cannot reach the API server: "+oe.Op+" "+oe.Err.Error())
		case errors.As(ue.Err, &ne) && ne.Timeout():
			return a.err(op, ref, stores.ErrUnavailable, "cannot reach the API server: timeout")
		}
	}
	return a.err(op, ref, stores.ErrUnavailable, "cannot reach the API server")
}

// adopt moves a Secret's data into secret.Values and clears the map, so the
// object no longer references the bytes.
func adopt(data map[string][]byte, only string) map[string]secret.Value {
	out := map[string]secret.Value{}
	for k, b := range data {
		if only == "" || k == only {
			out[k] = secret.Adopt(b)
		} else {
			secret.WipeBytes(b)
		}
		delete(data, k)
	}
	return out
}

// wipeData wipes every value of a Secret's data.
func wipeData(data map[string][]byte) {
	for k, b := range data {
		secret.WipeBytes(b)
		delete(data, k)
	}
}

// meta builds the metadata of a Secret object. Data keys are read, never
// their values.
func (a *Adapter) meta(scheme string, s *corev1.Secret) stores.Metadata {
	fields := slices.Sorted(maps.Keys(s.Data))
	return stores.Metadata{
		Ref:       stores.Ref{Scheme: scheme, Path: a.path(s.Namespace, s.Name)},
		Fields:    fields,
		Version:   s.ResourceVersion,
		CreatedAt: s.CreationTimestamp.Time,
		Labels:    labels(&s.ObjectMeta, string(s.Type)),
	}
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if ref.Selectors != "" {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "the kubernetes source has no version selectors")
	}
	t, err := a.secretTarget(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	c, err := a.client(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	rctx, cancel := a.ctx(ctx)
	defer cancel()
	s, err := c.Secrets.Get(rctx, t.ns, t.name)
	if err != nil {
		return stores.Secret{}, a.apiErr(stores.OpRead, ref, err)
	}
	m := a.meta(ref.Scheme, s)
	if ref.Field != "" {
		if _, ok := s.Data[ref.Field]; !ok {
			wipeData(s.Data)
			return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "the secret has no key "+ref.Field)
		}
	}
	return stores.Secret{Meta: m, Fields: adopt(s.Data, ref.Field)}, nil
}

// ReadMetadata implements stores.MetadataReader through the server-side
// table of the Secret, which carries its metadata and type but no data.
// Fields is left empty: the table gives only the number of keys.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	if ref.Selectors != "" {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "the kubernetes source has no version selectors")
	}
	ref = ref.Secret()
	t, err := a.secretTarget(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	c, err := a.client(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	rctx, cancel := a.ctx(ctx)
	defer cancel()
	rows, _, err := a.table(rctx, c, t.ns, t.name, "")
	if err != nil {
		return stores.Metadata{}, a.tableErr(stores.OpRead, ref, err)
	}
	if len(rows) != 1 {
		return stores.Metadata{}, a.err(stores.OpRead, ref, stores.ErrUnavailable, "unexpected table from the API server")
	}
	return a.rowMeta(ref.Scheme, rows[0]), nil
}

func (a *Adapter) rowMeta(scheme string, r row) stores.Metadata {
	return stores.Metadata{
		Ref:       stores.Ref{Scheme: scheme, Path: a.path(r.meta.Namespace, r.meta.Name)},
		Version:   r.meta.ResourceVersion,
		CreatedAt: r.meta.CreationTimestamp.Time,
		Labels:    labels(&r.meta, r.typ),
	}
}

// List implements stores.Adapter through server-side tables, so no value is
// transferred. Fields is left empty; Read fills it.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	prefix = prefix.Secret()
	sel, err := a.selectionFor(stores.OpList, prefix)
	if err != nil {
		return nil, err
	}
	c, err := a.client(stores.OpList, prefix)
	if err != nil {
		return nil, err
	}
	var out []stores.Metadata
	for _, ns := range sel.namespaces {
		cont := ""
		for {
			rctx, cancel := a.ctx(ctx)
			rows, next, err := a.table(rctx, c, ns, "", cont)
			cancel()
			if err != nil {
				return nil, a.tableErr(stores.OpList, prefix, err)
			}
			for _, r := range rows {
				if sel.match(r.meta.Name) {
					out = append(out, a.rowMeta(prefix.Scheme, r))
				}
			}
			if next == "" {
				break
			}
			cont = next
		}
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out, nil
}

// Write implements stores.Adapter. Without writable it is refused before
// any API call. The fields replace the Secret's data; its other keys,
// labels, annotations and type stay. WriteOptions.Labels must be scrim.*
// keys and are kept as annotations of the same name.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if !a.cfg.Writable {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrUnsupported, readOnly)
	}
	if ref.Selectors != "" {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "the kubernetes source has no version selectors")
	}
	t, err := a.secretTarget(stores.OpWrite, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	if len(fields) == 0 {
		return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "nothing to write")
	}
	for k := range fields {
		if len(validation.IsConfigMapKey(k)) > 0 {
			return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef,
				"a secret key may hold only letters, digits, '-', '_' and '.'")
		}
	}
	for k := range opts.Labels {
		if !strings.HasPrefix(k, stores.ScrimLabelPrefix) || len(validation.IsQualifiedName(k)) > 0 {
			return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrUnsupported,
				"label "+k+": the kubernetes source keeps only scrim.* labels, as annotations")
		}
	}
	c, err := a.client(stores.OpWrite, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	data := map[string][]byte{}
	defer wipeData(data)
	for k, v := range fields {
		if err := v.Expose(func(b []byte) error { data[k] = append([]byte(nil), b...); return nil }); err != nil {
			return stores.Metadata{}, a.err(stores.OpWrite, ref, stores.ErrInvalidRef, "field "+k+" was wiped")
		}
	}
	s, err := a.put(ctx, c, t, data, opts)
	if err != nil {
		return stores.Metadata{}, a.apiErr(stores.OpWrite, ref, err)
	}
	m := a.meta(ref.Scheme, s)
	wipeData(s.Data)
	return m, nil
}

// put creates or updates the Secret, retrying an update that lost a race.
// It returns the stored object, whose data the caller wipes.
func (a *Adapter) put(ctx context.Context, c *Clients, t target, data map[string][]byte, opts stores.WriteOptions) (*corev1.Secret, error) {
	api := c.Secrets
	create := func() (*corev1.Secret, error) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: t.name, Namespace: t.ns, Annotations: maps.Clone(opts.Labels)},
			Type:       corev1.SecretTypeOpaque,
			Data:       data,
		}
		rctx, cancel := a.ctx(ctx)
		defer cancel()
		return api.Create(rctx, s)
	}
	if opts.CreateOnly {
		return create()
	}
	var last error
	for range 4 {
		rctx, cancel := a.ctx(ctx)
		cur, err := api.Get(rctx, t.ns, t.name)
		cancel()
		switch {
		case apierrors.IsNotFound(err):
			s, err := create()
			if apierrors.IsAlreadyExists(err) {
				last = err
				continue
			}
			return s, err
		case err != nil:
			return nil, err
		}
		wipeData(cur.Data)
		cur.Data = data
		cur.StringData = nil
		if len(opts.Labels) > 0 && cur.Annotations == nil {
			cur.Annotations = map[string]string{}
		}
		maps.Copy(cur.Annotations, opts.Labels)
		rctx, cancel = a.ctx(ctx)
		s, err := api.Update(rctx, cur)
		cancel()
		if apierrors.IsConflict(err) {
			last = err
			continue
		}
		return s, err
	}
	return nil, last
}

// Health implements stores.Adapter: one metadata-only list per namespace,
// which checks the API server answers and scrim may list there.
func (a *Adapter) Health(ctx context.Context) error {
	c, err := a.client(stores.OpHealth, stores.Ref{})
	if err != nil {
		return err
	}
	for _, ns := range a.cfg.all() {
		rctx, cancel := a.ctx(ctx)
		_, err := c.Meta.Resource(secretsGVR).Namespace(ns).List(rctx, metav1.ListOptions{Limit: 1})
		cancel()
		if err != nil {
			e := a.apiErr(stores.OpHealth, stores.Ref{}, err)
			var se *stores.Error
			if errors.As(e, &se) {
				se.Detail = strings.TrimPrefix(se.Detail+"; ", "; ") + "namespace " + ns
			}
			return e
		}
	}
	return nil
}

// Close implements stores.Adapter. client-go keeps no state that needs
// releasing beyond idle connections, which the transport drops.
func (a *Adapter) Close() error { return nil }
