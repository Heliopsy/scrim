// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func gen(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "k8s_" + hex.EncodeToString(b)
}

func plain(v secret.Value) string {
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

// leaks reports whether err, its %+v and %#v forms or any error in its
// chain contain p.
func leaks(err error, p string) bool {
	if err == nil {
		return false
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(s, p) {
			return true
		}
	}
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if leaks(e, p) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return leaks(u.Unwrap(), p)
	}
	return false
}

// fakeSecrets is SecretsAPI over client-go's fake clientset.
type fakeSecrets struct{ cs *fake.Clientset }

func (f fakeSecrets) Get(ctx context.Context, ns, name string) (*corev1.Secret, error) {
	return f.cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
}

func (f fakeSecrets) Create(ctx context.Context, s *corev1.Secret) (*corev1.Secret, error) {
	return f.cs.CoreV1().Secrets(s.Namespace).Create(ctx, s, metav1.CreateOptions{})
}

func (f fakeSecrets) Update(ctx context.Context, s *corev1.Secret) (*corev1.Secret, error) {
	return f.cs.CoreV1().Secrets(s.Namespace).Update(ctx, s, metav1.UpdateOptions{})
}

func fakeAdapter(cfg Config, objs ...runtime.Object) (*Adapter, *fake.Clientset) {
	cs := fake.NewClientset(objs...)
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	return New("k8s", cfg, WithClients(Clients{Secrets: fakeSecrets{cs}})), cs
}

func TestReadOnlyWriteRefusedBeforeAnyCall(t *testing.T) {
	a, cs := fakeAdapter(Config{Namespace: "prod"})
	if a.Capabilities().Has(stores.CapWrite) {
		t.Fatal("a read-only instance declares write")
	}
	p := gen(t)
	v := secret.FromString(p)
	_, err := a.Write(context.Background(), stores.Ref{Scheme: "k8s", Path: "db"}, map[string]secret.Value{"password": v}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrUnsupported) || !strings.Contains(err.Error(), "kubernetes source is read-only") {
		t.Fatalf("write to a read-only instance: %v", err)
	}
	if n := len(cs.Actions()); n != 0 {
		t.Errorf("a refused write made %d API calls", n)
	}
	if v.Wiped() {
		t.Errorf("a refused write wiped the caller's value")
	}
	if leaks(err, p) {
		t.Errorf("refusal carries the value")
	}
	w, _ := fakeAdapter(Config{Namespace: "prod", Writable: true})
	if !w.Capabilities().Has(stores.CapWrite) {
		t.Errorf("a writable instance does not declare write")
	}
}

func TestReadAdoptsValues(t *testing.T) {
	p1, p2 := gen(t), gen(t)
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls.example.com", Namespace: "prod", ResourceVersion: "42"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte(p1), "tls.key": []byte(p2)},
	}
	a, _ := fakeAdapter(Config{Namespaces: []string{"prod"}}, s)
	got, err := a.Read(context.Background(), stores.Ref{Scheme: "k8s", Path: "prod/tls/example/com"})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Wipe()
	if v, _ := got.Field("tls.key"); plain(v) != p2 {
		t.Errorf("tls.key has the wrong value")
	}
	if got.Meta.Version != "42" || strings.Join(got.Meta.Fields, ",") != "tls.crt,tls.key" {
		t.Errorf("metadata: %+v", got.Meta)
	}
	if got.Meta.Labels["kubernetes.type"] != "kubernetes.io/tls" || got.Meta.Labels["kubernetes.name"] != "tls.example.com" {
		t.Errorf("labels: %v", got.Meta.Labels)
	}
	one, err := a.Read(context.Background(), stores.Ref{Scheme: "k8s", Path: "prod/tls/example/com", Field: "tls.crt"})
	if err != nil {
		t.Fatal(err)
	}
	defer one.Wipe()
	if len(one.Fields) != 1 || plain(one.Fields["tls.crt"]) != p1 {
		t.Errorf("field read returned %d fields", len(one.Fields))
	}
	_, err = a.Read(context.Background(), stores.Ref{Scheme: "k8s", Path: "prod/tls/example/com", Field: "absent"})
	if !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("missing key: %v", err)
	}
}

func TestReadRefusals(t *testing.T) {
	a, cs := fakeAdapter(Config{Namespaces: []string{"prod"}})
	for _, c := range []struct {
		path, sel string
		kind      error
	}{
		{"staging/db", "", stores.ErrPermission},
		{"prod", "", stores.ErrInvalidRef},
		{"prod/Db", "", stores.ErrInvalidRef},
		{"prod/tls.example.com", "", stores.ErrInvalidRef},
		{"prod/db_x", "", stores.ErrInvalidRef},
		{"prod/db", "version=1", stores.ErrInvalidRef},
		{"prod/missing", "", stores.ErrNotFound},
	} {
		_, err := a.Read(context.Background(), stores.Ref{Scheme: "k8s", Path: c.path, Selectors: c.sel})
		if !errors.Is(err, c.kind) {
			t.Errorf("Read %s?%s: %v, want %v", c.path, c.sel, err, c.kind)
		}
		var se *stores.Error
		if !errors.As(err, &se) || se.Store != "k8s" {
			t.Errorf("Read %s: not a store error naming the store: %v", c.path, err)
		}
	}
	// Only the last case reaches the API server.
	if n := len(cs.Actions()); n != 1 {
		t.Errorf("%d API calls, want 1", n)
	}
}

// TestErrorMappingNoLeak makes the API server answer with errors whose
// messages quote the value being written, and checks every one maps to its
// kind without the value anywhere in the error chain.
func TestErrorMappingNoLeak(t *testing.T) {
	gr := schema.GroupResource{Resource: "secrets"}
	p := gen(t)
	cases := []struct {
		name string
		err  error
		kind error
	}{
		{"forbidden", apierrors.NewForbidden(gr, "db", errors.New("webhook says "+p)), stores.ErrPermission},
		{"unauthorized", apierrors.NewUnauthorized("token " + p), stores.ErrPermission},
		{"conflict", apierrors.NewConflict(gr, "db", errors.New(p)), stores.ErrConflict},
		{"invalid", apierrors.NewBadRequest("data: Invalid value: " + p), stores.ErrUnsupported},
		{"too large", apierrors.NewRequestEntityTooLargeError(p), stores.ErrUnsupported},
		{"internal", apierrors.NewInternalError(errors.New(p)), stores.ErrUnavailable},
		{"unavailable", apierrors.NewServiceUnavailable(p), stores.ErrUnavailable},
		{"timeout", apierrors.NewTimeoutError(p, 1), stores.ErrUnavailable},
		{"transport", &url.Error{Op: "Put", URL: "https://api/x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}, stores.ErrUnavailable},
		{"other", errors.New("boom " + p), stores.ErrUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, cs := fakeAdapter(Config{Namespace: "prod", Writable: true})
			cs.PrependReactor("*", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, c.err })
			v := secret.FromString(p)
			_, err := a.Write(context.Background(), stores.Ref{Scheme: "k8s", Path: "db"}, map[string]secret.Value{"password": v}, stores.WriteOptions{})
			if !errors.Is(err, c.kind) {
				t.Errorf("Write: %v, want %v", err, c.kind)
			}
			if leaks(err, p) {
				t.Errorf("Write error carries the value: %v", err)
			}
			if v.Wiped() {
				t.Errorf("a failed write wiped the caller's value")
			}
			_, err = a.Read(context.Background(), stores.Ref{Scheme: "k8s", Path: "db"})
			if !errors.Is(err, c.kind) || leaks(err, p) {
				t.Errorf("Read: %v, want %v without the value", err, c.kind)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	a, cs := fakeAdapter(Config{Namespace: "prod", Writable: true})
	ctx := context.Background()
	ref := stores.Ref{Scheme: "k8s", Path: "app/db"}
	p1, p2 := gen(t), gen(t)
	m, err := a.Write(ctx, ref, map[string]secret.Value{"password": secret.FromString(p1)},
		stores.WriteOptions{CreateOnly: true, Labels: map[string]string{"scrim.hosts": "db.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Ref.Path != "app/db" || m.Labels["scrim.hosts"] != "db.example.test" {
		t.Errorf("metadata %+v", m)
	}
	s, err := cs.CoreV1().Secrets("prod").Get(ctx, "app.db", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Data["password"]) != p1 || s.Type != corev1.SecretTypeOpaque || s.Annotations["scrim.hosts"] != "db.example.test" {
		t.Errorf("stored secret: type %s annotations %v", s.Type, s.Annotations)
	}
	_, err = a.Write(ctx, ref, map[string]secret.Value{"password": secret.FromString(p2)}, stores.WriteOptions{CreateOnly: true})
	if !errors.Is(err, stores.ErrConflict) || leaks(err, p2) {
		t.Errorf("create-only over an existing secret: %v", err)
	}
	// An overwrite keeps labels and type, replaces data.
	s.Labels = map[string]string{"team": "payments"}
	if _, err := cs.CoreV1().Secrets("prod").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write(ctx, ref, map[string]secret.Value{"token": secret.FromString(p2)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	s, _ = cs.CoreV1().Secrets("prod").Get(ctx, "app.db", metav1.GetOptions{})
	if _, old := s.Data["password"]; old || string(s.Data["token"]) != p2 || s.Labels["team"] != "payments" {
		t.Errorf("overwrite: data keys %d, labels %v", len(s.Data), s.Labels)
	}
	// Labels that would not round-trip, and invalid keys, are refused
	// before any call.
	before := len(cs.Actions())
	for _, c := range []struct {
		fields map[string]secret.Value
		labels map[string]string
	}{
		{map[string]secret.Value{"ok": secret.FromString(p1)}, map[string]string{"team": "x"}},
		{map[string]secret.Value{"ok": secret.FromString(p1)}, map[string]string{"scrim.bad key": "x"}},
		{map[string]secret.Value{"bad key": secret.FromString(p1)}, nil},
		{map[string]secret.Value{}, nil},
	} {
		if _, err := a.Write(ctx, ref, c.fields, stores.WriteOptions{Labels: c.labels}); err == nil || leaks(err, p1) {
			t.Errorf("Write %v %v: %v, want a refusal", c.fields, c.labels, err)
		}
	}
	if n := len(cs.Actions()) - before; n != 0 {
		t.Errorf("refused writes made %d API calls", n)
	}
	if _, err := a.Write(ctx, stores.Ref{Scheme: "k8s", Path: "Bad"}, map[string]secret.Value{"k": secret.FromString(p1)}, stores.WriteOptions{}); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("invalid name: %v", err)
	}
}

func TestWriteOutsideNamespaces(t *testing.T) {
	a, cs := fakeAdapter(Config{Namespaces: []string{"agents"}, Writable: true})
	_, err := a.Write(context.Background(), stores.Ref{Scheme: "k8s", Path: "kube-system/x"},
		map[string]secret.Value{"k": secret.FromString(gen(t))}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "kube-system/x") {
		t.Errorf("write outside the namespaces: %v", err)
	}
	if len(cs.Actions()) != 0 {
		t.Errorf("a write outside the namespaces reached the API server")
	}
}

func TestLabelsCannotForgeNative(t *testing.T) {
	m := &metav1.ObjectMeta{
		Namespace: "prod", Name: "db",
		Labels: map[string]string{"kubernetes.namespace": "dev", "app.kubernetes.io/name": "api"},
		Annotations: map[string]string{
			"kubernetes.type":  "Opaque",
			"scrim.hosts":      "api.example.test",
			"kubernetes.name":  "other",
			"store.name":       "forged",
			"team":             "payments",
			lastApplied:        `{"data":{"password":"c2VjcmV0"}}`,
			"kubernetes.meta":  "x",
			"kubernetes.io/sa": "default",
		},
	}
	l := labels(m, "kubernetes.io/tls")
	want := map[string]string{
		"kubernetes.namespace":                         "prod",
		"kubernetes.name":                              "db",
		"kubernetes.type":                              "kubernetes.io/tls",
		"kubernetes.meta.label.kubernetes.namespace":   "dev",
		"kubernetes.meta.label.app.kubernetes.io_name": "api",
		"kubernetes.meta.annotation.kubernetes.type":   "Opaque",
		"kubernetes.meta.annotation.kubernetes.name":   "other",
		"kubernetes.meta.annotation.team":              "payments",
		"kubernetes.meta.annotation.store.name":        "forged",
		"kubernetes.meta.annotation.kubernetes.meta":   "x",
		"kubernetes.meta.annotation.kubernetes.io_sa":  "default",
		"scrim.hosts":                                  "api.example.test",
		"kubernetes.meta.annotation.scrim.hosts":       "api.example.test",
	}
	for k, v := range want {
		if l[k] != v {
			t.Errorf("label %s = %q, want %q", k, l[k], v)
		}
	}
	for k, v := range l {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected label %s = %q", k, v)
		}
		if strings.Contains(v, "c2VjcmV0") {
			t.Errorf("label %s carries the last-applied configuration", k)
		}
	}
	// Composed, the store's own keys stay scrim's.
	got := stores.ComposeLabels("k8s", Kind, stores.Ref{Scheme: "k8s", Path: "prod/db"}, l, stores.LabelMapping{})
	if got["store.name"] != "k8s" || got["kubernetes.namespace"] != "prod" {
		t.Errorf("composed labels: %v", got)
	}
}

func TestWriteLabels(t *testing.T) {
	a, _ := fakeAdapter(Config{Namespaces: []string{"agents"}, Writable: true})
	l := a.WriteLabels(stores.Ref{Scheme: "k8s", Path: "agents/github/token", Field: "value"})
	if l["kubernetes.namespace"] != "agents" || l["kubernetes.name"] != "github.token" || len(l) != 2 {
		t.Errorf("write labels: %v", l)
	}
	if l := a.WriteLabels(stores.Ref{Scheme: "k8s", Path: "other/x"}); l != nil {
		t.Errorf("write labels outside the namespaces: %v", l)
	}
}
