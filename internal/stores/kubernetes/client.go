// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

// The adapter talks to the core API through a REST client over a scheme
// that knows core/v1 only. client-go's typed clients would register every
// API group of the cluster (k8s.io/client-go/kubernetes/scheme) and add
// tens of megabytes to the binary for one resource.

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	metav1.AddToGroupVersion(scheme, corev1.SchemeGroupVersion)
}

// SecretsAPI is the part of the core API the adapter reads and writes
// Secrets with. Tests substitute their own.
type SecretsAPI interface {
	Get(ctx context.Context, ns, name string) (*corev1.Secret, error)
	Create(ctx context.Context, s *corev1.Secret) (*corev1.Secret, error)
	Update(ctx context.Context, s *corev1.Secret) (*corev1.Secret, error)
}

// restSecrets is SecretsAPI over a core/v1 REST client.
type restSecrets struct{ c rest.Interface }

func (r restSecrets) Get(ctx context.Context, ns, name string) (*corev1.Secret, error) {
	out := &corev1.Secret{}
	return out, r.c.Get().Namespace(ns).Resource("secrets").Name(name).Do(ctx).Into(out)
}

func (r restSecrets) Create(ctx context.Context, s *corev1.Secret) (*corev1.Secret, error) {
	out := &corev1.Secret{}
	return out, r.c.Post().Namespace(s.Namespace).Resource("secrets").Body(s).Do(ctx).Into(out)
}

func (r restSecrets) Update(ctx context.Context, s *corev1.Secret) (*corev1.Secret, error) {
	out := &corev1.Secret{}
	return out, r.c.Put().Namespace(s.Namespace).Resource("secrets").Name(s.Name).Body(s).Do(ctx).Into(out)
}

func build(cfg Config) (*Clients, error) {
	rc, err := cfg.restConfig()
	if err != nil {
		return nil, err
	}
	// Protobuf for Secrets: their data is decoded straight into byte
	// slices, never through base64 text.
	core := rest.CopyConfig(rc)
	core.APIPath = "/api"
	core.GroupVersion = &corev1.SchemeGroupVersion
	core.NegotiatedSerializer = codecs.WithoutConversion()
	core.ContentType = runtime.ContentTypeProtobuf
	core.AcceptContentTypes = runtime.ContentTypeProtobuf + "," + runtime.ContentTypeJSON
	client, err := rest.RESTClientFor(core)
	if err != nil {
		return nil, fmt.Errorf("cannot build the API client: %w", err)
	}
	meta, err := metadata.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("cannot build the metadata client: %w", err)
	}
	return &Clients{Secrets: restSecrets{client}, Meta: meta, REST: client}, nil
}
