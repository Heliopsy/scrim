// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// The integration tests run against a real API server, normally a
// throwaway kind cluster:
//
//	SCRIM_TEST_KUBECONFIG=/abs/path/kubeconfig  (never ~/.kube/config)
//	SCRIM_TEST_KUBE_CONTEXT=kind-scrim-k8s-...
//
// Without them they skip, unless SCRIM_TEST_KUBERNETES=1 says the run must
// not skip (CI). Every namespace they create is named scrim-k8s-test-* and
// deleted at the end. The API server is reached through a local TCP proxy,
// so a test can cut it off to check outage handling.

type cluster struct {
	kubeconfig string // a copy pointing at the proxy
	context    string
	admin      kubernetes.Interface
	proxy      *proxy
}

func requireCluster(t *testing.T) *cluster {
	t.Helper()
	path, ctxName := os.Getenv("SCRIM_TEST_KUBECONFIG"), os.Getenv("SCRIM_TEST_KUBE_CONTEXT")
	if path == "" || ctxName == "" {
		if os.Getenv("SCRIM_TEST_KUBERNETES") == "1" {
			t.Fatal("SCRIM_TEST_KUBERNETES=1 but SCRIM_TEST_KUBECONFIG or SCRIM_TEST_KUBE_CONTEXT is not set")
		}
		t.Skip("set SCRIM_TEST_KUBECONFIG and SCRIM_TEST_KUBE_CONTEXT to run against a cluster")
	}
	kc, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	kctx, ok := kc.Contexts[ctxName]
	if !ok {
		t.Fatalf("%s has no context %s", path, ctxName)
	}
	cl := kc.Clusters[kctx.Cluster]
	u, err := url.Parse(cl.Server)
	if err != nil {
		t.Fatal(err)
	}
	p := startProxy(t, u.Host)
	cl.Server = "https://" + p.addr
	copyPath := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*kc, copyPath); err != nil {
		t.Fatal(err)
	}
	rc, err := Config{AuthMethod: AuthKubeconfig, Kubeconfig: path, Context: ctxName}.restConfig()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(rc)
	if err != nil {
		t.Fatal(err)
	}
	return &cluster{kubeconfig: copyPath, context: ctxName, admin: admin, proxy: p}
}

func (c *cluster) namespace(t *testing.T) string {
	t.Helper()
	name := "scrim-k8s-test-" + strings.ToLower(gen(t)[4:14])
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if _, err := c.admin.CoreV1().Namespaces().Create(t.Context(), ns, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = c.admin.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{})
	})
	return name
}

func (c *cluster) adapter(t storetest.TB, cfg Config) *Adapter {
	cfg.AuthMethod, cfg.Kubeconfig, cfg.Context = AuthKubeconfig, c.kubeconfig, c.context
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return New("k8s", cfg)
}

// objectOf maps a reference of a, out of band, to namespace and name.
func objectOf(t storetest.TB, a *Adapter, ref stores.Ref) (string, string) {
	tg, err := a.secretTarget(stores.OpRead, ref)
	if err != nil {
		t.Fatalf("target %s: %v", ref, err)
	}
	return tg.ns, tg.name
}

// seed creates or replaces a Secret through the admin client.
func (c *cluster) seed(t storetest.TB, a *Adapter, ref stores.Ref, fields map[string]secret.Value) {
	ns, name := objectOf(t, a, ref)
	data := map[string][]byte{}
	for k, v := range fields {
		_ = v.Expose(func(b []byte) error { data[k] = append([]byte(nil), b...); return nil })
	}
	api := c.admin.CoreV1().Secrets(ns)
	cur, err := api.Get(t.Context(), name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		_, err = api.Create(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}, Data: data}, metav1.CreateOptions{})
	case err == nil:
		cur.Data = data
		_, err = api.Update(t.Context(), cur, metav1.UpdateOptions{})
	}
	if err != nil {
		t.Fatalf("seed %s: %v", ref, err)
	}
}

func (c *cluster) delete(t storetest.TB, a *Adapter, ref stores.Ref) {
	ns, name := objectOf(t, a, ref)
	if err := c.admin.CoreV1().Secrets(ns).Delete(t.Context(), name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete %s: %v", ref, err)
	}
}

func (c *cluster) outage(storetest.TB) func() {
	// Let a watch the case just started reach the API server, so the
	// outage cuts an established watch rather than delaying its start.
	time.Sleep(time.Second)
	c.proxy.stop()
	return c.proxy.start
}

// TestConformanceReadOnly: the default, read-only instance confined to one
// namespace, seeded out of band.
func TestConformanceReadOnly(t *testing.T) {
	c := requireCluster(t)
	ns := c.namespace(t)
	storetest.Run(t, func(tb storetest.TB) storetest.Harness {
		a := c.adapter(tb, Config{Namespace: ns})
		return storetest.Harness{
			Adapter:      a,
			Seed:         func(t storetest.TB, ref stores.Ref, f map[string]secret.Value) { c.seed(t, a, ref, f) },
			Delete:       func(t storetest.TB, ref stores.Ref) { c.delete(t, a, ref) },
			Outage:       c.outage,
			WatchTimeout: 30 * time.Second,
		}
	})
}

// TestConformanceWritable: a writable instance over two namespaces, which
// refuses writes outside them.
func TestConformanceWritable(t *testing.T) {
	c := requireCluster(t)
	ns, other := c.namespace(t), c.namespace(t)
	storetest.Run(t, func(tb storetest.TB) storetest.Harness {
		a := c.adapter(tb, Config{Namespaces: []string{ns, other}, Writable: true})
		return storetest.Harness{
			Adapter: a,
			Prefix:  ns + "/c-" + strings.ToLower(gen(t)[4:12]),
			Labels:  true,
			Delete:  func(t storetest.TB, ref stores.Ref) { c.delete(t, a, ref) },
			Outage:  c.outage,
			Reject: func(storetest.TB) stores.Ref {
				return stores.Ref{Scheme: "k8s", Path: "kube-system/scrim-rejected"}
			},
			WatchTimeout: 30 * time.Second,
		}
	})
}

// TestLabelsAgainstCluster checks labels of a Secret edited by hand: native
// keys hold, ReadMetadata and List report what Read reports, and the
// last-applied annotation (which holds the data) is not read into labels.
func TestLabelsAgainstCluster(t *testing.T) {
	c := requireCluster(t)
	ns := c.namespace(t)
	p := gen(t)
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "tls.example.com",
			Labels:      map[string]string{"kubernetes.namespace": "forged", "team": "payments"},
			Annotations: map[string]string{"kubernetes.type": "forged", "scrim.hosts": "api.example.test", lastApplied: `{"stringData":{"tls.key":"` + p + `"}}`},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": []byte("cert-" + p), "tls.key": []byte(p)},
	}
	if _, err := c.admin.CoreV1().Secrets(ns).Create(t.Context(), s, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	a := c.adapter(t, Config{Namespaces: []string{ns}})
	ref := stores.Ref{Scheme: "k8s", Path: ns + "/tls/example/com"}
	got, err := a.Read(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	got.Wipe()
	l := got.Meta.Labels
	for k, v := range map[string]string{
		"kubernetes.namespace": ns, "kubernetes.name": "tls.example.com", "kubernetes.type": "kubernetes.io/tls",
		"kubernetes.meta.label.kubernetes.namespace": "forged", "kubernetes.meta.annotation.kubernetes.type": "forged",
		"kubernetes.meta.label.team": "payments", "scrim.hosts": "api.example.test",
	} {
		if l[k] != v {
			t.Errorf("label %s = %q, want %q", k, l[k], v)
		}
	}
	for k, v := range l {
		if strings.Contains(k+v, p) {
			t.Errorf("label %s carries the value", k)
		}
	}
	md, err := a.ReadMetadata(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if !equalMaps(md.Labels, l) || md.Version != got.Meta.Version {
		t.Errorf("ReadMetadata labels %v version %s, Read %v %s", md.Labels, md.Version, l, got.Meta.Version)
	}
	ms, err := a.List(t.Context(), stores.Ref{Scheme: "k8s", Path: ns + "/tls/*"})
	if err != nil || len(ms) != 1 || !equalMaps(ms[0].Labels, l) {
		t.Errorf("List: %v %+v", err, ms)
	}
	if _, err := a.ReadMetadata(t.Context(), stores.Ref{Scheme: "k8s", Path: ns + "/absent"}); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a missing secret: %v", err)
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// proxy forwards TCP to the API server and can cut every connection.
type proxy struct {
	t      *testing.T
	addr   string
	target string

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]bool
}

func startProxy(t *testing.T, target string) *proxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{t: t, addr: ln.Addr().String(), target: target, conns: map[net.Conn]bool{}}
	p.serve(ln)
	t.Cleanup(p.stop)
	return p
}

func (p *proxy) start() {
	var ln net.Listener
	var err error
	for range 50 {
		if ln, err = net.Listen("tcp", p.addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		p.t.Errorf("proxy restart: %v", err)
		return
	}
	p.serve(ln)
}

func (p *proxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = in.Close()
				continue
			}
			p.mu.Lock()
			p.conns[in], p.conns[out] = true, true
			p.mu.Unlock()
			go func() { _, _ = io.Copy(out, in); _ = out.Close() }()
			go func() { _, _ = io.Copy(in, out); _ = in.Close() }()
		}
	}()
}

func (p *proxy) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for c := range p.conns {
		_ = c.Close()
		delete(p.conns, c)
	}
}
