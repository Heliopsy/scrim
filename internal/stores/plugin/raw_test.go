// SPDX-License-Identifier: AGPL-3.0-only

package plugin_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/heliopsy/scrim/internal/stores"
	storeplugin "github.com/heliopsy/scrim/internal/stores/plugin"
	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// rawStore is a hostile plugin written against the generated code without
// the SDK: it echoes a value in its status messages, answers for paths it
// was not asked about, and never confirms a watch.
type rawStore struct {
	pb.UnimplementedPluginServer
	pb.UnimplementedStoreServer
	value string
}

func (rawStore) Handshake(context.Context, *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	return &pb.HandshakeResponse{Protocol: 1, Kind: pb.Kind_KIND_STORE, Capabilities: []pb.Capability{
		pb.Capability_CAPABILITY_READ, pb.Capability_CAPABILITY_LIST, pb.Capability_CAPABILITY_WATCH,
	}}, nil
}

func (rawStore) ValidateConfig(context.Context, *pb.ConfigRequest) (*pb.ValidateConfigResponse, error) {
	return &pb.ValidateConfigResponse{Protocol: 1}, nil
}

func (rawStore) Configure(context.Context, *pb.ConfigRequest) (*pb.ConfigureResponse, error) {
	return &pb.ConfigureResponse{Protocol: 1}, nil
}

func (r rawStore) Read(_ context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	switch req.GetRef().GetPath() {
	case "other":
		return &pb.ReadResponse{Protocol: 1, Meta: &pb.Metadata{Path: "elsewhere"},
			Fields: []*pb.Field{{Name: "value", Value: []byte(r.value)}}}, nil
	case "internal":
		return nil, status.Errorf(codes.Internal, "backend said %s", r.value)
	}
	return nil, status.Errorf(codes.NotFound, "secret with value %s is gone", r.value)
}

func (rawStore) List(context.Context, *pb.ListRequest) (*pb.ListResponse, error) {
	return &pb.ListResponse{Protocol: 1, Entries: []*pb.Metadata{{Path: "outside/prefix"}}}, nil
}

func (rawStore) Watch(_ *pb.WatchRequest, s grpc.ServerStreamingServer[pb.WatchEvent]) error {
	<-s.Context().Done()
	return nil
}

type oneListener struct {
	c    chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *oneListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, errors.New("closed")
	}
}
func (l *oneListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneListener) Addr() net.Addr { return &net.UnixAddr{Name: "plugin", Net: "unix"} }

func serveRaw() int {
	nc, err := net.FileConn(os.NewFile(3, "scrim"))
	if err != nil {
		return 1
	}
	l := &oneListener{c: make(chan net.Conn, 1), done: make(chan struct{})}
	l.c <- nc
	srv := grpc.NewServer()
	r := rawStore{value: os.Getenv("SCRIM_TEST_VALUE")}
	pb.RegisterPluginServer(srv, r)
	pb.RegisterStoreServer(srv, r)
	_ = srv.Serve(l)
	return 0
}

func openRaw(t *testing.T, value string) stores.Adapter {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe) //nolint:gosec // the running test binary
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "raw")
	if err := os.WriteFile(bin, b, 0o700); err != nil { //nolint:gosec // an executable
		t.Fatal(err)
	}
	a, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{Name: "raw", Kind: storeplugin.Kind, Resolve: noResolve,
		Options: map[string]any{"command": bin, "timeout": "500ms", "env": map[string]any{"SCRIM_TEST_RAW": "1", "SCRIM_TEST_VALUE": value}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// A hostile plugin cannot get a value into scrim's errors through its
// status messages, nor pass off a secret for another path or a listing
// outside the prefix, and a watch it never confirms fails closed.
func TestHostilePlugin(t *testing.T) {
	value := fmt.Sprintf("val-%d", time.Now().UnixNano())
	a := openRaw(t, value)
	ctx := t.Context()
	leak := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: no error", what)
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), value) {
			t.Errorf("%s: error carries the value: %v", what, err)
		}
	}
	_, err := a.Read(ctx, stores.MustParseRef("raw://gone"))
	if !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("read: %v, want not found", err)
	}
	leak("read", err)
	_, err = a.Read(ctx, stores.MustParseRef("raw://internal"))
	if !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("internal error: %v, want unavailable", err)
	}
	leak("internal error", err)
	_, err = a.Read(ctx, stores.MustParseRef("raw://other"))
	if !errors.Is(err, stores.ErrUnavailable) || !strings.Contains(err.Error(), "answered for another path") {
		t.Errorf("read answered for another path: %v", err)
	}
	leak("other path", err)
	_, err = a.List(ctx, stores.MustParseRef("raw://inside"))
	if err == nil || !strings.Contains(err.Error(), "outside the prefix") {
		t.Errorf("list outside the prefix: %v", err)
	}
	start := time.Now()
	_, err = a.Watch(ctx, stores.MustParseRef("raw://inside"))
	if !errors.Is(err, stores.ErrUnavailable) || !strings.Contains(err.Error(), "did not confirm watch within 500ms") {
		t.Errorf("unconfirmed watch: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("unconfirmed watch took %s", time.Since(start))
	}
}
