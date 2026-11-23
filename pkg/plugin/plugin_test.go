// SPDX-License-Identifier: AGPL-3.0-only

package plugin_test

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/heliopsy/scrim/pkg/plugin"
	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// store records what reached it.
type store struct {
	mu        sync.Mutex
	secrets   map[string][]byte
	wrote     map[string][]byte
	readCalls int
}

func (*store) Info() plugin.Info {
	return plugin.Info{Name: "t", Capabilities: []plugin.Capability{plugin.CapRead, plugin.CapWrite}}
}
func (*store) ValidateConfig(c plugin.Config) []string {
	for k, v := range c.Secrets {
		if len(v) != 0 {
			return []string{"validation received a value for " + k}
		}
	}
	return nil
}

func (s *store) Configure(_ context.Context, c plugin.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = c.Secrets // kept on purpose: the test checks the SDK zeroes it
	return nil
}

func (s *store) Read(context.Context, plugin.Ref) (plugin.Secret, error) {
	s.mu.Lock()
	s.readCalls++
	s.mu.Unlock()
	return plugin.Secret{}, errors.New("backend said: the value is hunter2-like")
}

func (*store) List(context.Context, string) ([]plugin.Metadata, error) {
	return nil, plugin.ErrUnsupported
}

func (*store) Watch(context.Context, string) (<-chan plugin.Change, error) {
	return nil, plugin.ErrUnsupported
}

func (s *store) Write(_ context.Context, path string, f map[string][]byte, _ plugin.WriteOptions) (plugin.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrote = f // kept on purpose: the test checks the SDK zeroes it
	return plugin.Metadata{Path: path}, nil
}

func (*store) Health(context.Context) error { return nil }

func serve(t *testing.T, s *store) *grpc.ClientConn {
	t.Helper()
	a, b := net.Pipe()
	go func() { _ = plugin.ServeConn(b, pb.Kind_KIND_STORE, s) }()
	var once sync.Once
	conn, err := grpc.NewClient("passthrough:///p",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			var c net.Conn
			once.Do(func() { c = a })
			if c == nil {
				return nil, errors.New("used")
			}
			return c, nil
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodecV2(pb.Codec())))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func code(err error) codes.Code { return status.Code(err) }

func TestProtocolAndOrder(t *testing.T) {
	s := &store{}
	conn := serve(t, s)
	ctx := t.Context()
	pc, sc := pb.NewPluginClient(conn), pb.NewStoreClient(conn)

	if _, err := pc.Handshake(ctx, &pb.HandshakeRequest{Protocol: 2, Kind: pb.Kind_KIND_STORE}); code(err) != codes.FailedPrecondition {
		t.Fatalf("handshake with protocol 2: %v", err)
	}
	h, err := pc.Handshake(ctx, &pb.HandshakeRequest{Protocol: plugin.Protocol, Kind: pb.Kind_KIND_STORE})
	if err != nil || h.GetKind() != pb.Kind_KIND_STORE || len(h.GetCapabilities()) != 2 {
		t.Fatalf("handshake: %v %v", h, err)
	}
	if _, err := sc.Read(ctx, &pb.ReadRequest{Protocol: plugin.Protocol, Ref: &pb.Ref{Path: "a"}}); code(err) != codes.FailedPrecondition {
		t.Fatalf("read before Configure: %v", err)
	}
	v, err := pc.ValidateConfig(ctx, &pb.ConfigRequest{Protocol: plugin.Protocol, Secrets: map[string][]byte{"token": []byte("x")}})
	if err != nil || len(v.GetProblems()) != 0 {
		t.Fatalf("validate saw a credential value: %v %v", v, err)
	}
	cred := []byte("credential-bytes")
	if _, err := pc.Configure(ctx, &pb.ConfigRequest{Protocol: plugin.Protocol, Secrets: map[string][]byte{"token": cred}}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	kept := string(s.secrets["token"])
	s.mu.Unlock()
	if strings.Trim(kept, "\x00") != "" {
		t.Fatal("credential bytes were not zeroed after Configure returned")
	}
	if _, err := sc.List(ctx, &pb.ListRequest{Protocol: plugin.Protocol}); code(err) != codes.Unimplemented {
		t.Fatalf("list outside the capabilities: %v", err)
	}
	_, err = sc.Read(ctx, &pb.ReadRequest{Protocol: plugin.Protocol, Ref: &pb.Ref{Path: "a"}})
	if code(err) != codes.Unavailable {
		t.Fatalf("an unknown error must read as unavailable: %v", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the plugin's own error text was sent")
	}
	if _, err := sc.Read(ctx, &pb.ReadRequest{Protocol: 7, Ref: &pb.Ref{Path: "a"}}); code(err) != codes.FailedPrecondition {
		t.Fatalf("read with protocol 7: %v", err)
	}
	if _, err := sc.Write(ctx, &pb.WriteRequest{Protocol: plugin.Protocol, Path: "a", Fields: []*pb.Field{{Name: "v", Value: []byte("value-bytes")}}}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	wrote := string(s.wrote["v"])
	s.mu.Unlock()
	if strings.Trim(wrote, "\x00") != "" {
		t.Fatal("written bytes were not zeroed after Write returned")
	}
}

func TestCodecWipesAfterMarshal(t *testing.T) {
	c := pb.Codec()
	val := []byte("secret-material")
	req := &pb.WriteRequest{Protocol: 1, Path: "p", Fields: []*pb.Field{{Name: "v", Value: val}}}
	out, err := c.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Trim(string(val), "\x00") != "" {
		t.Fatal("the message still holds the value after marshalling")
	}
	var back pb.WriteRequest
	if err := c.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if string(back.GetFields()[0].GetValue()) != "secret-material" {
		t.Fatal("round trip lost the value")
	}
	buf := out[0].ReadOnlyData()
	out.Free()
	if strings.Contains(string(buf), "secret-material") {
		t.Fatal("the marshalled bytes still hold the value once released")
	}
}

// The SDK and the example plugins import nothing internal to scrim, so a
// plugin outside the repository can be written the same way.
func TestNoInternalImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}",
		"github.com/heliopsy/scrim/pkg/plugin", "github.com/heliopsy/scrim/examples/plugins/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		if strings.HasPrefix(p, "github.com/heliopsy/scrim/internal") {
			t.Errorf("the plugin SDK or an example depends on %s", p)
		}
	}
}
