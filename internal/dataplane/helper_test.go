// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// The test binary doubles as a fake data plane: run with SCRIM_FAKE_DP=1 it
// serves the protocol on fd 3 the way scrim-dataplane does. That tests the
// launch, handshake and supervision without a Rust build; the real binary
// is exercised by TestRealDataPlane.
func TestMain(m *testing.M) {
	if os.Getenv("SCRIM_FAKE_DP") == "1" {
		os.Exit(fakeDataPlane())
	}
	os.Exit(m.Run())
}

func fakeDataPlane() int {
	fd, _ := strconv.Atoi(os.Getenv("SCRIM_DP_FD"))
	c, err := net.FileConn(os.NewFile(uintptr(fd), "control"))
	if err != nil {
		return 2
	}
	protocol := Protocol
	if v := os.Getenv("SCRIM_FAKE_PROTOCOL"); v != "" {
		n, _ := strconv.Atoi(v)
		protocol = uint32(n)
	}
	srv := grpc.NewServer()
	pb.RegisterDataPlaneServer(srv, &fake{protocol: protocol})
	closed := make(chan struct{})
	l := &oneConn{c: &notifyConn{Conn: c, closed: closed}, done: make(chan struct{})}
	go func() { _ = srv.Serve(l) }()
	<-closed
	return 0
}

type fake struct {
	pb.UnimplementedDataPlaneServer
	protocol uint32
	mu       sync.Mutex
	applied  uint64
}

func (f *fake) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{Protocol: f.protocol, DataPlaneVersion: "fake", Pid: uint32(os.Getpid())}, nil
}

func (f *fake) ApplySnapshot(_ context.Context, s *pb.Snapshot) (*pb.ApplySnapshotResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.GetVersion() <= f.applied {
		return nil, errors.New("stale")
	}
	f.applied = s.GetVersion()
	return &pb.ApplySnapshotResponse{Protocol: Protocol, AppliedVersion: s.GetVersion(), ValueCount: uint32(len(s.GetValues()))}, nil
}

func (f *fake) Events(_ *pb.EventsRequest, s grpc.ServerStreamingServer[pb.EventBatch]) error {
	if err := s.Send(&pb.EventBatch{Protocol: Protocol, Events: []*pb.Event{{Seq: 1, Kind: pb.EventKind_EVENT_KIND_REDACTION}}}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (f *fake) Asks(s grpc.BidiStreamingServer[pb.AskAnswer, pb.AskRequest]) error {
	if err := s.Send(&pb.AskRequest{Protocol: Protocol, Id: 7, Request: &pb.PolicyRequest{Host: "api.github.com"}}); err != nil {
		return err
	}
	a, err := s.Recv()
	if err != nil {
		return err
	}
	if a.GetId() == 7 && a.GetEffect() == pb.Effect_EFFECT_ALLOW {
		_ = s.Send(&pb.AskRequest{Protocol: Protocol, Id: 8, Rule: "answered"})
	}
	<-s.Context().Done()
	return nil
}

func (f *fake) Captures(s grpc.BidiStreamingServer[pb.CaptureResult, pb.CaptureRequest]) error {
	if err := s.Send(&pb.CaptureRequest{Protocol: Protocol, Id: 9, Rule: "issued", Ref: "mem://new#token", Value: []byte("captured-in-test")}); err != nil {
		return err
	}
	r, err := s.Recv()
	if err != nil {
		return err
	}
	if r.GetId() == 9 && r.GetError() == "" {
		_ = s.Send(&pb.CaptureRequest{Protocol: Protocol, Id: 10, Rule: "stored:" + r.GetPlaceholder(), Value: []byte("x")})
	}
	<-s.Context().Done()
	return nil
}

func (f *fake) Status(context.Context, *pb.StatusRequest) (*pb.StatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.StatusResponse{Protocol: Protocol, Ready: f.applied > 0, AppliedSnapshotVersion: f.applied, CaTrustBundlePem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"}, nil
}

// oneConn is a listener that yields one connection.
type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.c.LocalAddr() }

type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// fakeBinary is this test executable as a data plane image.
func fakeBinary(t *testing.T) Binary {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	img, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	return Binary{Image: img, Sum: sha256.Sum256(img), Source: "test"}
}
