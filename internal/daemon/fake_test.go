// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
	"github.com/heliopsy/scrim/internal/testing/testhome"
)

// The test binary doubles as a fake data plane: run with SCRIM_FAKE_DP=1 it
// serves the boundary protocol on the inherited socket, writes every
// snapshot it applies to SCRIM_FAKE_DIR, and, when asked, sends one ask and
// one capture after the first snapshot and records the answers there. The
// real data plane is exercised by TestEndToEndRealDataPlane.
//
// TestMain also points HOME and the XDG directories at a temporary
// directory, so no test touches the user's state, keys, CA or sockets.
func TestMain(m *testing.M) {
	if os.Getenv("SCRIM_FAKE_DP") == "1" {
		os.Exit(fakeDataPlane())
	}
	code := testhome.Run(m)
	pgtest.Stop()
	os.Exit(code)
}

const (
	fakeAskFile     = "ask.json"
	fakeCaptureFile = "capture.json"
)

func fakeDataPlane() int {
	fd, _ := strconv.Atoi(os.Getenv("SCRIM_DP_FD"))
	c, err := net.FileConn(os.NewFile(uintptr(fd), "control"))
	if err != nil {
		return 2
	}
	srv := grpc.NewServer()
	f := &fakeDP{dir: os.Getenv("SCRIM_FAKE_DIR"), first: make(chan struct{})}
	pb.RegisterDataPlaneServer(srv, f)
	done := make(chan struct{})
	go func() { _ = srv.Serve(&oneConn{c: c, done: done}) }()
	<-done
	return 0
}

type fakeDP struct {
	pb.UnimplementedDataPlaneServer
	dir       string
	mu        sync.Mutex
	applied   uint64
	snap      *pb.Snapshot
	first     chan struct{}
	firstOnce sync.Once
}

func (f *fakeDP) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{Protocol: uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT), DataPlaneVersion: "fake", Pid: uint32(os.Getpid())}, nil //nolint:gosec // pids fit
}

func (f *fakeDP) ApplySnapshot(_ context.Context, s *pb.Snapshot) (*pb.ApplySnapshotResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.GetVersion() <= f.applied {
		return nil, errors.New("stale")
	}
	b, err := proto.Marshal(s)
	if err != nil {
		return nil, err
	}
	tmp := filepath.Join(f.dir, "snap.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(f.dir, "snap.pb")); err != nil {
		return nil, err
	}
	f.applied, f.snap = s.GetVersion(), s
	f.firstOnce.Do(func() { close(f.first) })
	return &pb.ApplySnapshotResponse{Protocol: 1, AppliedVersion: s.GetVersion(), ValueCount: uint32(len(s.GetValues()))}, nil //nolint:gosec // small
}

func (f *fakeDP) Status(context.Context, *pb.StatusRequest) (*pb.StatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := &pb.StatusResponse{Protocol: 1, Ready: f.snap != nil, AppliedSnapshotVersion: f.applied, DataPlaneVersion: "fake"}
	for _, l := range f.snap.GetListeners() {
		st.Listeners = append(st.Listeners, &pb.ListenerStatus{Name: l.GetName(), Address: l.GetAddress(), Bound: true})
	}
	return st, nil
}

func (f *fakeDP) Events(_ *pb.EventsRequest, s grpc.ServerStreamingServer[pb.EventBatch]) error {
	<-f.first
	ev := &pb.Event{Seq: 1, Kind: pb.EventKind_EVENT_KIND_REDACTION, Provider: "anthropic", Ref: "testenv://SCRIMTEST_TOKEN",
		RequestId: "req-1", Count: 2, TimeUnixNano: time.Now().UnixNano()}
	if err := s.Send(&pb.EventBatch{Protocol: 1, Events: []*pb.Event{ev}}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (f *fakeDP) Asks(s grpc.BidiStreamingServer[pb.AskAnswer, pb.AskRequest]) error {
	ref := os.Getenv("SCRIM_FAKE_ASK_REF")
	if ref == "" {
		<-s.Context().Done()
		return nil
	}
	<-f.first
	req := &pb.AskRequest{Protocol: 1, Id: 7, Rule: "r", DeadlineUnixNano: time.Now().Add(10 * time.Second).UnixNano(),
		Request: &pb.PolicyRequest{AgentId: "dev", Action: "inject", Ref: ref, Host: "api.example.com"}}
	if err := s.Send(req); err != nil {
		return err
	}
	ans, err := s.Recv()
	if err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(f.dir, fakeAskFile), map[string]any{"id": ans.GetId(), "effect": ans.GetEffect().String(), "reason": ans.GetReason()}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (f *fakeDP) Captures(s grpc.BidiStreamingServer[pb.CaptureResult, pb.CaptureRequest]) error {
	ref := os.Getenv("SCRIM_FAKE_CAPTURE_REF")
	if ref == "" {
		<-s.Context().Done()
		return nil
	}
	<-f.first
	req := &pb.CaptureRequest{Protocol: 1, Id: 9, Rule: "issued", Ref: ref, Destination: "https://api.example.com:443",
		Value: []byte(os.Getenv("SCRIM_FAKE_CAPTURE_VALUE")), DeadlineUnixNano: time.Now().Add(10 * time.Second).UnixNano()}
	if err := s.Send(req); err != nil {
		return err
	}
	res, err := s.Recv()
	if err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(f.dir, fakeCaptureFile), map[string]any{"id": res.GetId(), "placeholder": res.GetPlaceholder(), "error": res.GetError()}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func writeJSONFile(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// oneConn is a listener that yields one connection, then blocks until it
// closes.
type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConn) Accept() (net.Conn, error) {
	var out net.Conn
	l.once.Do(func() { out = &closeConn{Conn: l.c, done: l.done} })
	if out != nil {
		return out, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.c.LocalAddr() }

type closeConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.once.Do(func() { close(c.done) })
	}
	return n, err
}

func (c *closeConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}
