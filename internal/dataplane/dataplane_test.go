// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

func fakeOpts(extra ...string) StartOptions {
	return StartOptions{ExtraEnv: append([]string{"SCRIM_FAKE_DP=1"}, extra...)}
}

func TestStartAndStop(t *testing.T) {
	for _, file := range []bool{false, true} {
		name := "memfd"
		if file || runtime.GOOS != "linux" {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			o := fakeOpts()
			o.forceFile = file
			p, err := Start(fakeBinary(t), o)
			if err != nil {
				t.Fatal(err)
			}
			if p.How != name {
				t.Errorf("ran via %s, want %s", p.How, name)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			hello, err := p.Client.Hello(ctx, &pb.HelloRequest{Protocol: Protocol})
			if err != nil {
				t.Fatal(err)
			}
			if int(hello.GetPid()) != p.Pid() {
				t.Errorf("pid %d, want %d", hello.GetPid(), p.Pid())
			}
			p.Stop(5 * time.Second)
			select {
			case <-p.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("data plane did not exit when its socket closed")
			}
		})
	}
}

func TestChildEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("SCRIM_TEST_LEAK", "must-not-reach-the-child")
	o := fakeOpts()
	exe, err := prepare(fakeBinary(t), runtime.GOOS != "linux")
	if err != nil {
		t.Fatal(err)
	}
	defer exe.Close()
	p, err := spawn(exe, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop(time.Second)
	for _, kv := range p.cmd.Env {
		if kv == "SCRIM_TEST_LEAK=must-not-reach-the-child" {
			t.Fatal("parent environment leaked into the data plane")
		}
	}
}

func TestUpstreamCAFileReachesTheChild(t *testing.T) {
	for _, file := range []string{"", "/etc/scrim/upstream-ca.pem"} {
		o := fakeOpts()
		o.UpstreamCAFile = file
		exe, err := prepare(fakeBinary(t), runtime.GOOS != "linux")
		if err != nil {
			t.Fatal(err)
		}
		p, err := spawn(exe, o, nil)
		exe.Close()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, kv := range p.cmd.Env {
			if strings.HasPrefix(kv, "SCRIM_DP_EXTRA_CA_FILE=") {
				got = append(got, kv)
			}
		}
		p.Stop(time.Second)
		want := []string{}
		if file != "" {
			want = []string{"SCRIM_DP_EXTRA_CA_FILE=" + file}
		}
		if !slices.Equal(got, want) {
			t.Errorf("UpstreamCAFile %q: child environment has %q, want %q", file, got, want)
		}
	}
}

func TestWriteVerified(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scrim")
	img := []byte("#!/bin/false\nnot really a binary\n")
	b := Binary{Image: img, Sum: sha256.Sum256(img)}
	f, err := writeVerified(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	path := filepath.Join(dir, fileName(b.Sum))
	// Tamper with the cached file: it must be replaced, not executed.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openVerified(path, b.Sum); err == nil {
		t.Fatal("tampered file passed verification")
	}
	f, err = writeVerified(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	got, _ := os.ReadFile(path)
	if string(got) != string(img) {
		t.Fatal("tampered file was not replaced")
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := writeVerified(dir, b); err == nil {
		t.Fatal("world-writable directory accepted")
	}
}

func TestResolve(t *testing.T) {
	if _, err := Resolve(""); Embedded() == (err != nil) {
		t.Fatalf("Resolve(\"\") = %v with Embedded() = %v", err, Embedded())
	}
	if !Embedded() {
		if _, err := Resolve(""); !errors.Is(err, ErrNoBinary) {
			t.Fatal(err)
		}
	}
	if _, err := Resolve(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing path accepted")
	}
}

func snapshotSource(calls *atomic.Int32) SnapshotFunc {
	return func(context.Context) (*pb.Snapshot, error) {
		calls.Add(1)
		return &pb.Snapshot{
			Values:          []*pb.ValueEntry{{Ref: "mem://x#value", Value: []byte("generated-in-test")}},
			PlaceholderKeys: []*pb.PlaceholderKey{{Version: 1, Key: make([]byte, 32), Current: true}},
		}, nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSupervisorRestartsAndAnswersAsks(t *testing.T) {
	var calls atomic.Int32
	var batches atomic.Int32
	asked := make(chan *pb.AskRequest, 4)
	captured := make(chan string, 4)
	s := &Supervisor{
		Binary:   fakeBinary(t),
		Options:  fakeOpts(),
		Snapshot: snapshotSource(&calls),
		OnEvents: func(*pb.EventBatch) { batches.Add(1) },
		OnAsk: func(_ context.Context, r *pb.AskRequest) *pb.AskAnswer {
			asked <- r
			return &pb.AskAnswer{Effect: pb.Effect_EFFECT_ALLOW}
		},
		OnCapture: func(_ context.Context, r *pb.CaptureRequest) (string, error) {
			captured <- r.GetRule() + "=" + string(r.GetValue())
			return "SCRIM_NEW_TOKEN", nil
		},
		MinBackoff: 10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, "ready", s.Ready)
	if got := <-captured; got != "issued=captured-in-test" {
		t.Fatalf("capture handler got %q", got)
	}
	if got := <-captured; got != "stored:SCRIM_NEW_TOKEN=x" {
		t.Fatalf("the placeholder did not reach the data plane: %q", got)
	}
	if pem, err := s.TrustBundle(ctx); err != nil || pem == "" {
		t.Fatalf("TrustBundle = %q, %v", pem, err)
	}
	if dp := s.DataPlaneStatus(ctx); !dp.Running || !dp.Healthy || dp.PID == 0 {
		t.Fatalf("DataPlaneStatus = %+v", dp)
	}
	if err := s.Health(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "an event batch", func() bool { return batches.Load() > 0 })
	if r := <-asked; r.GetId() != 7 {
		t.Fatalf("first ask id %d", r.GetId())
	}
	if r := <-asked; r.GetRule() != "answered" {
		t.Fatal("the allow answer did not reach the data plane")
	}
	if err := s.Push(ctx); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Kill the data plane: the supervisor must go not-ready, restart it
	// and push a snapshot again.
	s.mu.Lock()
	p := s.cur
	s.mu.Unlock()
	_ = p.cmd.Process.Kill()
	waitFor(t, "restart", func() bool { return s.Restarts() >= 1 && s.Ready() })
	if calls.Load() < 3 {
		t.Fatalf("snapshot built %d times, want a push after restart", calls.Load())
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	if s.Ready() {
		t.Fatal("ready after stop")
	}
	if dp := s.DataPlaneStatus(context.Background()); dp.Running || dp.Detail == "" {
		t.Fatalf("DataPlaneStatus after stop = %+v", dp)
	}
}

func TestProbe(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dp := Probe{Path: exe, Options: fakeOpts()}.DataPlaneStatus(context.Background())
	if !dp.Running || !dp.Healthy || dp.Version != "fake" {
		t.Fatalf("probe = %+v", dp)
	}
	dp = Probe{Path: filepath.Join(t.TempDir(), "missing")}.DataPlaneStatus(context.Background())
	if dp.Running || dp.Detail == "" {
		t.Fatalf("probe of a missing binary = %+v", dp)
	}
}

func TestSupervisorRefusesProtocolMismatch(t *testing.T) {
	var calls atomic.Int32
	s := &Supervisor{Binary: fakeBinary(t), Options: fakeOpts("SCRIM_FAKE_PROTOCOL=99"), Snapshot: snapshotSource(&calls)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.Run(ctx); !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("Run = %v, want ErrProtocolMismatch", err)
	}
	if calls.Load() != 0 {
		t.Fatal("a snapshot was sent to a mismatched data plane")
	}
}

func TestWipeClearsSentSecrets(t *testing.T) {
	v := []byte("generated-in-test")
	k := []byte{1, 2, 3}
	ca := []byte("generated-ca-key")
	wipe(&pb.Snapshot{Values: []*pb.ValueEntry{{Value: v}}, PlaceholderKeys: []*pb.PlaceholderKey{{Key: k}},
		ToolProxyCa: []*pb.CaCertificate{{CertPem: "public", KeyPem: ca}}})
	for _, b := range append(append(v, k...), ca...) {
		if b != 0 {
			t.Fatal("secret bytes left after wipe")
		}
	}
}
