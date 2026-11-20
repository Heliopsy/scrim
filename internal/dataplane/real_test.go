// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// TestRealDataPlane launches the Rust scrim-dataplane named by
// SCRIM_TEST_DATAPLANE (`just test` builds it and sets the variable; so does
// the CI integration job), handshakes, pushes a snapshot and reads status.
// SCRIM_TEST_DATAPLANE=embedded uses the embedded binary of a build with
// -tags embed_dataplane.
func TestRealDataPlane(t *testing.T) {
	path := os.Getenv("SCRIM_TEST_DATAPLANE")
	if path == "" {
		t.Skip("SCRIM_TEST_DATAPLANE is not set; run `just test` to build and use the Rust data plane")
	}
	if path == "embedded" {
		path = ""
	}
	b, err := Resolve(path)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	s := &Supervisor{Binary: b, Snapshot: snapshotSource(&calls), MinBackoff: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitFor(t, "ready", s.Ready)

	s.mu.Lock()
	p := s.cur
	s.mu.Unlock()
	st, err := p.Client.Status(ctx, &pb.StatusRequest{Protocol: Protocol})
	if err != nil {
		t.Fatal(err)
	}
	if !st.GetReady() || st.GetAppliedSnapshotVersion() != 1 || st.GetValueCount() != 1 {
		t.Fatalf("status = %+v", st)
	}
	if err := s.Push(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Client.Status(ctx, &pb.StatusRequest{Protocol: 42}); err == nil {
		t.Fatal("the data plane accepted a foreign protocol version")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("data plane still running after the control plane stopped")
	}
	if err := p.Err(); err != nil {
		t.Fatalf("data plane exited with %v, want a clean exit", err)
	}
}
