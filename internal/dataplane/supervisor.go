// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/version"
)

// ErrProtocolMismatch means the data plane speaks another protocol version.
// It is permanent: the supervisor stops instead of restarting.
var ErrProtocolMismatch = errors.New("dataplane: protocol version mismatch")

// SnapshotFunc builds the snapshot to push. The supervisor sets protocol and
// version, and wipes the secret bytes once the snapshot is sent, so the
// function must return fresh copies every time.
type SnapshotFunc func(ctx context.Context) (*pb.Snapshot, error)

// AskFunc answers an ask from the data plane. Anything but an allow answer
// denies.
type AskFunc func(ctx context.Context, req *pb.AskRequest) *pb.AskAnswer

// Supervisor runs the data plane and keeps it running. Ready is false
// whenever the data plane is down or has no snapshot, and health uses it,
// so traffic is refused rather than served unredacted.
type Supervisor struct {
	Binary   Binary
	Options  StartOptions
	Log      *slog.Logger
	Snapshot SnapshotFunc
	// OnEvents receives every event batch. Optional.
	OnEvents func(*pb.EventBatch)
	// OnAsk answers asks; nil denies all.
	OnAsk AskFunc
	// StartTimeout bounds launch, handshake and first snapshot.
	StartTimeout time.Duration
	// MinBackoff and MaxBackoff bound the delay between restarts.
	MinBackoff, MaxBackoff time.Duration

	version atomic.Uint64
	ready   atomic.Bool
	mu      sync.Mutex
	cur     *Process
	restart atomic.Uint64
}

// Ready reports whether the data plane is up with a snapshot applied.
func (s *Supervisor) Ready() bool { return s.ready.Load() }

// Restarts reports how many times the data plane was started after the
// first.
func (s *Supervisor) Restarts() uint64 { return s.restart.Load() }

// Health is an obs.Check for readiness.
func (s *Supervisor) Health(context.Context) error {
	if !s.Ready() {
		return errors.New("data plane is not running or has no snapshot")
	}
	return nil
}

// Run starts the data plane and restarts it with backoff until ctx ends,
// then stops it. It returns ctx's error, or ErrProtocolMismatch.
func (s *Supervisor) Run(ctx context.Context) error {
	log := s.logger()
	backoff := s.minBackoff()
	for first := true; ; first = false {
		if !first {
			s.restart.Add(1)
		}
		began := time.Now()
		err := s.session(ctx)
		s.ready.Store(false)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrProtocolMismatch) {
			log.Error("refusing to run the data plane", "err", err)
			return err
		}
		if time.Since(began) > time.Minute {
			backoff = s.minBackoff()
		}
		log.Error("data plane stopped; traffic is refused until it is back", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, s.maxBackoff())
	}
}

// Push builds a new snapshot and applies it to the running data plane.
func (s *Supervisor) Push(ctx context.Context) error {
	s.mu.Lock()
	p := s.cur
	s.mu.Unlock()
	if p == nil {
		return errors.New("dataplane: not running")
	}
	return s.push(ctx, p)
}

func (s *Supervisor) session(ctx context.Context) error {
	log := s.logger()
	opts := s.Options
	opts.Log = log
	p, err := Start(s.Binary, opts)
	if err != nil {
		return err
	}
	defer p.Stop(5 * time.Second)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-p.Done():
			cancel()
		case <-sctx.Done():
		}
	}()

	startCtx, startCancel := context.WithTimeout(sctx, s.startTimeout())
	hello, err := p.Client.Hello(startCtx, &pb.HelloRequest{Protocol: Protocol, ControlPlaneVersion: version.Version})
	if err == nil && hello.GetProtocol() != Protocol {
		err = fmt.Errorf("%w: data plane speaks %d, control plane %d", ErrProtocolMismatch, hello.GetProtocol(), Protocol)
	}
	if status.Code(err) == codes.FailedPrecondition {
		err = fmt.Errorf("%w: %w", ErrProtocolMismatch, err)
	}
	if err != nil {
		startCancel()
		return err
	}
	log.Info("data plane started", "pid", hello.GetPid(), "how", p.How, "binary", s.Binary.Source,
		"version", hello.GetDataPlaneVersion(), "memory_locked", hello.GetMemoryLocked(), "dumpable", hello.GetDumpable())
	if !hello.GetMemoryLocked() {
		log.Warn("data plane memory is not locked; values may be swapped to disk")
	}

	s.mu.Lock()
	s.cur = p
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.cur = nil
		s.mu.Unlock()
	}()

	events, err := p.Client.Events(sctx, &pb.EventsRequest{Protocol: Protocol})
	if err != nil {
		startCancel()
		return fmt.Errorf("dataplane: events: %w", err)
	}
	asks, err := p.Client.Asks(sctx)
	if err != nil {
		startCancel()
		return fmt.Errorf("dataplane: asks: %w", err)
	}
	if err := s.push(startCtx, p); err != nil {
		startCancel()
		return err
	}
	startCancel()
	s.ready.Store(true)

	var wg sync.WaitGroup
	wg.Go(func() { s.consumeEvents(events) })
	wg.Go(func() { s.answerAsks(sctx, asks) })
	<-sctx.Done()
	s.ready.Store(false)
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := p.Err(); err != nil {
		return fmt.Errorf("dataplane exited: %w", err)
	}
	return errors.New("dataplane exited")
}

func (s *Supervisor) push(ctx context.Context, p *Process) error {
	if s.Snapshot == nil {
		return errors.New("dataplane: no snapshot source")
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("dataplane: building snapshot: %w", err)
	}
	defer wipe(snap)
	snap.Protocol = Protocol
	snap.Version = s.version.Add(1)
	resp, err := p.Client.ApplySnapshot(ctx, snap)
	if err != nil {
		return fmt.Errorf("dataplane: snapshot %d rejected: %w", snap.Version, err)
	}
	s.logger().Info("snapshot applied", "version", resp.GetAppliedVersion(), "values", resp.GetValueCount())
	return nil
}

// wipe zeroes the secret bytes of a sent snapshot. The gRPC send buffer is
// out of reach; that copy is a documented limitation.
func wipe(snap *pb.Snapshot) {
	for _, v := range snap.GetValues() {
		clear(v.Value)
	}
	for _, k := range snap.GetPlaceholderKeys() {
		clear(k.Key)
	}
}

func (s *Supervisor) consumeEvents(stream pb.DataPlane_EventsClient) {
	for {
		batch, err := stream.Recv()
		if err != nil {
			return
		}
		if d := batch.GetDropped(); d > 0 {
			s.logger().Warn("data plane dropped events", "count", d)
		}
		if s.OnEvents != nil {
			s.OnEvents(batch)
		}
	}
}

func (s *Supervisor) answerAsks(ctx context.Context, stream pb.DataPlane_AsksClient) {
	var send sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		req, err := stream.Recv()
		if err != nil {
			return
		}
		wg.Go(func() {
			ans := &pb.AskAnswer{Effect: pb.Effect_EFFECT_DENY, Reason: "no approval handler"}
			if s.OnAsk != nil {
				actx := ctx
				if dl := req.GetDeadlineUnixNano(); dl > 0 {
					var cancel context.CancelFunc
					actx, cancel = context.WithDeadline(ctx, time.Unix(0, dl))
					defer cancel()
				}
				if a := s.OnAsk(actx, req); a != nil {
					ans = a
				}
			}
			ans.Protocol, ans.Id = Protocol, req.GetId()
			send.Lock()
			defer send.Unlock()
			_ = stream.Send(ans)
		})
	}
}

func (s *Supervisor) logger() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func (s *Supervisor) startTimeout() time.Duration {
	if s.StartTimeout > 0 {
		return s.StartTimeout
	}
	return 10 * time.Second
}

func (s *Supervisor) minBackoff() time.Duration {
	if s.MinBackoff > 0 {
		return s.MinBackoff
	}
	return 200 * time.Millisecond
}

func (s *Supervisor) maxBackoff() time.Duration {
	if s.MaxBackoff > 0 {
		return s.MaxBackoff
	}
	return 30 * time.Second
}
