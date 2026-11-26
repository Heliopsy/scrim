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
	"github.com/heliopsy/scrim/internal/secret"
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

// CaptureFunc stores a value a tool-proxy capture rule took from a response
// and returns the placeholder the agent sees. req.Value is wiped after it
// returns, so it must copy what it keeps (into a secret.Value). An error
// withholds the field; its text must not contain the value.
type CaptureFunc func(ctx context.Context, req *pb.CaptureRequest) (placeholder string, err error)

// CertificateCheckFunc checks a client certificate chain a TLS listener
// accepted, leaf first, DER, and returns why it is refused, "" to serve the
// connection.
type CertificateCheckFunc func(ctx context.Context, chain [][]byte) (reason string)

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
	// OnCapture stores captured values; nil withholds every captured field.
	OnCapture CaptureFunc
	// OnCertificateCheck checks client certificate chains while OCSP is on;
	// nil refuses every chain the data plane sends.
	OnCertificateCheck CertificateCheckFunc
	// OnPush, if set, is told about every snapshot push, for metrics.
	OnPush func(PushReport)
	// StartTimeout bounds launch, handshake and first snapshot.
	StartTimeout time.Duration
	// MinBackoff and MaxBackoff bound the delay between restarts.
	MinBackoff, MaxBackoff time.Duration

	version atomic.Uint64
	// pushMu serialises pushes, so versions reach the data plane in the
	// order they were assigned and a push never races the start-up push.
	pushMu  sync.Mutex
	ready   atomic.Bool
	mu      sync.Mutex
	cur     *Process
	hello   *pb.HelloResponse
	since   time.Time
	lastErr error
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
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
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
	s.cur, s.hello, s.since = p, hello, time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.cur, s.hello = nil, nil
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
	captures, err := p.Client.Captures(sctx)
	if err != nil {
		startCancel()
		return fmt.Errorf("dataplane: captures: %w", err)
	}
	checks, err := p.Client.CertificateChecks(sctx)
	if err != nil {
		startCancel()
		return fmt.Errorf("dataplane: certificate checks: %w", err)
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
	wg.Go(func() { s.storeCaptures(sctx, captures) })
	wg.Go(func() { s.checkCertificates(sctx, checks) })
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
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	var rep PushReport
	began := time.Now()
	snap, err := s.Snapshot(ctx)
	rep.Build = time.Since(began)
	if err != nil {
		rep.BuildErr = err
		s.report(rep)
		return fmt.Errorf("dataplane: building snapshot: %w", err)
	}
	defer wipe(snap)
	snap.Protocol = Protocol
	snap.Version = s.version.Add(1)
	rep.Version, rep.Entries = snap.Version, Entries(snap)
	sent := time.Now()
	resp, err := p.Client.ApplySnapshot(ctx, snap)
	rep.Apply, rep.ApplyErr = time.Since(sent), err
	s.report(rep)
	if err != nil {
		return fmt.Errorf("dataplane: snapshot %d rejected: %w", snap.Version, err)
	}
	s.logger().Info("snapshot applied", "version", resp.GetAppliedVersion(), "values", resp.GetValueCount())
	return nil
}

// PushReport describes one snapshot push. Counts and durations only.
type PushReport struct {
	// Build is how long the snapshot took to build; BuildErr is set when
	// the build failed and nothing was sent.
	Build    time.Duration
	BuildErr error
	// Apply is how long the data plane took to apply it; ApplyErr is set
	// when it was rejected or the call failed.
	Apply    time.Duration
	ApplyErr error
	// Version is the version sent.
	Version uint64
	// Entries counts what the snapshot carried, by kind.
	Entries map[string]int
}

// Entries counts a snapshot's parts: values, placeholder_keys, routes,
// listeners, policy_rules and ca_certificates.
func Entries(snap *pb.Snapshot) map[string]int {
	return map[string]int{
		"values":           len(snap.GetValues()),
		"placeholder_keys": len(snap.GetPlaceholderKeys()),
		"routes":           len(snap.GetRoutes()),
		"listeners":        len(snap.GetListeners()),
		"policy_rules":     len(snap.GetPolicy().GetRules()) + len(snap.GetPolicy().GetTable()),
		"ca_certificates":  len(snap.GetToolProxyCa()),
	}
}

func (s *Supervisor) report(r PushReport) {
	if s.OnPush != nil {
		s.OnPush(r)
	}
}

// Metrics reads the data plane's own metrics. A data plane started without
// metrics answers with Enabled false.
func (s *Supervisor) Metrics(ctx context.Context) (*pb.MetricsResponse, error) {
	s.mu.Lock()
	p := s.cur
	s.mu.Unlock()
	if p == nil {
		return nil, errors.New("dataplane: not running")
	}
	return p.Client.Metrics(ctx, &pb.MetricsRequest{Protocol: Protocol})
}

// Redact runs text through the data plane's redactor and guard (the same
// pair a provider request passes) and returns the redacted bytes. text may
// hold secret values: it is wiped once sent, whatever the outcome, and the
// connection zeroes its own copies (wipingDialOptions).
func (s *Supervisor) Redact(ctx context.Context, text []byte) (*pb.RedactResponse, error) {
	req := &pb.RedactRequest{Protocol: Protocol, Text: text}
	defer func() {
		secret.WipeBytes(text)
		req.Text = nil
	}()
	s.mu.Lock()
	p := s.cur
	s.mu.Unlock()
	if p == nil {
		return nil, errors.New("dataplane: not running")
	}
	return p.Client.Redact(ctx, req)
}

// wipe zeroes the secret bytes of a sent snapshot. The marshalled copy is
// zeroed by the connection's codec once it is written (wipingDialOptions).
func wipe(snap *pb.Snapshot) {
	clear(snap.GetUpstreamProxy().GetPassword())
	clear(snap.GetClientCertificates().GetListenerKeyPem())
	for _, v := range snap.GetValues() {
		clear(v.Value)
	}
	for _, k := range snap.GetPlaceholderKeys() {
		clear(k.Key)
	}
	for _, c := range snap.GetToolProxyCa() {
		clear(c.KeyPem)
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

func (s *Supervisor) storeCaptures(ctx context.Context, stream pb.DataPlane_CapturesClient) {
	var send sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		req, err := stream.Recv()
		if err != nil {
			return
		}
		wg.Go(func() {
			defer clear(req.Value)
			res := &pb.CaptureResult{Protocol: Protocol, Id: req.GetId(), Error: "no capture store is configured"}
			if s.OnCapture != nil {
				cctx := ctx
				if dl := req.GetDeadlineUnixNano(); dl > 0 {
					var cancel context.CancelFunc
					cctx, cancel = context.WithDeadline(ctx, time.Unix(0, dl))
					defer cancel()
				}
				ph, err := s.OnCapture(cctx, req)
				switch {
				case err != nil:
					res.Error = err.Error()
				case ph == "":
					res.Error = "capture store returned no placeholder"
				default:
					res.Error, res.Placeholder = "", ph
				}
			}
			send.Lock()
			defer send.Unlock()
			_ = stream.Send(res)
		})
	}
}

func (s *Supervisor) checkCertificates(ctx context.Context, stream pb.DataPlane_CertificateChecksClient) {
	var send sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		req, err := stream.Recv()
		if status.Code(err) == codes.Unimplemented && s.OnCertificateCheck != nil {
			s.logger().Error("the data plane does not check client certificates with the control plane; " +
				"its TLS listeners apply CRLs only, not OCSP")
			return
		}
		if err != nil {
			return
		}
		wg.Go(func() {
			res := &pb.CertificateCheckResult{Protocol: Protocol, Id: req.GetId(), Reason: "no certificate check is configured"}
			if req.GetProtocol() == Protocol && s.OnCertificateCheck != nil {
				cctx := ctx
				if dl := req.GetDeadlineUnixNano(); dl > 0 {
					var cancel context.CancelFunc
					cctx, cancel = context.WithDeadline(ctx, time.Unix(0, dl))
					defer cancel()
				}
				res.Reason = s.OnCertificateCheck(cctx, req.GetChain())
				res.Accepted = res.Reason == ""
			}
			send.Lock()
			defer send.Unlock()
			_ = stream.Send(res)
		})
	}
}

// Status asks the running data plane for its status.
func (s *Supervisor) Status(ctx context.Context) (*pb.StatusResponse, error) {
	s.mu.Lock()
	p := s.cur
	s.mu.Unlock()
	if p == nil {
		return nil, errors.New("dataplane: not running")
	}
	return p.Client.Status(ctx, &pb.StatusRequest{Protocol: Protocol})
}

// TrustBundle returns the PEM certificates of the tool-proxy CA that
// clients must trust. Public material.
func (s *Supervisor) TrustBundle(ctx context.Context) (string, error) {
	st, err := s.Status(ctx)
	if err != nil {
		return "", err
	}
	if st.GetCaTrustBundlePem() == "" {
		return "", errors.New("dataplane: no CA trust bundle reported")
	}
	return st.GetCaTrustBundlePem(), nil
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
