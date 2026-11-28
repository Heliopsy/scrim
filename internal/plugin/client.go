// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin runs out-of-process store and notifier plugins (design
// D17, docs/plugins.md, specs/secret-stores "Store plugins").
//
// A plugin is a separate executable that scrim starts with one end of a
// socketpair as file descriptor 3 and talks gRPC to, schema in
// proto/scrim/plugin/v1. [Client] supervises one plugin instance: it checks
// the binary before every start, handshakes (protocol version, kind,
// capabilities), configures it, bounds every call with a timeout, and fails
// closed: a plugin that exits, hangs or answers out of contract makes the
// call fail with an error naming the instance and what happened, never with
// a guess. A crashed or hung plugin is started again on a later call, after
// a backoff that doubles from one second to thirty.
//
// Status messages from a plugin are never printed, logged or returned: only
// their code is kept. The plugin's stderr goes to scrim's scrubbing log.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// Protocol is the plugin protocol version this build speaks.
const Protocol = uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT)

// Failure is an error scrim itself observed about a plugin: it did not
// start, exited, hung or broke the contract. Its message is scrim's own text
// and safe to show. Code is codes.Unavailable for everything but a refused
// configuration (codes.InvalidArgument).
type Failure struct {
	Instance string
	Code     codes.Code
	Msg      string
}

func (f *Failure) Error() string { return fmt.Sprintf("plugin %s: %s", f.Instance, f.Msg) }

// Code returns the error kind of err from a [Client] call: a [Failure]'s
// code, a plugin status's code, or Unavailable for anything else (a
// cancelled or expired context included).
func Code(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	var f *Failure
	if errors.As(err, &f) {
		return f.Code
	}
	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.Canceled, codes.DeadlineExceeded, codes.Unknown:
			return codes.Unavailable
		}
		return s.Code()
	}
	return codes.Unavailable
}

// Detail returns text safe to show about err: a [Failure]'s message, or ""
// for a plugin's own status, whose message is never repeated.
func Detail(err error) string {
	var f *Failure
	if errors.As(err, &f) {
		return f.Msg
	}
	return ""
}

// OnStart configures a freshly started plugin. It runs after every
// successful handshake, bounded by the start timeout.
type OnStart func(ctx context.Context, conn *grpc.ClientConn) error

// proc is one running plugin process.
type proc struct {
	conn *grpc.ClientConn
	pid  int
	done chan struct{}
	err  error
	// killed says why scrim stopped it, if it did.
	killed atomic.Pointer[string]
}

// Client supervises one plugin instance. It is safe for concurrent use.
type Client struct {
	cfg     Config
	log     *slog.Logger
	onStart OnStart

	mu       sync.Mutex
	cur      *proc
	info     *pb.HandshakeResponse
	failures int
	retryAt  time.Time
	lastExit string
	closed   bool
	starts   int
}

// NewClient returns a client for cfg. Nothing starts until the first call.
// log receives the plugin's stderr and scrim's warnings about it; it must
// scrub.
func NewClient(cfg Config, log *slog.Logger, onStart OnStart) *Client {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = defaultBackoff
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = DefaultStartTimeout
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = DefaultTimeout
	}
	return &Client{cfg: cfg, log: log.With("plugin", cfg.Instance), onStart: onStart}
}

func (c *Client) fail(code codes.Code, format string, args ...any) *Failure {
	return &Failure{Instance: c.cfg.Instance, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Info returns the plugin's handshake, starting it if it never ran.
func (c *Client) Info(ctx context.Context) (*pb.HandshakeResponse, error) {
	if _, err := c.running(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info, nil
}

// Starts counts the processes started, for tests.
func (c *Client) Starts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.starts
}

// Pid is the running plugin's process id, 0 when none runs. For tests.
func (c *Client) Pid() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil {
		return 0
	}
	return c.cur.pid
}

// running returns the live process, starting one if none runs and the
// backoff allows.
func (c *Client) running(ctx context.Context) (*proc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, c.fail(codes.Unavailable, "closed")
	}
	if p := c.cur; p != nil {
		select {
		case <-p.done:
		default:
			return p, nil
		}
		c.exitedLocked(p)
	}
	if wait := time.Until(c.retryAt); wait > 0 {
		return nil, c.fail(codes.Unavailable, "%s; next start in %s", c.lastExit, wait.Round(100*time.Millisecond))
	}
	p, err := c.startLocked(ctx)
	if err != nil {
		var f *Failure
		if !errors.As(err, &f) {
			f = c.fail(codes.Unavailable, "%v", err)
		}
		c.lastExit = "failed to start: " + f.Msg
		c.backoffLocked()
		c.log.Warn("plugin failed to start", "err", f.Msg)
		return nil, f
	}
	return p, nil
}

func (c *Client) backoffLocked() {
	c.failures++
	d := c.cfg.Backoff << min(c.failures-1, 10)
	c.retryAt = time.Now().Add(min(d, maxBackoff))
}

// exitedLocked records that p is gone.
func (c *Client) exitedLocked(p *proc) {
	if c.cur != p {
		return
	}
	c.cur = nil
	why := ""
	if k := p.killed.Load(); k != nil {
		why = *k
	}
	if why == "" {
		why = "exited"
		if p.err != nil {
			why += " (" + p.err.Error() + ")"
		}
	}
	c.lastExit = why
	c.backoffLocked()
	c.log.Warn("plugin stopped", "reason", why)
}

func (c *Client) startLocked(ctx context.Context) (*proc, error) {
	path, err := CheckBinary(c.cfg.Command, c.cfg.SHA256)
	if err != nil {
		return nil, c.fail(codes.Unavailable, "%v", err)
	}
	p, err := spawn(path, c.cfg, c.log)
	if err != nil {
		return nil, c.fail(codes.Unavailable, "%v", err)
	}
	c.starts++
	sctx, cancel := context.WithTimeout(ctx, c.cfg.StartTimeout)
	defer cancel()
	info, err := c.handshake(sctx, p)
	if err == nil && c.onStart != nil {
		err = c.onStart(sctx, p.conn)
		if err != nil {
			err = c.startError(sctx, p, "configure", err)
		}
	}
	if err != nil {
		c.kill(p, "")
		<-p.done
		return nil, err
	}
	c.cur = p
	c.info = info
	go func() {
		<-p.done
		c.mu.Lock()
		c.exitedLocked(p)
		c.mu.Unlock()
	}()
	return p, nil
}

// startError explains a failed start call.
func (c *Client) startError(ctx context.Context, p *proc, what string, err error) error {
	select {
	case <-p.done:
		return c.fail(codes.Unavailable, "exited during %s (%v)", what, p.err)
	case <-time.After(50 * time.Millisecond):
	}
	if expired(ctx) {
		return c.fail(codes.Unavailable, "no answer to %s within %s", what, c.cfg.StartTimeout)
	}
	var f *Failure
	if errors.As(err, &f) {
		return f
	}
	if s, ok := status.FromError(err); ok && s.Code() == codes.InvalidArgument {
		return c.fail(codes.InvalidArgument, "refused its configuration")
	}
	return c.fail(codes.Unavailable, "%s failed (%s)", what, Code(err))
}

// handshake checks protocol, kind and, after a restart, that the plugin
// still offers what it did.
func (c *Client) handshake(ctx context.Context, p *proc) (*pb.HandshakeResponse, error) {
	resp, err := pb.NewPluginClient(p.conn).Handshake(ctx, &pb.HandshakeRequest{
		Protocol: Protocol, Kind: c.cfg.Kind, Instance: c.cfg.Instance,
	})
	if err != nil {
		return nil, c.startError(ctx, p, "the handshake", err)
	}
	if resp.GetProtocol() != Protocol {
		return nil, c.fail(codes.Unavailable, "speaks plugin protocol %d, scrim speaks %d", resp.GetProtocol(), Protocol)
	}
	if resp.GetKind() != c.cfg.Kind {
		return nil, c.fail(codes.Unavailable, "is a %s plugin, configured as a %s plugin", kindName(resp.GetKind()), kindName(c.cfg.Kind))
	}
	if c.cfg.Kind == pb.Kind_KIND_STORE && !slices.Contains(resp.GetCapabilities(), pb.Capability_CAPABILITY_READ) {
		return nil, c.fail(codes.Unavailable, "is a store plugin without the read capability")
	}
	for _, cp := range resp.GetCapabilities() {
		if _, known := pb.Capability_name[int32(cp)]; !known || cp == pb.Capability_CAPABILITY_UNSPECIFIED {
			return nil, c.fail(codes.Unavailable, "declares unknown capability %d", int32(cp))
		}
	}
	if c.info != nil && !sameCaps(c.info.GetCapabilities(), resp.GetCapabilities()) {
		return nil, c.fail(codes.Unavailable, "changed its capabilities across a restart")
	}
	return resp, nil
}

func sameCaps(a, b []pb.Capability) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

func kindName(k pb.Kind) string {
	switch k {
	case pb.Kind_KIND_STORE:
		return "store"
	case pb.Kind_KIND_NOTIFIER:
		return "notifier"
	}
	return "unknown"
}

// kill stops p, recording why when why is set.
func (c *Client) kill(p *proc, why string) {
	if why != "" {
		p.killed.CompareAndSwap(nil, &why)
	}
	_ = p.conn.Close()
	killGroup(p.pid)
}

// Call runs fn against the plugin with the call timeout. A plugin that does
// not answer in time is stopped; one that exits during the call is reported
// as having exited. Either way the error is a [Failure] with code
// Unavailable. A status the plugin returned is passed through for the
// caller to read with [Code].
func (c *Client) Call(ctx context.Context, op string, fn func(ctx context.Context, conn *grpc.ClientConn) error) error {
	p, err := c.running(ctx)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.CallTimeout)
	defer cancel()
	err = fn(cctx, p.conn)
	if err == nil {
		c.mu.Lock()
		c.failures = 0
		c.mu.Unlock()
		return nil
	}
	return c.callError(ctx, cctx, p, op, err)
}

func (c *Client) callError(ctx, cctx context.Context, p *proc, op string, err error) error {
	if expired(ctx) {
		return c.fail(codes.Unavailable, "%s cancelled", op)
	}
	if expired(cctx) {
		c.kill(p, fmt.Sprintf("stopped after it did not answer %s within %s", op, c.cfg.CallTimeout))
		return c.fail(codes.Unavailable, "did not answer %s within %s; stopped it", op, c.cfg.CallTimeout)
	}
	if s, ok := status.FromError(err); !ok || s.Code() == codes.Unavailable || s.Code() == codes.Canceled {
		// A broken transport: wait briefly to tell a crash from a status.
		select {
		case <-p.done:
			return c.fail(codes.Unavailable, "exited during %s (%v)", op, p.err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	return err
}

// expired reports whether ctx is cancelled or past its deadline. Err alone
// is not enough: a context's deadline error is set by a timer callback that
// can run after a call already failed for that deadline. gRPC decides by the
// clock: the plugin resets the stream at the deadline it was sent, and the
// client reports DeadlineExceeded as soon as its deadline has passed, while
// Err may still be nil.
func expired(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	d, ok := ctx.Deadline()
	return ok && !time.Now().Before(d)
}

// Stream opens a streaming call: fn gets the connection and a context that
// ends with ctx, with no timeout. ready must be closed or sent on by fn's
// caller within the call timeout; Stream itself only starts the plugin.
func (c *Client) Stream(ctx context.Context) (*grpc.ClientConn, <-chan struct{}, error) {
	p, err := c.running(ctx)
	if err != nil {
		return nil, nil, err
	}
	return p.conn, p.done, nil
}

// StreamError explains a stream that failed to become ready or broke.
func (c *Client) StreamError(ctx context.Context, done <-chan struct{}, op string, err error, timedOut bool) error {
	if expired(ctx) {
		return c.fail(codes.Unavailable, "%s cancelled", op)
	}
	c.mu.Lock()
	p := c.cur
	c.mu.Unlock()
	if timedOut {
		if p != nil && p.done == done {
			c.kill(p, fmt.Sprintf("stopped after it did not confirm %s within %s", op, c.cfg.CallTimeout))
		}
		return c.fail(codes.Unavailable, "did not confirm %s within %s; stopped it", op, c.cfg.CallTimeout)
	}
	select {
	case <-done:
		return c.fail(codes.Unavailable, "exited during %s", op)
	case <-time.After(100 * time.Millisecond):
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	return c.fail(codes.Unavailable, "%s failed", op)
}

// CallTimeout is the per-call bound.
func (c *Client) CallTimeout() time.Duration { return c.cfg.CallTimeout }

// Close stops the plugin: its socket closes, which ends a well-behaved
// plugin, and its process group is killed if it is still there after a
// short grace.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	p := c.cur
	c.cur = nil
	c.mu.Unlock()
	if p == nil {
		return nil
	}
	closed := "closed"
	p.killed.CompareAndSwap(nil, &closed)
	_ = p.conn.Close()
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		killGroup(p.pid)
		<-p.done
	}
	return nil
}

// Validate starts a throwaway process (handshake only, nothing configured),
// asks it to validate options with the credential fields named but empty,
// and stops it. It returns the handshake for its capabilities.
func Validate(ctx context.Context, cfg Config, log *slog.Logger) (*pb.HandshakeResponse, error) {
	c := NewClient(cfg, log, nil)
	defer func() { _ = c.Close() }()
	info, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}
	opts, err := OptionsJSON(cfg.Options)
	if err != nil {
		return nil, err
	}
	names := map[string][]byte{}
	for k := range cfg.Secrets {
		names[k] = nil
	}
	var resp *pb.ValidateConfigResponse
	err = c.Call(ctx, "validate", func(ctx context.Context, conn *grpc.ClientConn) error {
		var err error
		resp, err = pb.NewPluginClient(conn).ValidateConfig(ctx, &pb.ConfigRequest{
			Protocol: Protocol, Instance: cfg.Instance, OptionsJson: opts, Secrets: names,
		})
		return err
	})
	if err != nil {
		if d := Detail(err); d != "" {
			return nil, err
		}
		return nil, c.fail(codes.Unavailable, "validate failed (%s)", Code(err))
	}
	if p := resp.GetProblems(); len(p) > 0 {
		errs := make([]error, 0, len(p))
		for _, m := range p {
			errs = append(errs, fmt.Errorf("plugin %s: %s", cfg.Instance, clip(m, 200)))
		}
		return nil, errors.Join(errs...)
	}
	return info, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
