// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin is the Go SDK for writing scrim store and notifier plugins
// (docs/plugins.md).
//
// A plugin is an executable scrim starts and talks to over an inherited
// socket, speaking the protocol in proto/scrim/plugin/v1. This package
// implements that protocol: write a type that satisfies [Store] or
// [Notifier] and call [ServeStore] or [ServeNotifier] from main.
//
//	func main() {
//		if err := plugin.ServeStore(&myStore{}); err != nil {
//			fmt.Fprintln(os.Stderr, err)
//			os.Exit(1)
//		}
//	}
//
// The SDK checks the protocol version and the capabilities you declare on
// every call, so an operation outside them never reaches your code, and it
// zeroes secret bytes once they have been sent or once your method returns.
// Secret bytes you receive (credentials in [Config.Secrets], values in
// [Store.Write]) are borrowed: copy what you must keep. Never write a secret
// value to stderr, which scrim relays into its log, or into an error.
//
// Plugins in other languages implement the same gRPC services from the
// proto file; see docs/plugins.md for the transport.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// Protocol is the plugin protocol version this SDK speaks.
const Protocol = uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT)

// Capability is one store operation a plugin supports.
type Capability int

// Capabilities.
const (
	CapRead  = Capability(pb.Capability_CAPABILITY_READ)
	CapList  = Capability(pb.Capability_CAPABILITY_LIST)
	CapWatch = Capability(pb.Capability_CAPABILITY_WATCH)
	CapWrite = Capability(pb.Capability_CAPABILITY_WRITE)
	// CapGlob: List and Watch accept a prefix ending in `*`.
	CapGlob = Capability(pb.Capability_CAPABILITY_GLOB)
)

// Info identifies a plugin build and what it supports.
type Info struct {
	Name    string
	Version string
	// Capabilities a store supports; CapRead is required. Ignored for a
	// notifier.
	Capabilities []Capability
}

// Config is an instance's configuration.
type Config struct {
	// Instance is the configured instance name.
	Instance string
	// Options is the instance's `options` object as JSON.
	Options json.RawMessage
	// Secrets maps each configured credential field (token, password, ...)
	// to its value. Borrowed: zeroed when Configure returns. In
	// ValidateConfig the keys are present and the values empty.
	Secrets map[string][]byte
}

// Errors. Return one of these (wrapped as you like) from a [Store] method
// and scrim sees its kind. Any other error reads as ErrUnavailable. The text
// of your error is not sent: scrim never shows a plugin's message, since a
// store's own message can echo request data.
var (
	ErrNotFound    = errors.New("not found")
	ErrPermission  = errors.New("permission denied by store")
	ErrUnsupported = errors.New("not supported")
	ErrUnavailable = errors.New("store unavailable")
	ErrConflict    = errors.New("conflict")
	ErrLocked      = errors.New("store locked")
	ErrInvalid     = errors.New("invalid reference or configuration")
)

var errCodes = []struct {
	err  error
	code codes.Code
}{
	{ErrNotFound, codes.NotFound}, {ErrPermission, codes.PermissionDenied},
	{ErrUnsupported, codes.Unimplemented}, {ErrUnavailable, codes.Unavailable},
	{ErrConflict, codes.AlreadyExists}, {ErrLocked, codes.FailedPrecondition},
	{ErrInvalid, codes.InvalidArgument},
}

// toStatus turns err into a status carrying only its kind.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	for _, e := range errCodes {
		if errors.Is(err, e.err) {
			return status.Error(e.code, e.err.Error())
		}
	}
	return status.Error(codes.Unavailable, ErrUnavailable.Error())
}

// Ref names a secret inside the instance.
type Ref struct {
	Path string
	// Field selects one field; empty means every field.
	Field string
	// Selectors is the raw query (`version=3`). Refuse one you do not
	// understand with ErrInvalid.
	Selectors string
}

// Metadata describes a secret without its value.
type Metadata struct {
	Path      string
	Fields    []string
	Version   string
	Created   time.Time
	Updated   time.Time
	Labels    map[string]string
	WriteOnly bool
}

// Secret is a read result. The SDK takes ownership of Fields and zeroes
// them once sent.
type Secret struct {
	Meta   Metadata
	Fields map[string][]byte
}

// WriteOptions tunes [Store.Write].
type WriteOptions struct {
	// CreateOnly fails with ErrConflict if the secret exists.
	CreateOnly bool
	Labels     map[string]string
}

// Change is one watch notification. It never carries a value.
type Change struct {
	Path    string
	Deleted bool
}

// Store is a secret store plugin. Methods must be safe for concurrent use.
// A method for a capability you do not declare is never called; return
// ErrUnsupported from it.
type Store interface {
	Info() Info
	// ValidateConfig checks options without contacting anything and
	// returns one problem per invalid option, naming the option and never
	// quoting its value.
	ValidateConfig(c Config) []string
	// Configure applies the configuration. It must not contact the store.
	Configure(ctx context.Context, c Config) error
	// Read returns the secret at ref; with ref.Field set, only that field.
	Read(ctx context.Context, ref Ref) (Secret, error)
	// List returns metadata of every secret under prefix, recursively.
	List(ctx context.Context, prefix string) ([]Metadata, error)
	// Watch returns once the watch is established and reports every change
	// under prefix after that, until ctx ends. Close the channel when done.
	Watch(ctx context.Context, prefix string) (<-chan Change, error)
	// Write stores fields as a new version of the secret at path. fields
	// is borrowed: zeroed when Write returns. Refuse a value the store
	// cannot hold byte for byte with ErrUnsupported.
	Write(ctx context.Context, path string, fields map[string][]byte, opts WriteOptions) (Metadata, error)
	// Health checks the store is reachable and the credentials work.
	Health(ctx context.Context) error
}

// SummaryField is one labelled line of an approval summary.
type SummaryField struct{ Label, Value string }

// Notification is an approval request to deliver. ApproveURL and DenyURL
// are single-use decision links: whoever opens one decides the request, so
// send them only to the people who approve and never log them.
type Notification struct {
	ApprovalID  string
	Agent       string
	Action      string
	Reference   string
	Destination string
	Tool        string
	Rule        string
	Reason      string
	ExpiresAt   time.Time
	ApproveURL  string
	DenyURL     string
	// Title and Fields are scrim's rendering of the request.
	Title  string
	Fields []SummaryField
}

// Notifier is a notifier plugin. It only delivers: decisions come back
// through the decision links or `scrim approve`, never through Notify.
type Notifier interface {
	Info() Info
	ValidateConfig(c Config) []string
	// Configure applies the configuration without contacting anything.
	Configure(ctx context.Context, c Config) error
	// Notify delivers n, within ctx.
	Notify(ctx context.Context, n Notification) error
}

// ServeStore serves s on the socket scrim passed and returns when scrim
// closes it.
func ServeStore(s Store) error { return serveEnv(pb.Kind_KIND_STORE, s) }

// ServeNotifier serves n on the socket scrim passed and returns when scrim
// closes it.
func ServeNotifier(n Notifier) error { return serveEnv(pb.Kind_KIND_NOTIFIER, n) }

func serveEnv(kind pb.Kind, impl any) error {
	fdText := os.Getenv("SCRIM_PLUGIN_FD")
	if fdText == "" {
		return errors.New("this is a scrim plugin: scrim starts it (see docs/plugins.md)")
	}
	fd, err := strconv.Atoi(fdText)
	if err != nil || fd < 3 {
		return fmt.Errorf("SCRIM_PLUGIN_FD=%q is not a descriptor number", fdText)
	}
	f := os.NewFile(uintptr(fd), "scrim")
	nc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("SCRIM_PLUGIN_FD: %w", err)
	}
	return ServeConn(nc, kind, impl)
}

// ServeConn serves impl, a [Store] or [Notifier], on one connection until it
// closes. scrim's own tests use it in process; a plugin calls [ServeStore]
// or [ServeNotifier].
func ServeConn(nc net.Conn, kind pb.Kind, impl any) error {
	b := &base{kind: kind}
	srv := grpc.NewServer(grpc.ForceServerCodecV2(pb.Codec()))
	switch kind {
	case pb.Kind_KIND_STORE:
		s, ok := impl.(Store)
		if !ok {
			return errors.New("plugin: a store plugin must implement plugin.Store")
		}
		b.info, b.validate, b.configure = s.Info(), s.ValidateConfig, s.Configure
		pb.RegisterStoreServer(srv, &storeServer{base: b, impl: s})
	case pb.Kind_KIND_NOTIFIER:
		n, ok := impl.(Notifier)
		if !ok {
			return errors.New("plugin: a notifier plugin must implement plugin.Notifier")
		}
		b.info, b.validate, b.configure = n.Info(), n.ValidateConfig, n.Configure
		pb.RegisterNotifierServer(srv, &notifierServer{base: b, impl: n})
	default:
		return errors.New("plugin: unknown kind")
	}
	if kind == pb.Kind_KIND_STORE && !slices.Contains(b.info.Capabilities, CapRead) {
		return errors.New("plugin: a store plugin must declare CapRead")
	}
	pb.RegisterPluginServer(srv, b)
	lis := newOneConn(nc)
	err := srv.Serve(lis)
	if errors.Is(err, errConnClosed) {
		return nil
	}
	return err
}

// base serves the Plugin service.
type base struct {
	pb.UnimplementedPluginServer
	kind       pb.Kind
	info       Info
	validate   func(Config) []string
	configure  func(context.Context, Config) error
	configured atomic.Bool
}

func checkProtocol(p uint32) error {
	if p != Protocol {
		return status.Errorf(codes.FailedPrecondition, "plugin protocol %d, this plugin speaks %d", p, Protocol)
	}
	return nil
}

func (b *base) ready(p uint32) error {
	if err := checkProtocol(p); err != nil {
		return err
	}
	if !b.configured.Load() {
		return status.Error(codes.FailedPrecondition, "not configured")
	}
	return nil
}

func (b *base) has(c Capability) bool { return slices.Contains(b.info.Capabilities, c) }

func (b *base) Handshake(_ context.Context, req *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	if err := checkProtocol(req.GetProtocol()); err != nil {
		return nil, err
	}
	// A kind mismatch is scrim's to report: it names both kinds.
	resp := &pb.HandshakeResponse{Protocol: Protocol, Kind: b.kind, Name: b.info.Name, Version: b.info.Version}
	if b.kind == pb.Kind_KIND_STORE {
		for _, c := range b.info.Capabilities {
			resp.Capabilities = append(resp.Capabilities, pb.Capability(c))
		}
	}
	return resp, nil
}

func config(req *pb.ConfigRequest) Config {
	return Config{Instance: req.GetInstance(), Options: json.RawMessage(req.GetOptionsJson()), Secrets: req.GetSecrets()}
}

func (b *base) ValidateConfig(_ context.Context, req *pb.ConfigRequest) (*pb.ValidateConfigResponse, error) {
	defer req.WipeSecrets()
	if err := checkProtocol(req.GetProtocol()); err != nil {
		return nil, err
	}
	c := config(req)
	for k := range c.Secrets {
		c.Secrets[k] = nil
	}
	return &pb.ValidateConfigResponse{Protocol: Protocol, Problems: b.validate(c)}, nil
}

func (b *base) Configure(ctx context.Context, req *pb.ConfigRequest) (*pb.ConfigureResponse, error) {
	defer req.WipeSecrets()
	if err := checkProtocol(req.GetProtocol()); err != nil {
		return nil, err
	}
	if err := b.configure(ctx, config(req)); err != nil {
		return nil, status.Error(codes.InvalidArgument, "configuration refused")
	}
	b.configured.Store(true)
	return &pb.ConfigureResponse{Protocol: Protocol}, nil
}

type storeServer struct {
	pb.UnimplementedStoreServer
	*base
	impl Store
}

func (s *storeServer) gate(p uint32, c Capability) error {
	if err := s.ready(p); err != nil {
		return err
	}
	if !s.has(c) {
		return status.Error(codes.Unimplemented, ErrUnsupported.Error())
	}
	return nil
}

func meta(m Metadata) *pb.Metadata {
	out := &pb.Metadata{Path: m.Path, Fields: m.Fields, Version: m.Version, Labels: m.Labels, WriteOnly: m.WriteOnly}
	if !m.Created.IsZero() {
		out.CreatedUnixNano = m.Created.UnixNano()
	}
	if !m.Updated.IsZero() {
		out.UpdatedUnixNano = m.Updated.UnixNano()
	}
	return out
}

func (s *storeServer) Read(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	if err := s.gate(req.GetProtocol(), CapRead); err != nil {
		return nil, err
	}
	r := req.GetRef()
	sec, err := s.impl.Read(ctx, Ref{Path: r.GetPath(), Field: r.GetField(), Selectors: r.GetSelectors()})
	if err != nil {
		for _, v := range sec.Fields {
			clear(v)
		}
		return nil, toStatus(err)
	}
	// The codec zeroes the values once the response is marshalled.
	resp := &pb.ReadResponse{Protocol: Protocol, Meta: meta(sec.Meta)}
	for _, name := range sortedKeys(sec.Fields) {
		resp.Fields = append(resp.Fields, &pb.Field{Name: name, Value: sec.Fields[name]})
	}
	return resp, nil
}

func (s *storeServer) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	if err := s.gate(req.GetProtocol(), CapList); err != nil {
		return nil, err
	}
	ms, err := s.impl.List(ctx, req.GetPrefix())
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &pb.ListResponse{Protocol: Protocol}
	for _, m := range ms {
		resp.Entries = append(resp.Entries, meta(m))
	}
	return resp, nil
}

func (s *storeServer) Watch(req *pb.WatchRequest, stream grpc.ServerStreamingServer[pb.WatchEvent]) error {
	if err := s.gate(req.GetProtocol(), CapWatch); err != nil {
		return err
	}
	ctx := stream.Context()
	ch, err := s.impl.Watch(ctx, req.GetPrefix())
	if err != nil {
		return toStatus(err)
	}
	if err := stream.Send(&pb.WatchEvent{Protocol: Protocol, Ready: true}); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case c, ok := <-ch:
			if !ok {
				return status.Error(codes.Unavailable, "watch ended")
			}
			kind := pb.ChangeKind_CHANGE_KIND_CHANGED
			if c.Deleted {
				kind = pb.ChangeKind_CHANGE_KIND_DELETED
			}
			if err := stream.Send(&pb.WatchEvent{Protocol: Protocol, Path: c.Path, Kind: kind}); err != nil {
				return err
			}
		}
	}
}

func (s *storeServer) Write(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error) {
	defer req.WipeSecrets()
	if err := s.gate(req.GetProtocol(), CapWrite); err != nil {
		return nil, err
	}
	fields := make(map[string][]byte, len(req.GetFields()))
	for _, f := range req.GetFields() {
		fields[f.GetName()] = f.GetValue()
	}
	m, err := s.impl.Write(ctx, req.GetPath(), fields, WriteOptions{CreateOnly: req.GetCreateOnly(), Labels: req.GetLabels()})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.WriteResponse{Protocol: Protocol, Meta: meta(m)}, nil
}

func (s *storeServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	if err := s.ready(req.GetProtocol()); err != nil {
		return nil, err
	}
	if err := s.impl.Health(ctx); err != nil {
		return nil, toStatus(err)
	}
	return &pb.HealthResponse{Protocol: Protocol}, nil
}

type notifierServer struct {
	pb.UnimplementedNotifierServer
	*base
	impl Notifier
}

func (n *notifierServer) Notify(ctx context.Context, req *pb.NotifyRequest) (*pb.NotifyResponse, error) {
	if err := n.ready(req.GetProtocol()); err != nil {
		return nil, err
	}
	note := Notification{
		ApprovalID: req.GetApprovalId(), Agent: req.GetAgent(), Action: req.GetAction(),
		Reference: req.GetReference(), Destination: req.GetDestination(), Tool: req.GetTool(),
		Rule: req.GetRule(), Reason: req.GetReason(), ApproveURL: req.GetApproveUrl(), DenyURL: req.GetDenyUrl(),
		Title: req.GetTitle(),
	}
	if e := req.GetExpiresUnix(); e != 0 {
		note.ExpiresAt = time.Unix(e, 0)
	}
	for _, f := range req.GetFields() {
		note.Fields = append(note.Fields, SummaryField{Label: f.GetLabel(), Value: f.GetValue()})
	}
	if err := n.impl.Notify(ctx, note); err != nil {
		return nil, toStatus(err)
	}
	return &pb.NotifyResponse{Protocol: Protocol}, nil
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// oneConn is a listener that yields one connection, then blocks until that
// connection closes, so Serve returns when scrim hangs up.
type oneConn struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
	addr   net.Addr
}

var errConnClosed = errors.New("plugin: scrim closed the connection")

func newOneConn(nc net.Conn) *oneConn {
	l := &oneConn{conns: make(chan net.Conn, 1), closed: make(chan struct{}), addr: nc.LocalAddr()}
	l.conns <- &trackedConn{Conn: nc, onClose: func() { _ = l.Close() }}
	return l
}

func (l *oneConn) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, errConnClosed
	}
}

func (l *oneConn) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.addr }

type trackedConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}
