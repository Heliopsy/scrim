// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin is the `plugin` store kind: a store adapter served by an
// out-of-process plugin (design D15, docs/plugins.md, specs/secret-stores
// "Store plugins").
//
//	stores:
//	  acme:
//	    kind: plugin
//	    command: /usr/local/libexec/scrim/scrim-store-acme
//	    args: [--region, eu]
//	    options: {endpoint: https://vault.acme.test}
//	    token: file:/run/secrets/acme-token
//	    capabilities: [read, list]   # optional: narrow what scrim uses
//	    timeout: 10s
//
// The factory checks the binary and starts a throwaway copy of the plugin
// to handshake and validate its options, so `scrim config validate` reports
// a bad option or a wrong binary. The adapter then starts its own process on
// first use, configures it with the resolved credentials, and restarts it
// with backoff after a crash or a hang. While it is down every call fails
// with ErrUnavailable, so the refresher keeps the last known values and
// reports the store degraded.
package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/heliopsy/scrim/internal/config"
	hostplugin "github.com/heliopsy/scrim/internal/plugin"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// Kind is the adapter kind.
const Kind = "plugin"

// FieldCapabilities narrows the capabilities scrim uses to a subset of what
// the plugin declares.
const FieldCapabilities = "capabilities"

func init() { stores.Register(Kind, New) }

var _ stores.CredentialHolder = (*Adapter)(nil)

var capByName = map[string]stores.Capability{
	"read": stores.CapRead, "list": stores.CapList, "watch": stores.CapWatch,
	"write": stores.CapWrite, "glob": stores.CapGlob,
}

var capFromPB = map[pb.Capability]stores.Capability{
	pb.Capability_CAPABILITY_READ: stores.CapRead, pb.Capability_CAPABILITY_LIST: stores.CapList,
	pb.Capability_CAPABILITY_WATCH: stores.CapWatch, pb.Capability_CAPABILITY_WRITE: stores.CapWrite,
	pb.Capability_CAPABILITY_GLOB: stores.CapGlob,
}

// Adapter is one plugin-backed store instance.
type Adapter struct {
	name    string
	caps    stores.Capabilities
	client  *hostplugin.Client
	resolve func(context.Context, config.SecretRef) (secret.Value, error)
	cfg     hostplugin.Config

	mu    sync.Mutex
	creds map[string]secret.Value
}

// New builds the adapter. It validates the configuration through a
// throwaway plugin process; it does not contact the store.
func New(ctx context.Context, inst stores.Instance) (stores.Adapter, error) {
	fail := func(err error) error { return fmt.Errorf("store %s: %w", inst.Name, err) }
	cfg, rest, err := hostplugin.ParseConfig(inst.Name, pb.Kind_KIND_STORE, inst.Options, storeconfig.SecretFields, []string{FieldCapabilities})
	if err != nil {
		return nil, fail(err)
	}
	allowed := stores.Capabilities(0)
	if v, ok := rest[FieldCapabilities]; ok {
		if allowed, err = parseCaps(v); err != nil {
			return nil, fail(err)
		}
	}
	info, err := hostplugin.Validate(ctx, cfg, inst.Log)
	if err != nil {
		return nil, fail(err)
	}
	var caps stores.Capabilities
	for _, c := range info.GetCapabilities() {
		caps |= capFromPB[c]
	}
	if allowed != 0 {
		if !caps.Has(allowed) {
			return nil, fail(fmt.Errorf("%s lists %s, the plugin offers only %s", FieldCapabilities, allowed&^caps, caps))
		}
		caps = allowed
	}
	if !caps.Has(stores.CapRead) {
		return nil, fail(fmt.Errorf("%s must include read", FieldCapabilities))
	}
	a := &Adapter{name: inst.Name, caps: caps, resolve: inst.Resolve, cfg: cfg}
	a.client = hostplugin.NewClient(cfg, inst.Log, a.configure)
	return a, nil
}

func parseCaps(v any) (stores.Capabilities, error) {
	var names []string
	switch x := v.(type) {
	case string:
		names = strings.Split(x, ",")
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return 0, fmt.Errorf("%s must be a list of read, list, watch, write, glob", FieldCapabilities)
			}
			names = append(names, s)
		}
	default:
		return 0, fmt.Errorf("%s must be a list of read, list, watch, write, glob", FieldCapabilities)
	}
	var caps stores.Capabilities
	for _, n := range names {
		c, ok := capByName[strings.TrimSpace(n)]
		if !ok {
			return 0, fmt.Errorf("%s: unknown capability %q (read, list, watch, write, glob)", FieldCapabilities, strings.TrimSpace(n))
		}
		caps |= c
	}
	return caps, nil
}

// configure resolves the credentials and sends them with the options. It
// runs at every start, so a rotated credential reaches a restarted plugin.
func (a *Adapter) configure(ctx context.Context, conn *grpc.ClientConn) error {
	opts, err := hostplugin.OptionsJSON(a.cfg.Options)
	if err != nil {
		return err
	}
	resolved := map[string]secret.Value{}
	req := &pb.ConfigRequest{Protocol: hostplugin.Protocol, Instance: a.name, OptionsJson: opts, Secrets: map[string][]byte{}}
	defer req.WipeSecrets()
	for _, name := range sortedKeys(a.cfg.Secrets) {
		v, err := a.resolve(ctx, config.SecretRef(a.cfg.Secrets[name]))
		if err != nil {
			for _, r := range resolved {
				r.Wipe()
			}
			// The resolver's message names the reference, not the value.
			return &hostplugin.Failure{Instance: a.name, Code: codes.Unavailable, Msg: fmt.Sprintf("resolving %s: %v", name, err)}
		}
		resolved[name] = v
		_ = v.Expose(func(b []byte) error { req.Secrets[name] = bytes.Clone(b); return nil })
	}
	if _, err = pb.NewPluginClient(conn).Configure(ctx, req); err != nil {
		for _, r := range resolved {
			r.Wipe()
		}
		return err
	}
	a.mu.Lock()
	for _, old := range a.creds {
		old.Wipe()
	}
	a.creds = resolved
	a.mu.Unlock()
	return nil
}

// Name implements [stores.Adapter].
func (a *Adapter) Name() string { return a.name }

// Capabilities implements [stores.Adapter]: what the plugin declared at
// validation, narrowed by the `capabilities` field.
func (a *Adapter) Capabilities() stores.Capabilities { return a.caps }

// Credentials implements [stores.CredentialHolder]: the credentials last
// sent to the plugin, so scrim redacts them.
func (a *Adapter) Credentials() []secret.Value {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]secret.Value, 0, len(a.creds))
	for _, v := range a.creds {
		_ = v.Expose(func(b []byte) error { out = append(out, secret.New(b)); return nil })
	}
	return out
}

// errorFor maps a plugin call's failure to a store error. A plugin's own
// status message is dropped; scrim's own observations become the detail.
func (a *Adapter) errorFor(op stores.Op, ref stores.Ref, err error) error {
	kind := stores.ErrUnavailable
	switch hostplugin.Code(err) {
	case codes.NotFound:
		kind = stores.ErrNotFound
	case codes.PermissionDenied:
		kind = stores.ErrPermission
	case codes.Unimplemented:
		kind = stores.ErrUnsupported
	case codes.AlreadyExists, codes.Aborted:
		kind = stores.ErrConflict
	case codes.FailedPrecondition:
		kind = stores.ErrLocked
	case codes.InvalidArgument:
		kind = stores.ErrInvalidRef
	}
	e := stores.NewError(a.name, op, ref, kind, nil)
	if d := hostplugin.Detail(err); d != "" {
		e.Detail = "plugin " + d
	}
	return e
}

func (a *Adapter) gate(op stores.Op, ref stores.Ref, c stores.Capability) error {
	if !a.caps.Has(c) {
		return stores.NewError(a.name, op, ref, stores.ErrUnsupported, nil)
	}
	return nil
}

func pbRef(r stores.Ref) *pb.Ref {
	return &pb.Ref{Path: r.Path, Field: r.Field, Selectors: r.Selectors}
}

// metadata converts plugin metadata for a secret addressed by scheme.
func (a *Adapter) metadata(scheme string, m *pb.Metadata) stores.Metadata {
	out := stores.Metadata{
		Ref:       stores.Ref{Scheme: scheme, Path: m.GetPath()},
		Fields:    slices.Clone(m.GetFields()),
		Version:   m.GetVersion(),
		WriteOnly: m.GetWriteOnly(),
	}
	if n := m.GetCreatedUnixNano(); n != 0 {
		out.CreatedAt = time.Unix(0, n)
	}
	if n := m.GetUpdatedUnixNano(); n != 0 {
		out.UpdatedAt = time.Unix(0, n)
	}
	if l := m.GetLabels(); len(l) > 0 {
		out.Labels = make(map[string]string, len(l))
		for k, v := range l {
			out.Labels[k] = v
		}
	}
	return out
}

func under(path, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return prefix == "" || path == prefix || strings.HasPrefix(path, prefix+"/")
}

func (a *Adapter) contract(op stores.Op, ref stores.Ref, what string) error {
	e := stores.NewError(a.name, op, ref, stores.ErrUnavailable, nil)
	e.Detail = "plugin broke the contract: " + what
	return e
}

// Read implements [stores.Adapter].
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if err := a.gate(stores.OpRead, ref, stores.CapRead); err != nil {
		return stores.Secret{}, err
	}
	var resp *pb.ReadResponse
	err := a.client.Call(ctx, "read", func(ctx context.Context, conn *grpc.ClientConn) error {
		var err error
		resp, err = pb.NewStoreClient(conn).Read(ctx, &pb.ReadRequest{Protocol: hostplugin.Protocol, Ref: pbRef(ref)})
		return err
	})
	if err != nil {
		return stores.Secret{}, a.errorFor(stores.OpRead, ref, err)
	}
	defer resp.WipeSecrets()
	if resp.GetProtocol() != hostplugin.Protocol {
		return stores.Secret{}, a.contract(stores.OpRead, ref, "wrong protocol in the answer")
	}
	s := stores.Secret{Meta: a.metadata(ref.Scheme, resp.GetMeta()), Fields: map[string]secret.Value{}}
	if s.Meta.Ref.Path == "" {
		s.Meta.Ref.Path = ref.Path
	}
	if s.Meta.Ref.Path != ref.Path {
		return stores.Secret{}, a.contract(stores.OpRead, ref, "answered for another path")
	}
	for _, f := range resp.GetFields() {
		if ref.Field != "" && f.GetName() != ref.Field {
			continue
		}
		if _, dup := s.Fields[f.GetName()]; dup {
			s.Wipe()
			return stores.Secret{}, a.contract(stores.OpRead, ref, "returned a field twice")
		}
		s.Fields[f.GetName()] = secret.New(f.GetValue())
	}
	if ref.Field != "" && len(s.Fields) == 0 {
		return stores.Secret{}, stores.NewError(a.name, stores.OpRead, ref, stores.ErrNotFound, nil)
	}
	if len(s.Meta.Fields) == 0 {
		s.Meta.Fields = sortedKeys(s.Fields)
	}
	return s, nil
}

// List implements [stores.Adapter].
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	if err := a.gate(stores.OpList, prefix, stores.CapList); err != nil {
		return nil, err
	}
	var resp *pb.ListResponse
	err := a.client.Call(ctx, "list", func(ctx context.Context, conn *grpc.ClientConn) error {
		var err error
		resp, err = pb.NewStoreClient(conn).List(ctx, &pb.ListRequest{Protocol: hostplugin.Protocol, Prefix: prefix.Path})
		return err
	})
	if err != nil {
		return nil, a.errorFor(stores.OpList, prefix, err)
	}
	glob := strings.HasSuffix(prefix.Path, "*") && a.caps.Has(stores.CapGlob)
	out := make([]stores.Metadata, 0, len(resp.GetEntries()))
	for _, m := range resp.GetEntries() {
		ok := under(m.GetPath(), prefix.Path)
		if glob {
			ok = strings.HasPrefix(m.GetPath(), strings.TrimSuffix(prefix.Path, "*"))
		}
		if !ok || m.GetPath() == "" {
			return nil, a.contract(stores.OpList, prefix, "listed a path outside the prefix")
		}
		out = append(out, a.metadata(prefix.Scheme, m))
	}
	return out, nil
}

// Watch implements [stores.Adapter]. The plugin confirms the watch before
// Watch returns. If the stream breaks (the plugin crashed or was stopped),
// the watch is opened again with backoff on a restarted plugin until ctx
// ends; the refresher's full refreshes cover changes made in between.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	if err := a.gate(stores.OpWatch, prefix, stores.CapWatch); err != nil {
		return nil, err
	}
	stream, cancel, err := a.openWatch(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make(chan stores.Change)
	go func() {
		defer close(out)
		backoff := time.Second
		for {
			a.forward(ctx, prefix, stream, out)
			cancel()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, 30*time.Second)
				if stream, cancel, err = a.openWatch(ctx, prefix); err == nil {
					backoff = time.Second
					break
				}
			}
		}
	}()
	return out, nil
}

type watchStream = grpc.ServerStreamingClient[pb.WatchEvent]

func (a *Adapter) openWatch(ctx context.Context, prefix stores.Ref) (watchStream, context.CancelFunc, error) {
	conn, done, err := a.client.Stream(ctx)
	if err != nil {
		return nil, nil, a.errorFor(stores.OpWatch, prefix, err)
	}
	sctx, cancel := context.WithCancel(ctx)
	type first struct {
		ev  *pb.WatchEvent
		err error
	}
	got := make(chan first, 1)
	var stream watchStream
	go func() {
		var err error
		stream, err = pb.NewStoreClient(conn).Watch(sctx, &pb.WatchRequest{Protocol: hostplugin.Protocol, Prefix: prefix.Path})
		if err != nil {
			got <- first{err: err}
			return
		}
		ev, err := stream.Recv()
		got <- first{ev, err}
	}()
	var f first
	timedOut := false
	select {
	case f = <-got:
	case <-time.After(a.client.CallTimeout()):
		timedOut = true
	case <-ctx.Done():
		f.err = ctx.Err()
	}
	if timedOut || f.err != nil {
		cancel()
		return nil, nil, a.errorFor(stores.OpWatch, prefix, a.client.StreamError(ctx, done, "watch", f.err, timedOut))
	}
	if !f.ev.GetReady() || f.ev.GetProtocol() != hostplugin.Protocol {
		cancel()
		return nil, nil, a.contract(stores.OpWatch, prefix, "the first watch message was not ready")
	}
	return stream, cancel, nil
}

// forward relays changes until the stream ends.
func (a *Adapter) forward(ctx context.Context, prefix stores.Ref, stream watchStream, out chan<- stores.Change) {
	glob := strings.HasSuffix(prefix.Path, "*") && a.caps.Has(stores.CapGlob)
	for {
		ev, err := stream.Recv()
		if err != nil {
			return
		}
		ok := under(ev.GetPath(), prefix.Path)
		if glob {
			ok = strings.HasPrefix(ev.GetPath(), strings.TrimSuffix(prefix.Path, "*"))
		}
		if !ok || ev.GetPath() == "" {
			continue
		}
		kind := stores.Changed
		switch ev.GetKind() {
		case pb.ChangeKind_CHANGE_KIND_CHANGED:
		case pb.ChangeKind_CHANGE_KIND_DELETED:
			kind = stores.Deleted
		default:
			continue
		}
		select {
		case out <- stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: ev.GetPath()}, Kind: kind}:
		case <-ctx.Done():
			return
		}
	}
}

// Write implements [stores.Adapter]. The caller keeps its values; the
// copies made for the request are zeroed once it is marshalled and again
// when the call returns.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref.Field = ""
	if err := a.gate(stores.OpWrite, ref, stores.CapWrite); err != nil {
		return stores.Metadata{}, err
	}
	req := &pb.WriteRequest{Protocol: hostplugin.Protocol, Path: ref.Path, CreateOnly: opts.CreateOnly, Labels: opts.Labels}
	for _, name := range sortedKeys(fields) {
		_ = fields[name].Expose(func(b []byte) error {
			req.Fields = append(req.Fields, &pb.Field{Name: name, Value: bytes.Clone(b)})
			return nil
		})
	}
	defer req.WipeSecrets()
	var resp *pb.WriteResponse
	err := a.client.Call(ctx, "write", func(ctx context.Context, conn *grpc.ClientConn) error {
		var err error
		resp, err = pb.NewStoreClient(conn).Write(ctx, req)
		return err
	})
	if err != nil {
		return stores.Metadata{}, a.errorFor(stores.OpWrite, ref, err)
	}
	m := a.metadata(ref.Scheme, resp.GetMeta())
	if m.Ref.Path == "" {
		m.Ref.Path = ref.Path
	}
	if m.Ref.Path != ref.Path {
		return stores.Metadata{}, a.contract(stores.OpWrite, ref, "answered for another path")
	}
	return m, nil
}

// Health implements [stores.Adapter].
func (a *Adapter) Health(ctx context.Context) error {
	err := a.client.Call(ctx, "health", func(ctx context.Context, conn *grpc.ClientConn) error {
		_, err := pb.NewStoreClient(conn).Health(ctx, &pb.HealthRequest{Protocol: hostplugin.Protocol})
		return err
	})
	if err != nil {
		e := a.errorFor(stores.OpHealth, stores.Ref{}, err)
		var se *stores.Error
		if errors.As(e, &se) && !errors.Is(se.Kind, stores.ErrPermission) && !errors.Is(se.Kind, stores.ErrLocked) {
			// Health is reachability: anything but a refusal is an outage.
			se.Kind = stores.ErrUnavailable
		}
		return e
	}
	return nil
}

// Close implements [stores.Adapter]: it stops the plugin and wipes the
// credentials.
func (a *Adapter) Close() error {
	err := a.client.Close()
	a.mu.Lock()
	for _, v := range a.creds {
		v.Wipe()
	}
	a.creds = nil
	a.mu.Unlock()
	return err
}

// Client is the plugin supervisor, for tests.
func (a *Adapter) Client() *hostplugin.Client { return a.client }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
