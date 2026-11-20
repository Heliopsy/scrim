// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"net"
	"net/url"
	"slices"
	"sync"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// ValueSource is one store's redaction set; *refresh.Refresher implements
// it.
type ValueSource interface {
	Store() string
	EachValue(fn func(src refresh.Source, v secret.Value))
}

// CAGeneration is one generation of the tool-proxy CA as the snapshot
// carries it. Key is the PKCS#8 PEM private key; the builder copies it and
// never keeps it.
type CAGeneration struct {
	CertPEM string
	Key     secret.Value
	Current bool
}

// SnapshotBuilder assembles the data plane snapshot from the control plane's
// current state (design D12). Every field is read fresh on each Build, so a
// push after any change carries all of it; nothing here waits on a store.
//
// Build returns fresh copies of every secret byte: the supervisor wipes them
// once the snapshot is sent.
type SnapshotBuilder struct {
	// Config returns the configuration in force.
	Config func() *config.Config
	// Values are the store refreshers.
	Values []ValueSource
	// Catalog returns the catalog in force; nil means no catalog.
	Catalog func() *catalog.Catalog
	// Policy returns the compiled decision table; nil denies everything.
	Policy func() *pb.Policy
	// CA returns the tool-proxy CA generations, current first; nil leaves
	// the data plane's own CA in place. The caller wipes the returned keys
	// after Build copied them.
	CA func() []CAGeneration
	// Listeners are the sockets the data plane serves. They are fixed at
	// start: listener addresses need a restart.
	Listeners []*pb.Listener

	mu   sync.Mutex
	keys *placeholder.Ring
}

// SetKeys replaces the placeholder keys. The builder owns ring from now on
// and wipes the previous one.
func (b *SnapshotBuilder) SetKeys(ring *placeholder.Ring) {
	b.mu.Lock()
	old := b.keys
	b.keys = ring
	b.mu.Unlock()
	if old != nil && old != ring {
		old.Wipe()
	}
}

// Placeholder returns the placeholder the model sees for value under the
// current key, with the slug the snapshot gives ref. It is what a capture or
// a write hands back before the next snapshot reaches the data plane.
func (b *SnapshotBuilder) Placeholder(ref stores.Ref, value secret.Value) (string, error) {
	slug := SlugFor(b.binding(ref), ref)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keys == nil || len(b.keys.Keys) == 0 {
		return "", errors.New("no placeholder key")
	}
	return placeholder.Derive(b.keys.Current(), slug, value)
}

// PlaceholderFor returns the placeholder of the value ref names in the
// redaction set, or "" when the set does not hold it. It implements the
// agent API's Placeholders.
func (b *SnapshotBuilder) PlaceholderFor(ref stores.Ref) string {
	var out string
	for _, src := range b.Values {
		src.EachValue(func(s refresh.Source, v secret.Value) {
			if out != "" || s.Retained || s.Pending || !sameSecret(s.Ref, ref) {
				return
			}
			if p, err := b.Placeholder(s.Ref, v); err == nil {
				out = p
			}
		})
	}
	return out
}

func sameSecret(a, b stores.Ref) bool {
	if a.Field == "" || b.Field == "" {
		return a.Secret() == b.Secret()
	}
	return a == b
}

func (b *SnapshotBuilder) binding(ref stores.Ref) catalog.Binding {
	if b.Catalog == nil {
		return catalog.Binding{Ref: ref}
	}
	c := b.Catalog()
	if c == nil {
		return catalog.Binding{Ref: ref}
	}
	return c.Ref(ref)
}

// SlugFor is the slug placeholders carry for ref: the catalog name when
// the catalog binds one, otherwise the reference itself.
func SlugFor(bd catalog.Binding, ref stores.Ref) string {
	if bd.Name != "" {
		return placeholder.Slug(bd.Name)
	}
	return placeholder.Slug(ref.String())
}

// Build assembles a snapshot. The supervisor sets protocol and version.
func (b *SnapshotBuilder) Build(context.Context) (*pb.Snapshot, error) {
	cfg := b.Config()
	snap := &pb.Snapshot{
		Listeners:    cloneListeners(b.Listeners),
		Routes:       routes(cfg),
		Redaction:    &pb.RedactionSettings{MinValueLength: uint32(MinValueLength.Get(cfg))}, //nolint:gosec // validated to 1..1024
		CaptureRules: captureRulesPB(cfg),
		Policy:       &pb.Policy{DefaultEffect: pb.Effect_EFFECT_DENY},
	}
	if b.Policy != nil {
		if p := b.Policy(); p != nil {
			snap.Policy = p
		}
	}

	ok := false
	defer func() {
		if !ok {
			wipeSnapshot(snap)
		}
	}()

	b.mu.Lock()
	if b.keys == nil || len(b.keys.Keys) == 0 {
		b.mu.Unlock()
		return nil, errors.New("snapshot: no placeholder key")
	}
	for i, k := range b.keys.Keys {
		pk := &pb.PlaceholderKey{Version: uint32(k.Version), Current: i == 0} //nolint:gosec // validated to 1..255
		if err := k.Key.Expose(func(raw []byte) error { pk.Key = slices.Clone(raw); return nil }); err != nil {
			b.mu.Unlock()
			return nil, errors.New("snapshot: placeholder key is not usable")
		}
		snap.PlaceholderKeys = append(snap.PlaceholderKeys, pk)
	}
	b.mu.Unlock()

	var cat *catalog.Catalog
	if b.Catalog != nil {
		cat = b.Catalog()
	}
	snap.Values = b.values(cat)

	if b.CA != nil {
		gens := b.CA()
		for _, g := range gens {
			c := &pb.CaCertificate{CertPem: g.CertPEM, Current: g.Current}
			err := g.Key.Expose(func(raw []byte) error { c.KeyPem = slices.Clone(raw); return nil })
			g.Key.Wipe()
			if err != nil || len(c.KeyPem) == 0 {
				return nil, errors.New("snapshot: tool-proxy CA key is not usable")
			}
			snap.ToolProxyCa = append(snap.ToolProxyCa, c)
		}
	}
	ok = true
	return snap, nil
}

// values copies every value of every store into entries, with the catalog
// binding of its reference. Only a current value is bound: a retained
// (rotated or deleted) value or a write in flight is redacted but never
// injected, and a declared placeholder names only the current value.
func (b *SnapshotBuilder) values(cat *catalog.Catalog) []*pb.ValueEntry {
	var out []*pb.ValueEntry
	declared := map[string]bool{}
	for _, src := range b.Values {
		store := src.Store()
		src.EachValue(func(s refresh.Source, v secret.Value) {
			e := &pb.ValueEntry{Store: store, Class: pb.ValueClass_VALUE_CLASS_CREDENTIAL}
			if err := v.Expose(func(raw []byte) error { e.Value = slices.Clone(raw); return nil }); err != nil || len(e.Value) == 0 {
				clear(e.Value)
				return
			}
			if s.Ref.IsZero() {
				// The adapter's own credentials: redacted, never injected.
				e.Ref = "store:" + store
				e.Slug = placeholder.Slug(store + "-credential")
				out = append(out, e)
				return
			}
			e.Ref = s.Ref.String()
			bd := catalog.Binding{Ref: s.Ref}
			if cat != nil {
				bd = cat.Ref(s.Ref)
			}
			e.Slug = SlugFor(bd, s.Ref)
			e.Name = bd.Name
			if bd.Class == catalog.ClassDisplay {
				e.Class = pb.ValueClass_VALUE_CLASS_DISPLAY
			}
			if !s.Retained && !s.Pending {
				e.BoundHosts = slices.Clone(bd.Hosts)
				e.InjectLocations = slices.Clone(bd.Inject)
				if bd.Placeholder != "" && !declared[bd.Placeholder] {
					declared[bd.Placeholder] = true
					e.DeclaredPlaceholders = []string{bd.Placeholder}
				}
			}
			out = append(out, e)
		})
	}
	return out
}

// routes are the provider routes, with the optional chain.
func routes(cfg *config.Config) []*pb.Route {
	var chain *pb.RouteChain
	if u := ChainURL.Get(cfg); u != "" {
		chain = &pb.RouteChain{Url: u, DirectOnUnavailable: ChainOnUnavailable.Get(cfg) == "direct"}
	}
	clone := func() *pb.RouteChain {
		if chain == nil {
			return nil
		}
		return &pb.RouteChain{Url: chain.GetUrl(), DirectOnUnavailable: chain.GetDirectOnUnavailable()}
	}
	return []*pb.Route{
		{Name: "anthropic", Provider: "anthropic", Upstream: UpstreamAnthropic.Get(cfg), PathPrefix: "/anthropic",
			Hosts: []string{"api.anthropic.com"}, Chain: clone()},
		{Name: "openai", Provider: "openai", Upstream: UpstreamOpenAI.Get(cfg), PathPrefix: "/openai",
			Hosts: []string{"api.openai.com"}, Chain: clone()},
		// Codex signed in with ChatGPT calls the Responses API on
		// chatgpt.com (/backend-api/codex/responses), reached through the
		// forward proxy.
		{Name: "chatgpt", Provider: "openai", Upstream: UpstreamChatGPT.Get(cfg), PathPrefix: "/chatgpt",
			Hosts: []string{"chatgpt.com"}, Chain: clone()},
	}
}

// bypass returns the loopback hosts of the upstreams and the chain, which
// agents must reach directly (specs/interception "Local chained proxies are
// not intercepted").
func bypass(cfg *config.Config) []string {
	var out []string
	for _, raw := range []string{ChainURL.Get(cfg), UpstreamAnthropic.Get(cfg), UpstreamOpenAI.Get(cfg), UpstreamChatGPT.Get(cfg)} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		h := u.Hostname()
		if ip := net.ParseIP(h); (ip != nil && ip.IsLoopback()) || h == "localhost" {
			if !slices.Contains(out, u.Host) {
				out = append(out, u.Host)
			}
		}
	}
	return out
}

func captureRulesPB(cfg *config.Config) []*pb.CaptureRule {
	var out []*pb.CaptureRule
	for _, r := range captureRules(cfg) {
		out = append(out, &pb.CaptureRule{Name: r.Name, Hosts: r.Hosts, Methods: r.Methods, Path: r.Path,
			Status: r.Status, JsonPointer: r.JSONPointer, Header: r.Header, StoreRef: r.StoreRef.String()})
	}
	return out
}

// ListenersFrom returns the data plane listeners the configuration names.
func ListenersFrom(cfg *config.Config) []*pb.Listener {
	var out []*pb.Listener
	if a := ProxyListen.Get(cfg); a != "" {
		out = append(out, &pb.Listener{Name: "llm", Kind: pb.ListenerKind_LISTENER_KIND_BASE_URL, Address: a})
	}
	if a := ProxySocket.Get(cfg); a != "" {
		out = append(out, &pb.Listener{Name: "llm-unix", Kind: pb.ListenerKind_LISTENER_KIND_UNIX, Address: a})
	}
	if a := ForwardListen.Get(cfg); a != "" {
		out = append(out, &pb.Listener{Name: "forward", Kind: pb.ListenerKind_LISTENER_KIND_FORWARD_PROXY, Address: a})
	}
	if a := ToolProxyListen.Get(cfg); a != "" {
		out = append(out, &pb.Listener{Name: "tool-proxy", Kind: pb.ListenerKind_LISTENER_KIND_TOOL_PROXY, Address: a})
	}
	return out
}

func cloneListeners(in []*pb.Listener) []*pb.Listener {
	out := make([]*pb.Listener, len(in))
	for i, l := range in {
		out[i] = &pb.Listener{Name: l.GetName(), Kind: l.GetKind(), Address: l.GetAddress()}
	}
	return out
}

// wipeSnapshot clears the secret bytes of a snapshot that is not sent.
func wipeSnapshot(s *pb.Snapshot) {
	for _, v := range s.GetValues() {
		clear(v.Value)
	}
	for _, k := range s.GetPlaceholderKeys() {
		clear(k.Key)
	}
	for _, c := range s.GetToolProxyCa() {
		clear(c.KeyPem)
	}
}
