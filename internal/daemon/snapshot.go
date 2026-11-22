// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/policy"
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
	// Labels composes the labels rules see for a value from the labels its
	// store reported (stores.Set.Labels); nil sends store.name only.
	Labels func(ref stores.Ref, native map[string]string) map[string]string

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
		Restore:      restoreSettings(cfg),
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
	keys := labelKeys(snap.Policy)
	snap.ValueLabels = true
	snap.Values = b.values(cat, keys)
	snap.Unavailable = unavailable(cat, snap.Values)
	for _, u := range snap.Unavailable {
		if r, err := stores.ParseRef(u.GetRef()); err == nil {
			u.Labels = b.labels(keys, r, nil)
		}
	}

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
func (b *SnapshotBuilder) values(cat *catalog.Catalog, keys map[string]bool) []*pb.ValueEntry {
	var out []*pb.ValueEntry
	declared := map[string]bool{}
	for _, src := range b.Values {
		store := src.Store()
		src.EachValue(func(s refresh.Source, v secret.Value) {
			e := &pb.ValueEntry{Store: store, Class: pb.ValueClass_VALUE_CLASS_CREDENTIAL}
			if s.Ref.IsZero() {
				e.Labels = b.labels(keys, stores.Ref{Scheme: store}, nil)
			} else {
				e.Labels = b.labels(keys, s.Ref, s.Labels)
			}
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
				bindExtras(e, cat, bd)
				if bd.Placeholder != "" && !declared[bd.Placeholder] {
					declared[bd.Placeholder] = true
					e.DeclaredPlaceholders = []string{bd.Placeholder}
				}
			}
			out = append(out, e)
		})
	}
	return uniqueNames(out)
}

// labels is the part of what rules see as secret.labels for the value at
// ref that the snapshot's policy reads (keys); nil when it reads none. The
// data plane needs nothing else, and sending every label of every value
// costs memory per value in every data plane.
func (b *SnapshotBuilder) labels(keys map[string]bool, ref stores.Ref, native map[string]string) map[string]string {
	if len(keys) == 0 || b.Labels == nil {
		return nil
	}
	var out map[string]string
	for k, v := range b.Labels(ref, native) {
		if keys[k] {
			if out == nil {
				out = make(map[string]string, len(keys))
			}
			out[k] = v
		}
	}
	return out
}

// labelKeys are the secret.labels keys a condition of p reads, by index,
// selection, `in` or has(), in decided and residual clauses alike: the data
// plane evaluates the conditions of a residual clause too.
func labelKeys(p *pb.Policy) map[string]bool {
	var keys map[string]bool
	for _, r := range p.GetTable() {
		for _, c := range r.GetClauses() {
			for _, cond := range c.GetConditions() {
				if cond.GetField() == "secret.labels" && cond.GetKey() != "" {
					if keys == nil {
						keys = map[string]bool{}
					}
					keys[cond.GetKey()] = true
				}
			}
		}
	}
	return keys
}

// bindExtras copies the placeholder format, the client certificate flag and
// the AWS SigV4 link of a catalog binding into an entry. The SigV4 link names
// the access key id entry by its reference; one that does not resolve is
// left out, so the data plane never re-signs with a half-configured pair.
func bindExtras(e *pb.ValueEntry, cat *catalog.Catalog, bd catalog.Binding) {
	if bd.Class != catalog.ClassDisplay {
		e.PlaceholderFormat = bd.PlaceholderFormat
	}
	e.ClientCertificate = bd.ClientCertificate
	if a := bd.AWSSigV4; a != nil && cat != nil {
		if ak, err := cat.Name(a.AccessKeyID); err == nil && !ak.Ref.IsZero() {
			e.AwsSigv4 = &pb.AwsSigV4{
				AccessKeyIdRef: ak.Ref.String(),
				Regions:        slices.Clone(a.Regions),
				Services:       slices.Clone(a.Services),
			}
		}
	}
}

// uniqueNames drops repeated values and gives every credential entry a name no
// other entry uses, because the data plane refuses a snapshot in which two
// credentials share a name (the catalog name, else the reference) or a
// placeholder. Both happen without it: a store's own credentials repeat (a
// static OpenBao token is both the configured and the current token, each
// "store:<name>", with one placeholder), and a rotated value is retained under
// its entry's name next to the current one.
//
// An entry with the same slug and value as an earlier one would get the same
// placeholder, so it adds nothing and is dropped (its copy wiped). Of the
// rest, the first keeps its name, so a bound current value is never renamed;
// later ones get "~2", "~3", which no catalog name or reference contains.
func uniqueNames(entries []*pb.ValueEntry) []*pb.ValueEntry {
	out := entries[:0]
	bySlug := map[string][]*pb.ValueEntry{}
	seen := map[string]int{}
	for _, e := range entries {
		if slices.ContainsFunc(bySlug[e.GetSlug()], func(o *pb.ValueEntry) bool {
			return subtle.ConstantTimeCompare(o.GetValue(), e.GetValue()) == 1
		}) {
			clear(e.Value)
			continue
		}
		bySlug[e.GetSlug()] = append(bySlug[e.GetSlug()], e)
		out = append(out, e)
		if e.GetClass() == pb.ValueClass_VALUE_CLASS_DISPLAY {
			continue
		}
		n := e.GetName()
		if n == "" {
			n = e.GetRef()
		}
		seen[n]++
		if c := seen[n]; c > 1 {
			e.Name = fmt.Sprintf("%s~%d", n, c)
		}
	}
	clear(entries[len(out):])
	return out
}

// unavailable lists the catalog credentials bound to hosts that have no
// current value in values: a store still loading, a read that failed. The
// tool proxy refuses their placeholders toward their hosts with
// credential_unavailable instead of forwarding them as text
// (specs/credential-injection "Unresolved placeholders are refused"). No
// value is copied.
func unavailable(cat *catalog.Catalog, values []*pb.ValueEntry) []*pb.ValueEntry {
	if cat == nil {
		return nil
	}
	have := map[string]bool{}
	declared := map[string]bool{}
	for _, v := range values {
		have[v.GetRef()] = true
		if r, err := stores.ParseRef(v.GetRef()); err == nil {
			have[r.Secret().String()] = true
		}
		if v.GetName() != "" {
			have["name:"+v.GetName()] = true
		}
		for _, p := range v.GetDeclaredPlaceholders() {
			declared[p] = true
		}
	}
	var out []*pb.ValueEntry
	for _, e := range cat.Entries() {
		bd := e.Binding
		if !e.OK || e.Entry.Prefix != "" || bd.Ref.IsZero() || !bd.Injectable() || bd.Class == catalog.ClassDisplay {
			continue
		}
		if have[bd.Ref.String()] || have[bd.Ref.Secret().String()] || have["name:"+bd.Name] {
			continue
		}
		u := &pb.ValueEntry{
			Ref: bd.Ref.String(), Name: bd.Name, Slug: SlugFor(bd, bd.Ref), Class: pb.ValueClass_VALUE_CLASS_CREDENTIAL,
			Store: bd.Ref.Scheme, BoundHosts: slices.Clone(bd.Hosts), InjectLocations: slices.Clone(bd.Inject),
		}
		if bd.Placeholder != "" && !declared[bd.Placeholder] {
			declared[bd.Placeholder] = true
			u.DeclaredPlaceholders = []string{bd.Placeholder}
		}
		bindExtras(u, cat, bd)
		out = append(out, u)
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
		// Google Gemini API (Gemini CLI, the google-genai SDKs). The agent's
		// own x-goog-api-key header or key= query parameter is forwarded.
		{Name: "gemini", Provider: "gemini", Upstream: UpstreamGemini.Get(cfg), PathPrefix: "/gemini",
			Hosts: []string{"generativelanguage.googleapis.com"}, Chain: clone()},
		// Codex signed in with ChatGPT calls the Responses API on
		// chatgpt.com (/backend-api/codex/responses), reached through the
		// forward proxy.
		{Name: "chatgpt", Provider: "openai", Upstream: UpstreamChatGPT.Get(cfg), PathPrefix: "/chatgpt",
			Hosts: []string{"chatgpt.com"}, Chain: clone()},
		// ab.chatgpt.com carries the same session's traffic. No path there
		// is a Responses call, so every body is redacted as generic JSON.
		{Name: "chatgpt-ab", Provider: "openai", Upstream: UpstreamChatGPTAB.Get(cfg), PathPrefix: "/chatgpt-ab",
			Hosts: []string{"ab.chatgpt.com"}, Chain: clone()},
	}
}

// bypass returns the loopback hosts of the upstreams and the chain, which
// agents must reach directly (specs/interception "Local chained proxies are
// not intercepted").
func bypass(cfg *config.Config) []string {
	var out []string
	for _, raw := range []string{ChainURL.Get(cfg), UpstreamAnthropic.Get(cfg), UpstreamOpenAI.Get(cfg), UpstreamGemini.Get(cfg), UpstreamChatGPT.Get(cfg), UpstreamChatGPTAB.Get(cfg)} {
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
	block := TransparentUnrouted.Get(cfg) == "block"
	for i, a := range TransparentListen.Get(cfg) {
		name := "transparent"
		if i > 0 {
			name = fmt.Sprintf("transparent-%d", i+1)
		}
		out = append(out, &pb.Listener{Name: name, Kind: pb.ListenerKind_LISTENER_KIND_TRANSPARENT, Address: a, BlockUnrouted: block})
	}
	if a := SNIListen.Get(cfg); a != "" {
		out = append(out, &pb.Listener{Name: "sni", Kind: pb.ListenerKind_LISTENER_KIND_SNI, Address: a, BlockUnrouted: block})
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

// askTimeoutMillis is how long the data plane holds an operation it asked
// about (`Policy.ask_timeout_millis`): approvals.timeout, or the longest
// per-rule approval timeout when a rule sets a longer one. The table carries
// no per-rule timeout, so the data plane holds for the longest and the
// control plane expires each approval at its own rule's timeout, which then
// answers deny. At least 1 ms: 0 would mean the data plane's default.
func askTimeoutMillis(global time.Duration, cfg policy.Config) uint64 {
	t := global
	for _, r := range cfg.Rules {
		t = max(t, r.Approval.Timeout.D())
	}
	return uint64(max(t.Milliseconds(), 1)) // #nosec G115 -- positive
}

// ProviderHosts are the host names the provider routes claim: the names DNS
// override mode (scrim install --dns) resolves to scrim.
func ProviderHosts(cfg *config.Config) []string {
	var out []string
	for _, r := range routes(cfg) {
		for _, h := range r.GetHosts() {
			if !slices.Contains(out, h) {
				out = append(out, h)
			}
		}
	}
	return out
}
