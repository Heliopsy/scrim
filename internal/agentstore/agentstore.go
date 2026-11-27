// SPDX-License-Identifier: AGPL-3.0-only

// Package agentstore decides which store identity an agent uses, and checks
// with the store that this identity may do what scrim's rules already
// allowed (specs/agent-identity "Agents act on stores with their own
// identity", "Kubernetes identity passed through", "Static per-agent store
// credentials as fallback", "Effective permission is the intersection").
//
// Per store, in order:
//
//  1. A login (identity.store-login):
//     - Kubernetes passthrough: a caller identified by its service account
//     token logs in to the store with that same token, at a role rendered
//     from its namespace and service account, so the store's own role for
//     that service account applies.
//     - Token exchange: scrim's identity issuer signs a token for the agent
//     and the store trades it for a credential of its own (Vault and
//     OpenBao JWT auth, AWS web identity, Google workload identity
//     federation, Entra ID federated credentials, Infisical OIDC, Doppler
//     OIDC service account identities), so the store's policy for that
//     agent applies and its audit names it.
//  2. A static per-agent credential (identity.store-credentials), held by
//     scrim and given by reference.
//  3. Neither: when the store has per-agent identity configured at all, the
//     agent is refused for that store; otherwise the store is used with
//     scrim's own identity ("shared"), which `scrim doctor` reports.
//
// The redaction set is always loaded with scrim's own identity, so a value
// an agent cannot use is still redacted (specs/agent-identity "Redaction
// coverage is separate from use"). This package governs use only.
package agentstore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Settings. Both are read at start-up.
var (
	// Login configures Kubernetes passthrough per store.
	Login = config.Register(config.Spec[map[string]string]{
		Key: "identity.store-login",
		Description: "Per-agent store login, by store instance. `kubernetes role:<template> [mount:<path>]` logs in to the store (OpenBao Kubernetes auth) " +
			"with the calling pod's own service account token. The token exchange methods present an identity token scrim's issuer (identity.issuer.url) signs for the agent: " +
			"`jwt role:<template> audience:<aud> [mount:jwt]` (Vault and OpenBao JWT auth), " +
			"`aws-web-identity role-arn:<template> [audience:sts.amazonaws.com] [duration:15m]`, " +
			"`gcp-workload-identity provider://iam.googleapis.com/projects/<n>/locations/global/workloadIdentityPools/<pool>/providers/<p> [service-account:<template>] [audience:<aud>]`, " +
			"`azure-federated tenant:<id> client-id:<template> [audience:api://AzureADTokenExchange] [authority:<url>]`, " +
			"`infisical-oidc identity-id:<template> audience:<aud>` and `doppler-oidc identity:<template> audience:<aud>`. In templates {agent}, {agent_slug}, {namespace} and {service_account} are replaced. " +
			"A store listed here refuses agents that have no usable identity of their own.",
		RestartRequired: true,
	})
	// Credentials holds static per-agent store credentials by reference.
	Credentials = config.Register(config.Spec[map[string]string]{
		Key: "identity.store-credentials",
		Description: "Static per-agent store credentials: `<store>/<agent>` to a reference (env:, file:, cred: or a store reference) of a store token held for that agent. " +
			"The fallback for agents without Kubernetes passthrough; a store listed here refuses agents that have none.",
		RestartRequired: true,
		Validate: func(m map[string]string) error {
			for _, k := range slices.Sorted(maps.Keys(m)) {
				if !isReference(config.SecretRef(m[k])) {
					// Never echo the value: it may be a pasted credential.
					return fmt.Errorf("%s must be a reference (env:, file:, cred: or a store reference), not a literal", k)
				}
			}
			return nil
		},
	})
)

func isReference(r config.SecretRef) bool {
	switch r.Kind() {
	case config.RefEnv, config.RefFile, config.RefCredential, config.RefStore:
		return true
	}
	return false
}

// Sources of an agent's store identity, as audited and shown by doctor.
const (
	SourceKubernetes = "kubernetes"
	SourceFederated  = "federated"
	SourceStatic     = "static"
	SourceShared     = "shared"
	SourceNone       = "none"
)

// ErrNoIdentity is an agent without a usable identity for a store that
// requires one.
var ErrNoIdentity = errors.New("no store identity for this agent")

// DefaultMount is the auth mount Kubernetes passthrough logs in at.
const DefaultMount = "kubernetes"

// MethodKubernetes is Kubernetes passthrough; the token exchange methods
// are the stores.Federation* constants.
const MethodKubernetes = stores.LoginKubernetes

// method describes one identity.store-login method's options.
type method struct {
	required []string
	optional []string
	// defaults fill options left out; a function of the options given.
	defaults func(map[string]string) map[string]string
	// templated options have {agent} and friends replaced per agent.
	templated []string
}

var methods = map[string]method{
	MethodKubernetes: {required: []string{"role"}, optional: []string{"mount"}, templated: []string{"role"},
		defaults: func(map[string]string) map[string]string { return map[string]string{"mount": DefaultMount} }},
	stores.FederationJWT: {required: []string{"role", "audience"}, optional: []string{"mount"}, templated: []string{"role"},
		defaults: func(map[string]string) map[string]string { return map[string]string{"mount": "jwt"} }},
	stores.FederationAWS: {required: []string{"role-arn"}, optional: []string{"audience", "duration"}, templated: []string{"role-arn"},
		defaults: func(map[string]string) map[string]string {
			return map[string]string{"audience": "sts.amazonaws.com", "duration": "15m"}
		}},
	stores.FederationGCP: {required: []string{"provider"}, optional: []string{"service-account", "audience"}, templated: []string{"service-account"},
		defaults: func(o map[string]string) map[string]string {
			// Google's default allowed audience for an OIDC provider is
			// its resource name with an https: prefix.
			return map[string]string{"audience": "https:" + o["provider"]}
		}},
	stores.FederationAzure: {required: []string{"tenant", "client-id"}, optional: []string{"audience", "authority"}, templated: []string{"client-id"},
		defaults: func(map[string]string) map[string]string {
			return map[string]string{"audience": "api://AzureADTokenExchange", "authority": "https://login.microsoftonline.com"}
		}},
	stores.FederationInfisical: {required: []string{"identity-id", "audience"}, templated: []string{"identity-id"}},
	stores.FederationDoppler:   {required: []string{"identity", "audience"}, templated: []string{"identity"}},
}

type login struct {
	method string
	opts   map[string]string
}

// Issuer mints identity tokens for agents ([issuer.Issuer]).
type Issuer interface {
	Mint(id identity.Identity, audience string) (secret.Value, time.Time, error)
}

// Checker applies the per-store identity rules.
type Checker struct {
	logins  map[string]login
	statics map[string]map[string]config.SecretRef
	lookup  func(stores.Ref) (stores.Adapter, error)
	resolve func(context.Context, config.SecretRef) (secret.Value, error)
	issuer  Issuer
	// kinds maps store instances to their adapter kinds.
	kinds           map[string]string
	skipWrites      bool
	refuseUnchecked []string
}

// Options build a Checker.
type Options struct {
	// Login and Credentials are the setting values.
	Login       map[string]string
	Credentials map[string]string
	// Lookup finds the adapter of a reference ([stores.Set.Lookup]).
	Lookup func(stores.Ref) (stores.Adapter, error)
	// Resolve reads a credential reference ([config.Config.ResolveRef]).
	Resolve func(context.Context, config.SecretRef) (secret.Value, error)
	// Issuer signs the identity tokens the exchange methods present; a
	// login with such a method and no issuer is a configuration error
	// when RequireIssuer is set.
	Issuer        Issuer
	RequireIssuer bool
	// Adapter finds a store by instance name, to check it supports its
	// login method; nil skips the check.
	Adapter func(name string) (stores.Adapter, bool)
	// Kinds maps store instance names to adapter kinds, which say whether a
	// store can check an agent's write ([stores.ChecksAgentWrites]).
	Kinds map[string]string
	// SkipWriteChecks and RefuseUncheckedWrites are the setting values
	// (identity.skip-agent-write-checks, identity.refuse-unchecked-writes).
	SkipWriteChecks       bool
	RefuseUncheckedWrites []string
}

// New parses the settings. Every problem is reported, naming its key.
func New(o Options) (*Checker, error) {
	c := &Checker{logins: map[string]login{}, statics: map[string]map[string]config.SecretRef{},
		lookup: o.Lookup, resolve: o.Resolve, issuer: o.Issuer,
		kinds: o.Kinds, skipWrites: o.SkipWriteChecks, refuseUnchecked: o.RefuseUncheckedWrites}
	var errs []error
	for _, store := range slices.Sorted(maps.Keys(o.Login)) {
		l, err := parseLogin(store, o.Login[store])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		where := "identity.store-login." + store
		if l.method != MethodKubernetes && o.RequireIssuer && o.Issuer == nil {
			errs = append(errs, fmt.Errorf("%s: method %s presents a token scrim signs: set identity.issuer.url and identity.issuer.listen", where, l.method))
		}
		if o.Adapter != nil {
			if err := supports(o.Adapter, store, l.method); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", where, err))
			}
		}
		c.logins[store] = l
	}
	for _, key := range slices.Sorted(maps.Keys(o.Credentials)) {
		store, agent, ok := strings.Cut(key, "/")
		if !ok || store == "" || agent == "" {
			errs = append(errs, fmt.Errorf("identity.store-credentials: key %q is not <store>/<agent>", key))
			continue
		}
		ref := config.SecretRef(o.Credentials[key])
		if !isReference(ref) {
			errs = append(errs, fmt.Errorf("identity.store-credentials.%s: must be a reference (env:, file:, cred: or a store reference), not a literal", key))
			continue
		}
		if c.statics[store] == nil {
			c.statics[store] = map[string]config.SecretRef{}
		}
		c.statics[store][agent] = ref
	}
	return c, errors.Join(errs...)
}

// parseLogin reads one identity.store-login value: a method followed by
// key:value options.
func parseLogin(store, v string) (login, error) {
	where := "identity.store-login." + store
	f := strings.Fields(v)
	if len(f) == 0 {
		return login{}, fmt.Errorf("%s: empty; start with a method (%s)", where, strings.Join(slices.Sorted(maps.Keys(methods)), ", "))
	}
	m, ok := methods[f[0]]
	if !ok {
		return login{}, fmt.Errorf("%s: unknown method %q (have %s)", where, f[0], strings.Join(slices.Sorted(maps.Keys(methods)), ", "))
	}
	l := login{method: f[0], opts: map[string]string{}}
	var errs []error
	for _, sel := range f[1:] {
		k, val, ok := strings.Cut(sel, ":")
		switch {
		case !ok || val == "":
			errs = append(errs, fmt.Errorf("%s: %q is not key:value", where, sel))
		case !slices.Contains(m.required, k) && !slices.Contains(m.optional, k):
			errs = append(errs, fmt.Errorf("%s: unknown option %q for method %s", where, k, l.method))
		case l.opts[k] != "":
			errs = append(errs, fmt.Errorf("%s: option %q given twice", where, k))
		default:
			l.opts[k] = val
		}
	}
	for _, k := range m.required {
		if l.opts[k] == "" {
			errs = append(errs, fmt.Errorf("%s: %s:<value> is required for method %s", where, k, l.method))
		}
	}
	if len(errs) > 0 {
		return login{}, errors.Join(errs...)
	}
	if m.defaults != nil {
		for k, d := range m.defaults(l.opts) {
			if l.opts[k] == "" {
				l.opts[k] = d
			}
		}
	}
	if mt, ok := l.opts["mount"]; ok {
		l.opts["mount"] = strings.Trim(mt, "/")
	}
	for k, val := range l.opts {
		if slices.Contains(m.templated, k) {
			if err := checkTemplate(val); err != nil {
				errs = append(errs, fmt.Errorf("%s: %s: %w", where, k, err))
			}
		} else if strings.ContainsAny(val, "{}") {
			errs = append(errs, fmt.Errorf("%s: %s takes no {placeholder}", where, k))
		}
	}
	if d := l.opts["duration"]; d != "" {
		if dd, err := time.ParseDuration(d); err != nil || dd < 15*time.Minute || dd > 12*time.Hour {
			errs = append(errs, fmt.Errorf("%s: duration %q must be between 15m and 12h", where, d))
		}
	}
	if p := l.opts["provider"]; p != "" && !strings.HasPrefix(p, "//iam.googleapis.com/") {
		errs = append(errs, fmt.Errorf("%s: provider must be //iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>", where))
	}
	if a := l.opts["authority"]; a != "" && !strings.HasPrefix(a, "https://") {
		errs = append(errs, fmt.Errorf("%s: authority must be an https URL", where))
	}
	return l, errors.Join(errs...)
}

// supports checks the store exists and accepts the login method.
func supports(adapter func(string) (stores.Adapter, bool), store, m string) error {
	a, ok := adapter(store)
	if !ok {
		return fmt.Errorf("no store named %q", store)
	}
	have := []string{}
	if f, ok := a.(stores.AgentFederation); ok {
		have = f.FederationMethods()
	}
	if slices.Contains(have, m) {
		return nil
	}
	if len(have) == 0 {
		return fmt.Errorf("store %s cannot log agents in with their own identity", store)
	}
	return fmt.Errorf("store %s does not take method %s (takes %s)", store, m, strings.Join(have, ", "))
}

var templateVars = []string{"{namespace}", "{service_account}", "{agent_slug}", "{agent}"}

func checkTemplate(t string) error {
	rest := t
	for _, v := range templateVars {
		rest = strings.ReplaceAll(rest, v, "")
	}
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("role template %q has an unknown {placeholder} (have %s)", t, strings.Join(templateVars, ", "))
	}
	return nil
}

func render(t string, id identity.Identity) string {
	return strings.NewReplacer(
		"{namespace}", id.Labels[identity.LabelNamespace],
		"{service_account}", id.Labels[identity.LabelServiceAccount],
		"{agent_slug}", Slug(id.Agent),
		"{agent}", id.Agent,
	).Replace(t)
}

// Slug is an agent name with every character outside [A-Za-z0-9_.-]
// replaced by '-', for store names that take no slash (a Kubernetes agent
// is <namespace>/<service account>).
func Slug(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
}

// SessionName derives the name a store records for the agent's session
// (AWS RoleSessionName: 2 to 64 of [A-Za-z0-9+=,.@_-]) from its principal:
// claude-laptop.<session>, k8s.agents.agent-a.
func SessionName(id identity.Identity) string {
	n := strings.Map(func(r rune) rune {
		if r == '+' || r == '=' || r == ',' || r == '.' || r == '@' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '.'
	}, id.Principal())
	if len(n) > 64 {
		// Keep the end, which holds the session.
		n = n[len(n)-64:]
	}
	for len(n) < 2 {
		n += "-"
	}
	return n
}

// Governed lists the stores with per-agent identity configured, sorted.
// Every use of their secrets is checked by the control plane.
func (c *Checker) Governed() []string {
	if c == nil {
		return nil
	}
	set := map[string]bool{}
	for s := range c.logins {
		set[s] = true
	}
	for s := range c.statics {
		set[s] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// Methods returns each store's login method.
func (c *Checker) Methods() map[string]string {
	out := map[string]string{}
	if c == nil {
		return out
	}
	for s, l := range c.logins {
		out[s] = l.method
	}
	return out
}

// Source says which store identity id uses for store.
func (c *Checker) Source(store string, id identity.Identity) string {
	if c == nil {
		return SourceShared
	}
	l, hasLogin := c.logins[store]
	statics, hasStatic := c.statics[store]
	switch {
	case !hasLogin && !hasStatic:
		return SourceShared
	case hasLogin && l.method == MethodKubernetes && id.Source == identity.SourceKubernetes && id.Known():
		return SourceKubernetes
	case hasLogin && l.method != MethodKubernetes && id.Known() && c.issuer != nil:
		return SourceFederated
	case id.Known() && statics[id.Agent] != "":
		return SourceStatic
	default:
		return SourceNone
	}
}

// Check returns nil when the store identity of id may perform op on ref,
// and the source it used. kubeToken is the caller's service account token
// for passthrough; the caller owns and wipes it. A store without per-agent
// identity is shared and always passes; refusals wrap
// [stores.ErrPermission] or [ErrNoIdentity].
func (c *Checker) Check(ctx context.Context, id identity.Identity, kubeToken []byte, op stores.Op, ref stores.Ref) (string, error) {
	if c == nil || ref.Scheme == "" {
		return SourceShared, nil
	}
	a, err := c.lookup(ref)
	if err != nil {
		return SourceNone, err
	}
	store := a.Name()
	src := c.source(store, id, kubeToken)
	if src == SourceShared {
		return src, nil
	}
	if src == SourceNone {
		return src, fmt.Errorf("store %s: agent %s: %w", store, id.Principal(), ErrNoIdentity)
	}
	return src, c.can(ctx, a, src, id, kubeToken, op, ref)
}

// source is [Checker.Source] for one request: Kubernetes passthrough
// without the caller's token falls back to a static credential, or none.
func (c *Checker) source(store string, id identity.Identity, kubeToken []byte) string {
	src := c.Source(store, id)
	if src == SourceKubernetes && len(kubeToken) == 0 {
		src = SourceNone
		if c.statics[store][id.Agent] != "" {
			src = SourceStatic
		}
	}
	return src
}

// can asks adapter a whether the agent's identity from src may perform op
// on ref.
func (c *Checker) can(ctx context.Context, a stores.Adapter, src string, id identity.Identity, kubeToken []byte, op stores.Op, ref stores.Ref) error {
	store := a.Name()
	acc, ok := a.(stores.AgentAccess)
	if !ok {
		return stores.NewError(store, op, ref, stores.ErrUnsupported, nil)
	}
	cred := stores.AgentCredential{Agent: id.Principal()}
	switch src {
	case SourceKubernetes:
		l := c.logins[store]
		cred.KubernetesJWT = secret.New(kubeToken)
		cred.Role, cred.Mount = render(l.opts["role"], id), l.opts["mount"]
		defer cred.KubernetesJWT.Wipe()
	case SourceFederated:
		cred.Federation = c.federation(c.logins[store], id)
	case SourceStatic:
		tok, err := c.resolve(ctx, c.statics[store][id.Agent])
		if err != nil {
			return fmt.Errorf("store %s: agent %s: resolving identity.store-credentials: %w", store, id.Principal(), err)
		}
		cred.Token = tok
		defer tok.Wipe()
	}
	return acc.AgentCan(ctx, cred, op, ref)
}

// federation builds the exchange for one agent: rendered options, the
// identity token's audience, a cache key covering the agent identity
// (pod included) and options, and a minter.
func (c *Checker) federation(l login, id identity.Identity) *stores.Federation {
	m := methods[l.method]
	params := make(map[string]string, len(l.opts))
	for k, v := range l.opts {
		if slices.Contains(m.templated, k) {
			v = render(v, id)
		}
		params[k] = v
	}
	aud := params["audience"]
	var key strings.Builder
	key.WriteString(l.method)
	for _, part := range []string{id.Principal(), id.Labels[identity.LabelPod]} {
		key.WriteString("\x00")
		key.WriteString(part)
	}
	for _, k := range slices.Sorted(maps.Keys(params)) {
		key.WriteString("\x00" + k + "=" + params[k])
	}
	iss := c.issuer
	return &stores.Federation{Method: l.method, Params: params, Audience: aud, SessionName: SessionName(id),
		Key: key.String(), Session: id.SessionID,
		Token: func() (secret.Value, error) {
			v, _, err := iss.Mint(id, aud)
			return v, err
		}}
}

// Row is one line of the doctor report.
type Row struct {
	Store string `json:"store"`
	// Agent is an agent name, or "*" for any Kubernetes service account.
	Agent  string `json:"agent"`
	Source string `json:"source"`
	// Detail is the role template or mount, never a credential.
	Detail string `json:"detail,omitempty"`
}

// Report lists, for each store, which identity each named agent uses, plus
// one row per store for Kubernetes service accounts not named.
func (c *Checker) Report(storeNames, agents []string) []Row {
	var rows []Row
	for _, store := range storeNames {
		l, hasLogin := c.loginOf(store)
		statics := c.staticsOf(store)
		if !hasLogin && len(statics) == 0 {
			rows = append(rows, Row{Store: store, Agent: "*", Source: SourceShared, Detail: "scrim's own identity"})
			continue
		}
		names := slices.Clone(agents)
		for a := range statics {
			if !slices.Contains(names, a) {
				names = append(names, a)
			}
		}
		slices.Sort(names)
		for _, a := range names {
			switch {
			case statics[a] != "":
				rows = append(rows, Row{Store: store, Agent: a, Source: SourceStatic, Detail: "identity.store-credentials"})
			case hasLogin && l.method != MethodKubernetes:
				rows = append(rows, Row{Store: store, Agent: a, Source: SourceFederated, Detail: l.describe()})
			case hasLogin:
				rows = append(rows, Row{Store: store, Agent: a, Source: SourceNone, Detail: "kubernetes passthrough only applies to service account callers"})
			default:
				rows = append(rows, Row{Store: store, Agent: a, Source: SourceNone, Detail: "refused: no per-agent credential"})
			}
		}
		switch {
		case hasLogin && l.method == MethodKubernetes:
			rows = append(rows, Row{Store: store, Agent: "*", Source: SourceKubernetes, Detail: "role " + l.opts["role"] + " at auth/" + l.opts["mount"]})
		case hasLogin:
			rows = append(rows, Row{Store: store, Agent: "*", Source: SourceFederated, Detail: l.describe()})
		default:
			rows = append(rows, Row{Store: store, Agent: "*", Source: SourceNone, Detail: "refused: no per-agent credential"})
		}
	}
	return rows
}

// describe names a login for doctor: the method and its options, which
// hold no credential.
func (l login) describe() string {
	parts := []string{l.method}
	for _, k := range slices.Sorted(maps.Keys(l.opts)) {
		parts = append(parts, k+":"+l.opts[k])
	}
	return strings.Join(parts, " ")
}

func (c *Checker) loginOf(store string) (login, bool) {
	if c == nil {
		return login{}, false
	}
	l, ok := c.logins[store]
	return l, ok
}

func (c *Checker) staticsOf(store string) map[string]config.SecretRef {
	if c == nil {
		return nil
	}
	return c.statics[store]
}
