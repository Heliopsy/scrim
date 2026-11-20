// SPDX-License-Identifier: AGPL-3.0-only

// Package agentstore decides which store identity an agent uses, and checks
// with the store that this identity may do what scrim's rules already
// allowed (specs/agent-identity "Agents act on stores with their own
// identity", "Kubernetes identity passed through", "Static per-agent store
// credentials as fallback", "Effective permission is the intersection").
//
// Per store, in order:
//
//  1. Kubernetes passthrough (identity.store-login): a caller identified by
//     its service account token logs in to the store with that same token,
//     at a role rendered from its namespace and service account, so the
//     store's own role for that service account applies.
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
		Description: "Per-agent store login, by store instance: `kubernetes role:<template> [mount:<path>]` logs in to the store (OpenBao Kubernetes auth) " +
			"with the calling pod's own service account token at the role the template names; {namespace}, {service_account} and {agent} are replaced. " +
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
	SourceStatic     = "static"
	SourceShared     = "shared"
	SourceNone       = "none"
)

// ErrNoIdentity is an agent without a usable identity for a store that
// requires one.
var ErrNoIdentity = errors.New("no store identity for this agent")

// DefaultMount is the auth mount Kubernetes passthrough logs in at.
const DefaultMount = "kubernetes"

type login struct {
	role  string
	mount string
}

// Checker applies the per-store identity rules.
type Checker struct {
	logins  map[string]login
	statics map[string]map[string]config.SecretRef
	lookup  func(stores.Ref) (stores.Adapter, error)
	resolve func(context.Context, config.SecretRef) (secret.Value, error)
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
}

// New parses the settings. Every problem is reported, naming its key.
func New(o Options) (*Checker, error) {
	c := &Checker{logins: map[string]login{}, statics: map[string]map[string]config.SecretRef{},
		lookup: o.Lookup, resolve: o.Resolve}
	var errs []error
	for _, store := range slices.Sorted(maps.Keys(o.Login)) {
		where := "identity.store-login." + store
		f := strings.Fields(o.Login[store])
		if len(f) == 0 || f[0] != "kubernetes" {
			errs = append(errs, fmt.Errorf("%s: must start with the method kubernetes", where))
			continue
		}
		l := login{mount: DefaultMount}
		for _, sel := range f[1:] {
			k, v, ok := strings.Cut(sel, ":")
			switch {
			case !ok || v == "":
				errs = append(errs, fmt.Errorf("%s: %q is not key:value", where, sel))
			case k == "role":
				l.role = v
			case k == "mount":
				l.mount = strings.Trim(v, "/")
			default:
				errs = append(errs, fmt.Errorf("%s: unknown option %q", where, k))
			}
		}
		if l.role == "" {
			errs = append(errs, fmt.Errorf("%s: role:<template> is required", where))
		}
		if err := checkTemplate(l.role); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
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

var templateVars = []string{"{namespace}", "{service_account}", "{agent}"}

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
		"{agent}", id.Agent,
	).Replace(t)
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

// Source says which store identity id uses for store.
func (c *Checker) Source(store string, id identity.Identity) string {
	if c == nil {
		return SourceShared
	}
	_, hasLogin := c.logins[store]
	statics, hasStatic := c.statics[store]
	switch {
	case !hasLogin && !hasStatic:
		return SourceShared
	case hasLogin && id.Source == identity.SourceKubernetes && id.Known():
		return SourceKubernetes
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
	src := c.Source(store, id)
	if src == SourceKubernetes && len(kubeToken) == 0 {
		src = SourceNone
		if c.statics[store][id.Agent] != "" {
			src = SourceStatic
		}
	}
	if src == SourceShared {
		return src, nil
	}
	if src == SourceNone {
		return src, fmt.Errorf("store %s: agent %s: %w", store, id.Principal(), ErrNoIdentity)
	}
	acc, ok := a.(stores.AgentAccess)
	if !ok {
		return src, stores.NewError(store, op, ref, stores.ErrUnsupported, nil)
	}
	cred := stores.AgentCredential{Agent: id.Principal()}
	switch src {
	case SourceKubernetes:
		l := c.logins[store]
		cred.KubernetesJWT = secret.New(kubeToken)
		cred.Role, cred.Mount = render(l.role, id), l.mount
		defer cred.KubernetesJWT.Wipe()
	case SourceStatic:
		tok, err := c.resolve(ctx, c.statics[store][id.Agent])
		if err != nil {
			return src, fmt.Errorf("store %s: agent %s: resolving identity.store-credentials: %w", store, id.Principal(), err)
		}
		cred.Token = tok
		defer tok.Wipe()
	}
	return src, acc.AgentCan(ctx, cred, op, ref)
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
			case hasLogin:
				rows = append(rows, Row{Store: store, Agent: a, Source: SourceNone, Detail: "kubernetes passthrough only applies to service account callers"})
			default:
				rows = append(rows, Row{Store: store, Agent: a, Source: SourceNone, Detail: "refused: no per-agent credential"})
			}
		}
		if hasLogin {
			rows = append(rows, Row{Store: store, Agent: "*", Source: SourceKubernetes, Detail: "role " + l.role + " at auth/" + l.mount})
		} else {
			rows = append(rows, Row{Store: store, Agent: "*", Source: SourceNone, Detail: "refused: no per-agent credential"})
		}
	}
	return rows
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
