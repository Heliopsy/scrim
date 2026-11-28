// SPDX-License-Identifier: AGPL-3.0-only

// Package stores is the contract between scrim and the secret stores it
// brokers (specs/secret-stores).
//
// An [Adapter] talks to one configured store instance. Adapters are built by
// a [Factory] registered under an adapter kind ("openbao", "infisical",
// "vaultwarden", ...) and addressed by references ([Ref]) whose scheme names
// the instance. Values cross this interface only as secret.Value; metadata
// ([Metadata]) never carries a value, so listing and health paths cannot leak
// one by construction.
//
// Every adapter must pass the conformance suite in package storetest.
package stores

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// Capability is one operation an adapter may support.
type Capability uint8

// Capabilities, in the order of the doctor capability matrix.
const (
	CapRead Capability = 1 << iota
	CapList
	CapWatch
	CapWrite
	CapGenerate
	CapDynamic
	// CapGlob: List and Watch accept a prefix whose last character is `*`
	// right after part of a name (`APP_*`, `dir/app-*`) and match every
	// secret whose path starts with the text before it. Without it a
	// redact target such as `env://APP_*` is refused instead of loading
	// nothing.
	CapGlob
)

var capNames = []struct {
	c    Capability
	name string
}{
	{CapRead, "read"}, {CapList, "list"}, {CapWatch, "watch"},
	{CapWrite, "write"}, {CapGenerate, "generate"}, {CapDynamic, "dynamic"},
	{CapGlob, "glob"},
}

// Capabilities is a set of [Capability].
type Capabilities = Capability

// Has reports whether every capability in want is in c.
func (c Capability) Has(want Capability) bool { return c&want == want }

// String lists the capabilities, for example "read,list,watch".
func (c Capability) String() string {
	var parts []string
	for _, n := range capNames {
		if c.Has(n.c) {
			parts = append(parts, n.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// Metadata describes a secret without its value. Everything here is safe to
// show an agent, log or store.
type Metadata struct {
	Ref Ref
	// Fields names the fields the secret holds.
	Fields []string
	// Version is the store's version identifier, if it has one.
	Version   string
	CreatedAt time.Time
	UpdatedAt time.Time
	// Labels is store custom metadata (for example bound hosts declared in
	// OpenBao custom metadata), used by the catalog. Adapters must not put
	// values here.
	Labels map[string]string
	// WriteOnly marks a secret under a path the adapter is configured to
	// treat as write-only: scrim may write it but never loads it from the
	// store, so only the value scrim itself wrote is redacted.
	WriteOnly bool
}

// Secret is a secret read from a store: its metadata and the values of the
// fields that were requested. Call [Secret.Wipe] when done.
type Secret struct {
	Meta   Metadata
	Fields map[string]secret.Value
}

// Field returns one field's value.
func (s Secret) Field(name string) (secret.Value, bool) {
	v, ok := s.Fields[name]
	return v, ok
}

// Wipe wipes every field value.
func (s Secret) Wipe() {
	for _, v := range s.Fields {
		v.Wipe()
	}
}

// WriteOptions tunes [Adapter.Write].
type WriteOptions struct {
	// CreateOnly fails with [ErrConflict] if the secret already exists.
	CreateOnly bool
	// Labels are stored as custom metadata where the store supports it.
	Labels map[string]string
}

// ChangeKind says what happened to a watched secret.
type ChangeKind uint8

// Change kinds.
const (
	Changed ChangeKind = iota + 1
	Deleted
)

func (k ChangeKind) String() string {
	switch k {
	case Changed:
		return "changed"
	case Deleted:
		return "deleted"
	}
	return "unknown"
}

// Change is one notification from [Adapter.Watch]. It carries no value; the
// refresher reads the secret again.
type Change struct {
	Ref  Ref
	Kind ChangeKind
}

// Adapter is one configured store instance. Implementations must be safe for
// concurrent use. Every error must wrap one of the kinds in errors.go (use
// [NewError]) and must never contain a value, including values echoed back
// in a store's own error message.
type Adapter interface {
	// Name is the instance name from configuration.
	Name() string
	// Capabilities declares what the adapter supports. Calling an
	// operation outside it returns [ErrUnsupported].
	Capabilities() Capabilities
	// Read returns the secret at ref. With ref.Field set, Fields holds only
	// that field, and [ErrNotFound] is returned if it does not exist.
	Read(ctx context.Context, ref Ref) (Secret, error)
	// List returns metadata of the secrets under prefix (a Ref whose Path
	// is a prefix; Field is ignored), recursively.
	List(ctx context.Context, prefix Ref) ([]Metadata, error)
	// Watch reports changes under prefix until ctx is done, then closes the
	// channel. Adapters without native change notification do not declare
	// [CapWatch]; scrim polls them instead.
	Watch(ctx context.Context, prefix Ref) (<-chan Change, error)
	// Write stores fields as a new version of the secret at ref (Field is
	// ignored). The caller keeps ownership of the values. A write the store
	// rejects leaves nothing partially written where the store allows it.
	Write(ctx context.Context, ref Ref, fields map[string]secret.Value, opts WriteOptions) (Metadata, error)
	// Health checks the store is reachable and the credentials work.
	Health(ctx context.Context) error
	// Close releases connections. The adapter is unusable afterwards.
	Close() error
}

// AgentCredential is an agent's own identity toward a store (specs/
// agent-identity "Agents act on stores with their own identity"). Exactly
// one of KubernetesJWT, Token and Federation is set. The adapter borrows the
// values and never keeps them past the call, except a login token derived
// from them, which it may cache for the agent until it expires.
type AgentCredential struct {
	// Agent is the agent's principal, used as a cache key and in errors.
	Agent string
	// KubernetesJWT is the agent pod's service account token, for a store
	// that trusts the cluster (OpenBao Kubernetes auth), with the role and
	// auth mount to log in at.
	KubernetesJWT secret.Value
	Role          string
	Mount         string
	// Token is a static store credential held for this agent.
	Token secret.Value
	// Federation exchanges an identity token scrim signs for the agent for
	// a short-lived store credential (specs/agent-identity "Token exchange
	// per store").
	Federation *Federation
}

// Federation methods, as identity.store-login names them.
const (
	// FederationJWT is Vault and OpenBao JWT auth.
	FederationJWT = "jwt"
	// FederationAWS is AWS STS AssumeRoleWithWebIdentity.
	FederationAWS = "aws-web-identity"
	// FederationGCP is Google workload identity federation (STS token
	// exchange, optionally impersonating a service account).
	FederationGCP = "gcp-workload-identity"
	// FederationAzure is an Entra ID federated credential (client
	// assertion).
	FederationAzure = "azure-federated"
	// FederationInfisical is an Infisical OIDC machine identity.
	FederationInfisical = "infisical-oidc"
	// FederationDoppler is a Doppler service account identity with OIDC
	// authentication.
	FederationDoppler = "doppler-oidc"
)

// Federation is an agent's identity token exchanged for a store
// credential: scrim signs a token for the agent (its identity issuer) and
// the store trades it for a credential of its own, so the store's policy
// for that agent applies and its audit names the agent.
type Federation struct {
	// Method is one of the Federation* constants.
	Method string
	// Params are the method's options with the agent's placeholders
	// rendered: role, mount, role-arn, duration, provider, service-account,
	// tenant, client-id, authority, identity-id, identity.
	Params map[string]string
	// Audience is what the identity token is minted for.
	Audience string
	// SessionName names the agent where the store records one (the AWS
	// RoleSessionName, shown in CloudTrail): derived from the agent's
	// principal, 2 to 64 characters of [A-Za-z0-9+=,.@_-].
	SessionName string
	// Key identifies the agent identity and parameters; adapters cache the
	// exchanged credential by it.
	Key string
	// Session is the scrim session the agent runs in, empty for peer and
	// Kubernetes agents. Credentials cached for it are dropped when it ends
	// ([SessionForgetter]).
	Session string
	// Token mints the agent's identity token for Audience. The caller
	// wipes it.
	Token func() (secret.Value, error)
}

// Param returns a federation parameter, or def when it is unset.
func (f *Federation) Param(name, def string) string {
	if v := f.Params[name]; v != "" {
		return v
	}
	return def
}

// LoginKubernetes is Kubernetes passthrough as identity.store-login names
// it: the agent pod's own service account token.
const LoginKubernetes = "kubernetes"

// AgentFederation is implemented by adapters that log agents in with their
// own identity, naming the identity.store-login methods they accept:
// [LoginKubernetes] and the Federation* constants.
type AgentFederation interface {
	FederationMethods() []string
}

// SessionForgetter is implemented by adapters that cache per-agent store
// credentials, so a scrim session's credentials are dropped when it ends.
type SessionForgetter interface {
	ForgetSession(id string)
}

// AgentAccess is implemented by adapters that can check what an agent's own
// store identity may do, so scrim's rules and the store's permissions for
// the agent are intersected (specs/agent-identity "Effective permission is
// the intersection").
type AgentAccess interface {
	// AgentCan returns nil when cred may perform op (OpRead or OpWrite) on
	// ref, an error of kind [ErrPermission] when the store refuses it, and
	// another kind when the check itself failed. Errors never hold a value.
	AgentCan(ctx context.Context, cred AgentCredential, op Op, ref Ref) error
}

var writeChecks struct {
	sync.RWMutex
	kinds map[string]bool
}

// DeclareAgentWriteCheck declares that adapters of kind answer
// [AgentAccess.AgentCan] for [OpWrite] without writing, so scrim asks the
// agent's own store identity before an agent's write
// (specs/agent-identity "Agent writes are checked as the agent"). An
// adapter that cannot tell without writing does not declare it and refuses
// OpWrite in AgentCan as [ErrUnsupported]. Call it from the adapter's init,
// next to [Register].
func DeclareAgentWriteCheck(kind string) {
	writeChecks.Lock()
	defer writeChecks.Unlock()
	if writeChecks.kinds == nil {
		writeChecks.kinds = map[string]bool{}
	}
	writeChecks.kinds[kind] = true
}

// ChecksAgentWrites reports whether kind was declared with
// [DeclareAgentWriteCheck].
func ChecksAgentWrites(kind string) bool {
	writeChecks.RLock()
	defer writeChecks.RUnlock()
	return writeChecks.kinds[kind]
}
