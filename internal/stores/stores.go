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
)

var capNames = []struct {
	c    Capability
	name string
}{
	{CapRead, "read"}, {CapList, "list"}, {CapWatch, "watch"},
	{CapWrite, "write"}, {CapGenerate, "generate"}, {CapDynamic, "dynamic"},
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
// one of KubernetesJWT and Token is set. The adapter borrows the values and
// never keeps them past the call, except a login token derived from them,
// which it may cache for the agent until it expires.
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
