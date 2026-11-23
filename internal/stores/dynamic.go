// SPDX-License-Identifier: AGPL-3.0-only

package stores

import (
	"context"
	"time"
)

// Dynamic secrets (specs/secret-stores "HashiCorp Vault adapter"). A store
// that issues credentials on demand (a Vault database, AWS or PKI secrets
// engine) hands each one out under a lease. scrim holds the lease for
// whoever the credential was issued to, a grant, renews it while that
// holder is active and revokes it as soon as the holder ends, so a
// credential never outlives the permission it was issued under.

// LeaseHolder is what a dynamic secret is issued for.
type LeaseHolder struct {
	// ID names the holder, for example "grant:<id>". [DynamicIssuer.Release]
	// revokes every lease held under it. It appears in logs and errors.
	ID string
	// Active reports whether the holder still needs its secrets and until
	// when at the latest. The issuer asks before every renewal and at its
	// check interval, and revokes the leases once it answers false or the
	// time it gave has passed. An error is not an answer: the leases are
	// kept until the last time Active gave, without renewal past it, and the
	// issuer asks again later. Nil means active until the lease's own
	// maximum TTL.
	Active func(ctx context.Context) (until time.Time, active bool, err error)
}

// LeaseInfo describes one lease, without the secret it covers.
type LeaseInfo struct {
	// ID is the store's lease ID. It names the engine path and is not a
	// credential.
	ID     string
	Ref    Ref
	Holder string
	Issued time.Time
	// Expires is when the lease ends unless it is renewed.
	Expires   time.Time
	Renewable bool
}

// DynamicIssuer is implemented by adapters that issue dynamic secrets
// (those declaring [CapDynamic]). Issued values are new for each call; the
// caller redacts them from the moment they are returned, as for any value
// scrim holds.
type DynamicIssuer interface {
	// Issue obtains a new secret at ref for holder and keeps its lease
	// renewed until the holder ends. The caller owns the returned values.
	Issue(ctx context.Context, ref Ref, holder LeaseHolder) (Secret, LeaseInfo, error)
	// Release revokes every lease held by holderID now. Revoking a lease the
	// store already dropped is not an error.
	Release(ctx context.Context, holderID string) error
	// Leases lists the leases currently held.
	Leases() []LeaseInfo
}
