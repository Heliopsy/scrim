// SPDX-License-Identifier: AGPL-3.0-only

// Package aws holds the store adapters for AWS Secrets Manager (kind
// awssm) and AWS Systems Manager Parameter Store (kind ssm), specs/
// secret-stores "AWS Secrets Manager adapter" and "AWS SSM Parameter Store
// adapter":
//
//	<scheme>://<secret-name>[?version=<id>|stage=<label>][#<field>]      (awssm)
//	<scheme>://<parameter/path>[?version=<n>|label=<label>][#value]      (ssm)
//
// Both authenticate with the AWS SDK's default credential chain
// (environment, shared config profile, web identity token for IRSA, ECS and
// EKS Pod Identity container credentials, EC2 instance metadata), optionally
// with an IAM role assumed on top, or with access keys given by reference.
// Credentials are never logged, and the secret parts scrim holds are handed
// to the redaction set.
//
// The SDK provides credentials and SigV4 signing only. Requests are built
// and responses decoded here, so secret values move between the HTTP body
// and secret.Value without passing through Go strings (package wire).
package aws

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/agentcache"
)

// Adapter kinds this package registers. They are also the label prefixes:
// awssm.<attr> and ssm.<attr>.
const (
	KindSecretsManager = "awssm"
	KindParameterStore = "ssm"
)

// Field is the field a single-value secret is exposed as: an SSM parameter,
// a Secrets Manager secret whose string is not a JSON object, or a binary
// secret.
const Field = "value"

func init() {
	stores.DeclareMulti(KindSecretsManager, "stage")
	stores.DeclareMulti(KindParameterStore, "policy")
	stores.Register(KindSecretsManager, NewSecretsManager)
	stores.Register(KindParameterStore, NewParameterStore)
}

// base is what both adapters share.
type base struct {
	name string
	kind string
	s    *settings
	c    *client
	// agents caches the roles agents assumed with their own identity
	// (agent.go).
	agents *agentcache.Cache[*agentCreds]
}

// Name implements stores.Adapter.
func (b *base) Name() string { return b.name }

// Capabilities implements stores.Adapter. Watch polls the listing, which
// carries version identifiers but no values.
func (b *base) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite | stores.CapGlob
}

// Credentials implements stores.CredentialHolder: the static secret key,
// and the secret key and session token of the credentials last used.
func (b *base) Credentials() []secret.Value { return b.c.credentials() }

// Close implements stores.Adapter.
func (b *base) Close() error {
	b.agents.Close()
	b.c.close()
	return nil
}

// region is the configured or resolved region, "" before the first call.
func (b *base) region() string {
	if b.s.region != "" {
		return b.s.region
	}
	b.c.mu.Lock()
	defer b.c.mu.Unlock()
	return b.c.region
}

// fail turns a client error into a stores.Error for op on ref.
func (b *base) fail(op stores.Op, ref stores.Ref, err error) error {
	var se *stores.Error
	if errors.As(err, &se) {
		return se
	}
	var ae *apiError
	if errors.As(err, &ae) {
		kind := ae.kind
		if ae.deleted {
			kind = stores.ErrNotFound
			if op == stores.OpWrite {
				kind = stores.ErrConflict
			}
		}
		if op == stores.OpWrite && kind == stores.ErrInvalidRef && ae.code != "" {
			// The store refused what it was given (size, pattern, tag
			// limits): it cannot hold this write.
			kind = stores.ErrUnsupported
		}
		return &stores.Error{Store: b.name, Op: op, Ref: ref, Kind: kind, Detail: ae.msg, Cause: ae.cause}
	}
	return stores.NewError(b.name, op, ref, stores.ErrUnavailable, err)
}

func (b *base) invalid(op stores.Op, ref stores.Ref, detail string) error {
	return &stores.Error{Store: b.name, Op: op, Ref: ref, Kind: stores.ErrInvalidRef, Detail: detail}
}

func (b *base) unsupported(op stores.Op, ref stores.Ref, detail string) error {
	return &stores.Error{Store: b.name, Op: op, Ref: ref, Kind: stores.ErrUnsupported, Detail: detail}
}

// snapshotFunc lists the secrets under a prefix as path -> change marker
// (version and modification time), without values.
type snapshotFunc func(ctx context.Context, prefix stores.Ref) (map[string]string, error)

// watch polls snap every watch.interval with +-20% jitter and reports what
// changed. Errors back off exponentially up to watch.max-backoff; the
// channel stays open through an outage and closes only when ctx ends.
func (b *base) watch(ctx context.Context, prefix stores.Ref, snap snapshotFunc) (<-chan stores.Change, error) {
	// The baseline is taken before Watch returns, so a change made right
	// after the call is reported.
	prev, err := snap(ctx, prefix)
	if err != nil && !errors.Is(err, stores.ErrUnavailable) {
		return nil, err
	}
	ch := make(chan stores.Change, 64)
	go b.poll(ctx, prefix, snap, prev, err == nil, ch)
	return ch, nil
}

func (b *base) poll(ctx context.Context, prefix stores.Ref, snap snapshotFunc, prev map[string]string, haveBase bool, ch chan<- stores.Change) {
	defer close(ch)
	back := time.Duration(0)
	for {
		wait := jitter(b.s.watchInterval)
		if back > 0 {
			wait = jitter(back)
		}
		if sleep(ctx, wait) != nil {
			return
		}
		cur, err := snap(ctx, prefix)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if back == 0 {
				back = b.s.watchInterval
			}
			back = min(back*2, b.s.watchBackoff)
			continue
		}
		back = 0
		if !haveBase {
			// No baseline yet (the store was down when Watch started):
			// everything present is reported once, so the consumer
			// reloads it.
			prev, haveBase = map[string]string{}, true
		}
		for path, v := range cur {
			if old, ok := prev[path]; !ok || old != v {
				if !send(ctx, ch, stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: path}, Kind: stores.Changed}) {
					return
				}
			}
		}
		for path := range prev {
			if _, ok := cur[path]; !ok {
				if !send(ctx, ch, stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: path}, Kind: stores.Deleted}) {
					return
				}
			}
		}
		prev = cur
	}
}

func send(ctx context.Context, ch chan<- stores.Change, c stores.Change) bool {
	select {
	case ch <- c:
		return true
	case <-ctx.Done():
		return false
	}
}

func jitter(d time.Duration) time.Duration {
	// Uniform in [0.8d, 1.2d).
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// configError reports invalid options from a factory.
func configError(name string, err error) error {
	return &stores.Error{Store: name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
}

// listPrefix splits a listing prefix into the text a name must start with
// and whether the prefix is a glob (`app-*`) rather than a folder (`app`,
// `app/*`). Folder prefixes match names below them, not the folder's own
// name.
func listPrefix(path string) (string, bool) {
	if len(path) > 0 && path[len(path)-1] == '*' {
		return path[:len(path)-1], true
	}
	return path + "/", false
}
