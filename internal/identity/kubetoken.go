// SPDX-License-Identifier: AGPL-3.0-only

package identity

import "context"

type kubeTokenKey struct{}

// WithKubernetesToken carries the verified service account token a request
// presented, so a store write on the caller's behalf can log in to the
// store as that service account (Kubernetes passthrough). The caller owns
// tok and wipes it when the request is done; nothing else keeps it.
func WithKubernetesToken(ctx context.Context, tok []byte) context.Context {
	if len(tok) == 0 {
		return ctx
	}
	return context.WithValue(ctx, kubeTokenKey{}, tok)
}

// KubernetesTokenFrom returns the token [WithKubernetesToken] carried, or
// nil. The caller borrows it and must not keep it past the request.
func KubernetesTokenFrom(ctx context.Context) []byte {
	tok, _ := ctx.Value(kubeTokenKey{}).([]byte)
	return tok
}
