// SPDX-License-Identifier: AGPL-3.0-only

package stores

import "github.com/heliopsy/scrim/internal/secret"

// CredentialHolder is implemented by adapters that hold credentials of their
// own: configured tokens, AppRole secret IDs, client secrets, and the session
// tokens a store issues at login. scrim adds them to the redaction set
// (specs/secret-stores, "Scrim's store credentials are never exposed"), so an
// agent that finds one in a file or an environment cannot send it to a model
// provider.
type CredentialHolder interface {
	// Credentials returns copies of every credential the adapter currently
	// holds. The caller owns and wipes them. A login that issues a new
	// session token changes the result, so callers ask again on refresh.
	Credentials() []secret.Value
}
