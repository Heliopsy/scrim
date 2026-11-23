// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/internal/vaultapi"
)

// The HTTP client, authentication and token renewal are shared with the
// vault adapter in package vaultapi.
type (
	client   = vaultapi.Client
	request  = vaultapi.Request
	response = vaultapi.Response
)

// escapePath escapes each segment of a slash-separated path, once.
func escapePath(p string) string { return vaultapi.EscapePath(p) }

func copyValue(v secret.Value) secret.Value { return vaultapi.CopyValue(v) }
