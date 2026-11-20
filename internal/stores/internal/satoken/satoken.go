// SPDX-License-Identifier: AGPL-3.0-only

// Package satoken reads Kubernetes service account tokens for store logins.
//
// A token is read from its file at every login, never cached: the kubelet
// rotates projected tokens, and a token read once at start-up stops working
// when it expires. The content lives only in a secret.Value, which the
// caller wipes once the login request is sent.
package satoken

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/heliopsy/scrim/internal/secret"
)

// DefaultPath is where the kubelet mounts a pod's default service account
// token. A projected token with a dedicated audience is the better choice;
// the store docs show how to mount one.
const DefaultPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// Read returns the token in path without surrounding whitespace. Errors name
// the file, never its content.
func Read(path string) (secret.Value, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return secret.Value{}, fmt.Errorf("cannot read %s: %w", path, pe.Err)
		}
		return secret.Value{}, fmt.Errorf("cannot read %s", path)
	}
	v := secret.New(bytes.TrimSpace(b))
	secret.WipeBytes(b)
	if v.IsZero() {
		return secret.Value{}, fmt.Errorf("%s is empty", path)
	}
	return v, nil
}
