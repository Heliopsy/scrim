// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package keyring

import "errors"

func newBackend(cfg Config) (backend, error) {
	switch cfg.Backend {
	case BackendSecretService:
		return newSecretService(cfg), nil
	case BackendKeychain:
		return newKeychain(cfg), nil
	}
	return nil, errors.New("keyring: backend " + cfg.Backend + " is not available on this system")
}
