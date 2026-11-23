// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package keyring

import (
	"context"
	"errors"
	"syscall"

	"github.com/danieljoos/wincred"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func newBackend(cfg Config) (backend, error) {
	switch cfg.Backend {
	case BackendWinCred:
		return winCred{}, nil
	case BackendSecretService:
		return newSecretService(cfg), nil
	}
	return nil, errors.New("keyring: backend " + cfg.Backend + " is not available on windows")
}

// winCred is the Windows backend: generic credentials in the Credential
// Manager, target name "<service>:<account>" (the go-keyring convention).
// CredRead returns the blob with the metadata, so a label lookup reads the
// value and wipes it at once, and listing is not offered (CredEnumerate
// would load every value).
type winCred struct{}

const errorNotFound = syscall.Errno(1168) // ERROR_NOT_FOUND

func (winCred) caps() stores.Capabilities { return stores.CapRead }

func (winCred) get(service, account string) (item, []byte, error) {
	c, err := wincred.GetGenericCredential(service + ":" + account)
	if err != nil {
		if errors.Is(err, errorNotFound) {
			return item{}, nil, kerr(stores.ErrNotFound, "", nil)
		}
		return item{}, nil, kerr(stores.ErrUnavailable, "Credential Manager read failed", err)
	}
	it := item{service: service, account: account, label: c.Comment, modified: c.LastWritten.UTC()}
	return it, c.CredentialBlob, nil
}

func (w winCred) read(_ context.Context, service, account string) (item, secret.Value, error) {
	it, blob, err := w.get(service, account)
	if err != nil {
		return item{}, secret.Value{}, err
	}
	return it, secret.Adopt(blob), nil
}

func (w winCred) meta(_ context.Context, service, account string) (item, error) {
	it, blob, err := w.get(service, account)
	secret.WipeBytes(blob)
	return it, err
}

func (winCred) list(context.Context, string) ([]item, error) {
	return nil, kerr(stores.ErrUnsupported, "the Credential Manager backend cannot list", nil)
}

func (winCred) health(context.Context) error { return nil }

func (winCred) close() error { return nil }
