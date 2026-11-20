// SPDX-License-Identifier: AGPL-3.0-only

package stores

import (
	"errors"
	"fmt"
)

// Error kinds. Every adapter error wraps exactly one, so callers decide with
// errors.Is and never by parsing messages.
var (
	// ErrInvalidRef: the reference does not parse.
	ErrInvalidRef = errors.New("invalid reference")
	// ErrUnknownStore: the scheme names no configured store instance.
	ErrUnknownStore = errors.New("unknown store")
	// ErrUnknownKind: no adapter factory is registered for the kind.
	ErrUnknownKind = errors.New("unknown store kind")
	// ErrNotFound: the secret or field does not exist.
	ErrNotFound = errors.New("not found")
	// ErrUnsupported: the adapter does not declare the capability.
	ErrUnsupported = errors.New("operation not supported by this store")
	// ErrPermission: the store refused scrim's credentials for this path.
	ErrPermission = errors.New("permission denied by store")
	// ErrUnavailable: the store cannot be reached right now (outage,
	// timeout). Callers keep the last known values and fail closed for
	// injection.
	ErrUnavailable = errors.New("store unavailable")
	// ErrLocked: the store is reachable but locked (Vaultwarden without its
	// unlock key).
	ErrLocked = errors.New("store locked")
	// ErrConflict: a create-only write found an existing secret, or a
	// version check failed.
	ErrConflict = errors.New("conflict")
	// ErrPending: the store holds the operation for approval (OpenBao
	// control groups).
	ErrPending = errors.New("pending approval in store")
)

// Op names an adapter operation in errors.
type Op string

// Operations.
const (
	OpRead   Op = "read"
	OpList   Op = "list"
	OpWatch  Op = "watch"
	OpWrite  Op = "write"
	OpHealth Op = "health"
)

// Error is the error type adapters return. Its message names the store,
// operation, reference and kind. Cause is kept for errors.Is/As but is not
// printed, because a store's own message can echo request data; adapters that
// want detail in the message put sanitised text in Detail.
type Error struct {
	Store  string
	Op     Op
	Ref    Ref
	Kind   error
	Detail string
	Cause  error
}

// NewError builds an [Error]. kind must be one of the package's error kinds.
func NewError(store string, op Op, ref Ref, kind error, cause error) *Error {
	return &Error{Store: store, Op: op, Ref: ref, Kind: kind, Cause: cause}
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("store %s: %s", e.Store, e.Op)
	if !e.Ref.IsZero() {
		msg += " " + e.Ref.String()
	}
	msg += ": " + e.Kind.Error()
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// Unwrap exposes the kind and the cause.
func (e *Error) Unwrap() []error {
	if e.Cause == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Cause}
}
