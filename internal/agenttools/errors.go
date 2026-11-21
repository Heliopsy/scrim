// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"errors"
	"fmt"
)

// Code classifies an error for every transport: the local API maps it to an
// HTTP status, the MCP server to an error result, the CLI to an exit code.
type Code string

// The error codes.
const (
	CodeInvalid         Code = "invalid"
	CodeUnauthenticated Code = "unauthenticated"
	CodeForbidden       Code = "forbidden"
	CodeDenied          Code = "denied"
	CodeNeedsApproval   Code = "needs_approval"
	CodeNotFound        Code = "not_found"
	CodeConflict        Code = "conflict"
	CodeUnavailable     Code = "unavailable"
	CodeRateLimited     Code = "rate_limited"
	CodeInternal        Code = "internal"
)

// Error is an error safe to show to a caller. Its message is built from
// fixed text, references and other metadata, never from a value or from a
// dependency's error text.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Errorf returns an *Error. Arguments must be metadata, never values.
func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodeOf returns the code of err, CodeInternal for an error that is not an
// *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}

// Public returns err as an *Error a caller may see. Anything else becomes a
// generic internal error, so a dependency's message never reaches a caller.
func Public(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: CodeInternal, Message: "internal error"}
}
