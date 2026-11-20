// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// RefKind classifies the value of a secret-ref setting.
type RefKind string

// Reference kinds.
const (
	// RefNone is an empty reference: the setting is not configured.
	RefNone RefKind = ""
	// RefLiteral is a value written in place. It is accepted with a warning,
	// or rejected for settings registered with RequireReference.
	RefLiteral RefKind = "literal"
	// RefEnv is `env:NAME`, read from the process environment.
	RefEnv RefKind = "env"
	// RefFile is `file:/absolute/path`, read from a file.
	RefFile RefKind = "file"
	// RefCredential is `cred:NAME`, a systemd credential read from
	// $CREDENTIALS_DIRECTORY/NAME (LoadCredential= or SetCredential=).
	RefCredential RefKind = "cred"
	// RefStore is `<scheme>://<path>[#field]`, resolved by a secret store.
	RefStore RefKind = "store"
)

// literalMarker is the reference form shown for a literal secret.
const literalMarker = "<literal>"

// maxSecretFile bounds how much of a file: or cred: reference is read.
const maxSecretFile = 1 << 20

var (
	envNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	credNamePattern = regexp.MustCompile(`^[A-Za-z0-9_@.:-]+$`)
	schemePattern   = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)
)

// ErrUnresolved is returned for a store reference that has not been resolved
// because no [StoreResolver] was available when the Config was built.
var ErrUnresolved = errors.New("store reference not resolved yet")

// Kind reports what form the reference takes.
func (r SecretRef) Kind() RefKind { return refKind(r) }

func refKind(r SecretRef) RefKind {
	s := string(r)
	switch {
	case s == "":
		return RefNone
	case strings.HasPrefix(s, "env:"):
		return RefEnv
	case strings.HasPrefix(s, "file:"):
		return RefFile
	case strings.HasPrefix(s, "cred:"):
		return RefCredential
	case schemePattern.MatchString(s):
		return RefStore
	}
	return RefLiteral
}

// Scheme returns the store scheme of a store reference (`bao` for
// `bao://kv/x`), or "" for every other kind.
func (r SecretRef) Scheme() string {
	if r.Kind() != RefStore {
		return ""
	}
	scheme, _, _ := strings.Cut(string(r), "://")
	return scheme
}

// Display returns the reference in a form that is safe to print: the
// reference itself for env:, file: and cred:, a store reference with any
// user information masked, and `<literal>` for a literal. It never returns
// a secret value.
func (r SecretRef) Display() string {
	switch r.Kind() {
	case RefNone:
		return ""
	case RefLiteral:
		return literalMarker
	case RefStore:
		scheme, rest, _ := strings.Cut(string(r), "://")
		authority, path, hasPath := strings.Cut(rest, "/")
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			authority = "***@" + authority[at+1:]
		}
		if hasPath {
			return scheme + "://" + authority + "/" + path
		}
		return scheme + "://" + authority
	}
	return string(r)
}

// String implements fmt.Stringer with [SecretRef.Display], so a literal
// never reaches a log line or error message through formatting.
func (r SecretRef) String() string { return r.Display() }

// MarshalText implements encoding.TextMarshaler with [SecretRef.Display].
func (r SecretRef) MarshalText() ([]byte, error) { return []byte(r.Display()), nil }

// syntax checks that a reference is well formed. Messages name the
// reference form only.
func (r SecretRef) syntax() error {
	s := string(r)
	switch r.Kind() {
	case RefEnv:
		if name := strings.TrimPrefix(s, "env:"); !envNamePattern.MatchString(name) {
			return fmt.Errorf("reference %s: %q is not a valid environment variable name", r.Display(), name)
		}
	case RefFile:
		if p := strings.TrimPrefix(s, "file:"); !filepath.IsAbs(p) {
			return fmt.Errorf("reference %s: the path must be absolute", r.Display())
		}
	case RefCredential:
		name := strings.TrimPrefix(s, "cred:")
		if !credNamePattern.MatchString(name) || name == "." || name == ".." {
			return fmt.Errorf("reference %s: %q is not a valid credential name", r.Display(), name)
		}
	case RefStore:
		_, rest, _ := strings.Cut(s, "://")
		if path, _, _ := strings.Cut(rest, "#"); path == "" {
			return fmt.Errorf("reference %s: the store path is empty", r.Display())
		}
	case RefNone, RefLiteral:
	}
	return nil
}

// StoreResolver resolves store references (`bao://...`) to secret values.
// The secret-stores layer implements it; configuration only knows the
// reference syntax. Errors must not contain the value.
type StoreResolver interface {
	ResolveSecret(ctx context.Context, ref string) (secret.Value, error)
}

// StoreResolverFunc adapts a function to [StoreResolver].
type StoreResolverFunc func(ctx context.Context, ref string) (secret.Value, error)

// ResolveSecret implements [StoreResolver].
func (f StoreResolverFunc) ResolveSecret(ctx context.Context, ref string) (secret.Value, error) {
	return f(ctx, ref)
}

// refResolver resolves references other than store references and, given a
// StoreResolver, store references too.
type refResolver struct {
	env    map[string]string
	stores StoreResolver
}

// resolve returns the value r points to. It never returns an empty value
// without an error.
func (rr refResolver) resolve(ctx context.Context, r SecretRef) (secret.Value, error) {
	if err := r.syntax(); err != nil {
		return secret.Value{}, err
	}
	s := string(r)
	var (
		v   secret.Value
		err error
	)
	switch r.Kind() {
	case RefNone:
		return secret.Value{}, nil
	case RefLiteral:
		v = secret.FromString(s)
	case RefEnv:
		name := strings.TrimPrefix(s, "env:")
		val, ok := rr.env[name]
		if !ok {
			return secret.Value{}, fmt.Errorf("reference %s: environment variable %s is not set", r.Display(), name)
		}
		v = secret.FromString(val)
	case RefFile:
		v, err = readSecretFile(strings.TrimPrefix(s, "file:"))
	case RefCredential:
		dir := rr.env["CREDENTIALS_DIRECTORY"]
		if dir == "" {
			return secret.Value{}, fmt.Errorf("reference %s: $CREDENTIALS_DIRECTORY is not set (systemd sets it for LoadCredential=)", r.Display())
		}
		v, err = readSecretFile(filepath.Join(dir, strings.TrimPrefix(s, "cred:")))
	case RefStore:
		if rr.stores == nil {
			return secret.Value{}, ErrUnresolved
		}
		v, err = rr.stores.ResolveSecret(ctx, s)
	}
	if err != nil {
		return secret.Value{}, fmt.Errorf("reference %s: %w", r.Display(), err)
	}
	if v.IsZero() {
		return secret.Value{}, fmt.Errorf("reference %s resolves to an empty value", r.Display())
	}
	return v, nil
}

// readSecretFile reads a secret file, dropping one trailing newline as
// written by `echo` and most editors. Errors name the path, never content.
func readSecretFile(path string) (secret.Value, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator configured this path
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return secret.Value{}, pe.Err
		}
		return secret.Value{}, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err != nil {
		secret.WipeBytes(b)
		return secret.Value{}, errors.New("read failed")
	}
	if len(b) > maxSecretFile {
		secret.WipeBytes(b)
		return secret.Value{}, fmt.Errorf("file is larger than %d bytes", maxSecretFile)
	}
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		n--
		if n > 0 && b[n-1] == '\r' {
			n--
		}
	}
	secret.WipeBytes(b[n:])
	return secret.Adopt(b[:n]), nil
}
