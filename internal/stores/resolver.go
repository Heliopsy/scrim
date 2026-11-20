// SPDX-License-Identifier: AGPL-3.0-only

package stores

import (
	"context"
	"fmt"

	"github.com/heliopsy/scrim/internal/secret"
)

// ResolveSecret implements config.StoreResolver: it resolves a store
// reference used as a configuration value (`token: bao://kv/scrim/x#token`)
// by reading it from its store. The reference must name one field unless
// the secret has exactly one. The caller owns and wipes the value. Errors
// name the reference, never a value.
func (s *Set) ResolveSecret(ctx context.Context, raw string) (secret.Value, error) {
	ref, err := ParseRef(raw)
	if err != nil {
		return secret.Value{}, err
	}
	sec, err := s.Read(ctx, ref)
	if err != nil {
		return secret.Value{}, err
	}
	if ref.Field == "" && len(sec.Fields) != 1 {
		n := len(sec.Fields)
		sec.Wipe()
		e := NewError(ref.Scheme, OpRead, ref, ErrInvalidRef, nil)
		e.Detail = fmt.Sprintf("secret has %d fields; name one with #<field>", n)
		return secret.Value{}, e
	}
	var out secret.Value
	for _, v := range sec.Fields {
		out = v
	}
	if out.IsZero() {
		sec.Wipe()
		e := NewError(ref.Scheme, OpRead, ref, ErrNotFound, nil)
		e.Detail = "empty value"
		return secret.Value{}, e
	}
	return out, nil
}
