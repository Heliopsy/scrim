// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Problem is one thing wrong with a configuration: the setting it concerns
// (empty for problems with a whole file), where the bad value came from and
// what is wrong. A Problem never carries a secret value: messages about
// secret-ref settings name the reference form only.
type Problem struct {
	Key    string
	Source Source
	Err    error
}

func (p *Problem) Error() string {
	var b strings.Builder
	if p.Key != "" {
		b.WriteString(p.Key)
	}
	if p.Source.Kind != "" {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("(" + p.Source.String() + ")")
	}
	if b.Len() > 0 {
		b.WriteString(": ")
	}
	b.WriteString(p.Err.Error())
	return b.String()
}

// Unwrap returns the underlying error.
func (p *Problem) Unwrap() error { return p.Err }

// Problems flattens err, as returned by [Load] or [Build], into the problems
// it holds, in the order they were found. An error that is not a Problem is
// returned as a Problem without key or source.
func Problems(err error) []*Problem {
	if err == nil {
		return nil
	}
	switch e := err.(type) { //nolint:errorlint // walks the error tree itself; errors.As below covers the rest
	case *Problem:
		return []*Problem{e}
	case interface{ Unwrap() []error }:
		var out []*Problem
		for _, inner := range e.Unwrap() {
			out = append(out, Problems(inner)...)
		}
		return out
	}
	var p *Problem
	if errors.As(err, &p) {
		return []*Problem{p}
	}
	return []*Problem{{Err: err}}
}

func unknownKeyProblem(r *Registry, key string, src Source) *Problem {
	err := fmt.Errorf("%w %q", ErrUnknownKey, key)
	if near := r.Closest(key); near != "" {
		err = fmt.Errorf("%w (did you mean %q?)", err, near)
	}
	return &Problem{Key: key, Source: src, Err: err}
}

// newEntry builds an entry. For a map setting with a non-nil base the new
// map is merged into the base key by key, and the per-key sources follow.
func newEntry(s *Setting, v any, src Source, base *Entry) Entry {
	e := Entry{Setting: s, Value: v, Source: src}
	if s.Kind != KindMap {
		return e
	}
	m := v.(map[string]string)
	e.Sources = make(map[string]Source, len(m))
	if base != nil {
		merged := clone(base.Value).(map[string]string)
		for k, ks := range base.Sources {
			e.Sources[k] = ks
		}
		for k, x := range m {
			merged[k] = x
		}
		e.Value = merged
	}
	for k := range m {
		e.Sources[k] = src
	}
	return e
}

func mergeBase(prev Entry, merge bool) *Entry {
	if !merge || prev.Setting == nil || prev.Setting.Kind != KindMap {
		return nil
	}
	return &prev
}

// equalValues reports whether two setting values are equal. A nil and an
// empty list or map are equal.
func equalValues(a, b any) bool {
	switch x := a.(type) {
	case []string:
		y, _ := b.([]string)
		return slices.Equal(x, y)
	case map[string]string:
		y, _ := b.(map[string]string)
		if len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if w, ok := y[k]; !ok || w != v {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

// typedValue accepts a value that already has the setting's Go type, as
// profile values and programmatic layers supply.
func typedValue(kind Kind, raw any) (any, bool) {
	switch kind {
	case KindString:
		v, ok := raw.(string)
		return v, ok
	case KindSecretRef:
		v, ok := raw.(SecretRef)
		return v, ok
	case KindBool:
		v, ok := raw.(bool)
		return v, ok
	case KindInt:
		v, ok := raw.(int)
		return v, ok
	case KindFloat:
		v, ok := raw.(float64)
		return v, ok
	case KindDuration:
		v, ok := raw.(time.Duration)
		return v, ok
	case KindList:
		if v, ok := raw.([]string); ok {
			return clone(v), true
		}
	case KindMap:
		if v, ok := raw.(map[string]string); ok {
			return clone(v), true
		}
	}
	return nil, false
}
