// SPDX-License-Identifier: AGPL-3.0-only

package sqlite

// WithDetectFS replaces filesystem detection, for tests.
func WithDetectFS(o Options, f func(string) FSKind) Options {
	o.detectFS = f
	return o
}
