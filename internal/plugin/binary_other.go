// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package plugin

import "errors"

func checkOwnership(string) error {
	return errors.New("plugins are supported on Linux and macOS only")
}
