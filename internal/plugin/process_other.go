// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package plugin

import (
	"errors"
	"log/slog"
)

func spawn(string, Config, *slog.Logger) (*proc, error) {
	return nil, errors.New("plugins are supported on Linux and macOS only")
}

func killGroup(int) {}
