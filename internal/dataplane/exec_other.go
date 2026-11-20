// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package dataplane

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("the data plane runs on Linux and macOS only")

func prepare(Binary, bool) (*executable, error) { return nil, errUnsupported }

func execRefused(error) bool { return false }

func checkOwner(os.FileInfo, string) error { return errUnsupported }
