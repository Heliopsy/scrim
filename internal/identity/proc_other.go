// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package identity

func lookupProc(int32) (Proc, error) { return Proc{}, ErrNoProcessInfo }
