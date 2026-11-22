// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package bpfredirect

import "time"

// Loader attaches and detaches the programs; on this platform it only
// reports [ErrUnsupported].
type Loader struct {
	CgroupRoot string
	PinRoot    string
	RecordPath string
	Caps       func() Caps
	Now        func() time.Time
}

// Check reports [ErrUnsupported].
func (Loader) Check() error { return ErrUnsupported }

// Attach reports [ErrUnsupported].
func (Loader) Attach(string, int) (Attachment, error) { return Attachment{}, ErrUnsupported }

// Detach reports [ErrUnsupported].
func (Loader) Detach(string) error { return ErrUnsupported }

func cgroupID(string) (uint64, error) { return 0, ErrUnsupported }

func queryKernel(string) (map[string][]uint32, error) { return nil, ErrUnsupported }
