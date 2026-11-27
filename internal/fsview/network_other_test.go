// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix && !linux

package fsview

const envNetChild = "SCRIM_FSVIEW_TEST_NET"

func netChild() int { return 2 }
