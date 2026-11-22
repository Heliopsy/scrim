// SPDX-License-Identifier: AGPL-3.0-only

package bpfredirect

// The objects are committed; `just ebpf` regenerates them with clang from
// scripts/bpf/Containerfile and `just ebpf-check` fails when they are stale.
//go:generate go tool bpf2go -tags linux -target bpfel,bpfeb redirect bpf/redirect.c
