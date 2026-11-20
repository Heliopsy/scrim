// SPDX-License-Identifier: AGPL-3.0-only

// Package dataplane runs the Rust data plane as a child process and talks to
// it over the boundary protocol (design D11, D12).
//
// The release binary embeds scrim-dataplane (build tag embed_dataplane, set
// by `just build`). [Binary] resolves which executable to run, [Start]
// launches it with one end of a socketpair as fd 3 and returns a gRPC client
// over the other end, and [Supervisor] keeps it running: handshake, snapshot
// push, event and ask streams, restart with backoff, and not-ready while
// down so nothing is served unredacted.
//
// Launch on Linux runs the binary from a sealed memfd through
// /proc/self/fd/N. When the kernel refuses to execute memfds
// (vm.memfd_noexec) it falls back to a file under $XDG_RUNTIME_DIR/scrim,
// opened and checked against the embedded SHA-256 before it is executed
// through its descriptor. On macOS the file lives in the user cache
// directory and is hash-checked before exec.
package dataplane

import (
	"time"

	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// Protocol is the boundary protocol version this build speaks.
const Protocol = uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT)

// ChildFD is the descriptor number the data plane finds its socket on.
const ChildFD = 3

// Settings owned by this package.
var (
	// PathSetting runs a data plane binary from disk instead of the
	// embedded one. For development builds without embedding.
	PathSetting = config.Register(config.Spec[string]{
		Key:             "dataplane.path",
		Description:     "Path of a scrim-dataplane binary to run instead of the embedded one. For development builds; release builds embed it.",
		RestartRequired: true,
	})
	// MlockSetting is passed to the data plane as SCRIM_DP_MLOCK.
	MlockSetting = config.Register(config.Spec[string]{
		Key:             "dataplane.memory-lock",
		Default:         "auto",
		Enum:            []string{"auto", "require"},
		Description:     "Lock the data plane's memory so values are never swapped: auto locks when the memlock limit is unlimited and warns otherwise; require refuses to start without it.",
		RestartRequired: true,
	})
	// ExtraCAFile is passed to the data plane as SCRIM_DP_EXTRA_CA_FILE.
	ExtraCAFile = config.Register(config.Spec[string]{
		Key: "dataplane.upstream-ca-file",
		Description: "PEM bundle of extra roots the data plane trusts for upstream TLS (model providers and tool APIs), on top of the built-in Mozilla roots, " +
			"for example a cluster-internal CA. Empty trusts the built-in roots only.",
		RestartRequired: true,
	})
	// StartTimeout bounds launch plus handshake.
	StartTimeout = config.Register(config.Spec[time.Duration]{
		Key:         "dataplane.start-timeout",
		Default:     10 * time.Second,
		Description: "How long the data plane may take to start and answer the handshake.",
	})
	// MaxBackoff caps the delay between restarts.
	MaxBackoff = config.Register(config.Spec[time.Duration]{
		Key:         "dataplane.restart-max-backoff",
		Default:     30 * time.Second,
		Description: "Longest wait between data plane restarts after repeated crashes.",
	})
)
