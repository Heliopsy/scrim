// SPDX-License-Identifier: AGPL-3.0-only

// Package agentapi assembles the agent-facing side of the control plane from
// the composition root: the local API on its Unix socket, the human entry
// page, and the adapters that connect the agent tools service to policy,
// state, stores and audit.
package agentapi

import (
	"fmt"
	"strconv"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Settings owned by the agent tools. They are read when the agent API starts,
// so each needs a restart to change.
var (
	// Socket is where the local API listens. Empty means
	// $XDG_RUNTIME_DIR/scrim/api.sock, or a per-user directory under the
	// temporary directory. Clients read the same setting as SCRIM_API_SOCKET.
	Socket = config.Register(config.Spec[string]{
		Key:             "api.socket",
		Description:     "Unix socket of the local agent API. Empty uses $XDG_RUNTIME_DIR/scrim/api.sock.",
		Flag:            true,
		RestartRequired: true,
	})

	// SocketMode is the socket file's permission bits, in octal.
	SocketMode = config.Register(config.Spec[string]{
		Key:             "api.permissions",
		Default:         "0600",
		Description:     "Permission bits of the API socket, octal. Widen (for example 0660) only to let agents running as other local users connect; their identity still comes from peer credentials.",
		RestartRequired: true,
		Validate: func(s string) error {
			_, err := parseMode(s)
			return err
		},
	})

	// Peers maps local users and groups to agents.
	Peers = config.Register(config.Spec[map[string]string]{
		Key: "identity.peers",
		Description: "Agents by local user or group: agent name to space-separated selectors uid:N, user:NAME, gid:N, group:NAME, scope:SCOPE, label:K=V. " +
			"Empty maps the user scrim runs as to one agent named after it.",
		RestartRequired: true,
	})

	// SessionTTL is the default session token lifetime.
	SessionTTL = config.Register(config.Spec[time.Duration]{
		Key:             "session.ttl",
		Default:         12 * time.Hour,
		Description:     "Default lifetime of a session token minted by scrim run. The token is revoked earlier when scrim run exits.",
		Validate:        positive,
		RestartRequired: true,
	})

	// SessionMaxTTL caps what scrim run can ask for.
	SessionMaxTTL = config.Register(config.Spec[time.Duration]{
		Key:             "session.max-ttl",
		Default:         7 * 24 * time.Hour,
		Description:     "Longest lifetime a session token can be minted with.",
		Validate:        positive,
		RestartRequired: true,
	})

	// EntryListen is the human entry page's address.
	EntryListen = config.Register(config.Spec[string]{
		Key:             "entry.listen",
		Default:         "127.0.0.1:0",
		Description:     "Loopback address of the page where a human enters a value for secret_ask_human. Port 0 picks a free port.",
		RestartRequired: true,
	})

	// GrantDefaultTTL is the grant duration when a request names none.
	GrantDefaultTTL = config.Register(config.Spec[time.Duration]{
		Key:             "tools.grant-default-ttl",
		Default:         15 * time.Minute,
		Description:     "Duration of a grant when secret_request names none.",
		Validate:        positive,
		RestartRequired: true,
	})

	// GrantMaxTTL caps every grant; a rule's own limit can only lower it.
	GrantMaxTTL = config.Register(config.Spec[time.Duration]{
		Key:             "tools.grant-max-ttl",
		Default:         8 * time.Hour,
		Description:     "Longest grant secret_request can produce. Longer requests are capped and the result says so.",
		Validate:        positive,
		RestartRequired: true,
	})

	// ApprovalTimeout is how long a pending approval waits for a human.
	ApprovalTimeout = config.Register(config.Spec[time.Duration]{
		Key:             "tools.approval-timeout",
		Default:         15 * time.Minute,
		Description:     "How long a pending approval waits for a decision before it expires as denied.",
		Validate:        positive,
		RestartRequired: true,
	})
)

func positive(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("must be positive, got %s", d)
	}
	return nil
}

func parseMode(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n == 0 || n&^0o777 != 0 {
		return 0, fmt.Errorf("must be octal permission bits such as 0600, got %q", s)
	}
	return uint32(n), nil
}
