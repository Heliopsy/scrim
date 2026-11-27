// SPDX-License-Identifier: AGPL-3.0-only

// Package agentapi assembles the agent-facing side of the control plane from
// the composition root: the local API on its Unix socket, the human entry
// page, and the adapters that connect the agent tools service to policy,
// state, stores and audit.
package agentapi

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/kube"
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

	// SocketGroup gives the socket to a group, so agents of other users
	// in that group can connect (with api.permissions 0660).
	SocketGroup = config.Register(config.Spec[string]{
		Key:             "api.group",
		Description:     "Group (name or ID) the API socket belongs to, so members can connect with api.permissions 0660. scrim must be a member. Empty keeps the group of the process.",
		RestartRequired: true,
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

// Kubernetes service account identity (specs/agent-identity "Kubernetes
// service account identity"). Read when the agent API starts.
var (
	KubeEnabled = config.Register(config.Spec[bool]{
		Key: "identity.kubernetes.enabled",
		Description: "Identify in-cluster callers by projected service account tokens, verified with the TokenReview API. " +
			"Pods send the token as the password of the proxy user k8s or as the value of x-scrim-session. On in the k8s profile.",
		Profiles:        map[string]bool{"k8s": true},
		RestartRequired: true,
	})
	KubeAudience = config.Register(config.Spec[string]{
		Key:             "identity.kubernetes.audience",
		Default:         kube.DefaultAudience,
		Description:     "Audience an agent's projected service account token must carry. Tokens for any other audience, such as a pod's default API token, are refused.",
		Validate:        nonEmpty,
		RestartRequired: true,
	})
	KubeAPIServer = config.Register(config.Spec[string]{
		Key:             "identity.kubernetes.api-server",
		Description:     "Base URL of the Kubernetes API server for TokenReview. Empty uses the in-cluster address (KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT).",
		RestartRequired: true,
	})
	KubeCAFile = config.Register(config.Spec[string]{
		Key:             "identity.kubernetes.ca-file",
		Default:         kube.DefaultCAFile,
		Description:     "CA bundle that verifies the API server.",
		RestartRequired: true,
	})
	KubeTokenFile = config.Register(config.Spec[string]{
		Key:         "identity.kubernetes.token-file",
		KeyMaterial: true,
		// Read only for TokenReview, so only with Kubernetes identity on:
		// in any pod the default path exists and is not scrim's.
		KeyMaterialWhen: KubeEnabled.Get,
		Default:         kube.DefaultTokenFile,
		Description: "scrim's own service account token, which authorises TokenReview calls (RBAC: create tokenreviews, " +
			"for example by binding system:auth-delegator). Re-read on every call, since the kubelet rotates it.",
		RestartRequired: true,
	})
	KubeCacheTTL = config.Register(config.Spec[time.Duration]{
		Key:             "identity.kubernetes.cache-ttl",
		Default:         time.Minute,
		Description:     "How long a verified token is trusted before the cluster is asked again, capped at the token's expiry. A deleted pod or service account is refused within this bound.",
		Validate:        positive,
		RestartRequired: true,
	})
	KubeAgents = config.Register(config.Spec[map[string]string]{
		Key: "identity.kubernetes.agents",
		Description: "Agents by service account: agent name to space-separated selectors sa:NAMESPACE/NAME (globs allowed), scope:SCOPE, label:K=V. " +
			"A service account no rule maps is the agent NAMESPACE/NAME, or unknown with identity.kubernetes.unmapped: unknown.",
		RestartRequired: true,
	})
	KubeUnmapped = config.Register(config.Spec[string]{
		Key:             "identity.kubernetes.unmapped",
		Default:         identity.UnmappedDerive,
		Enum:            []string{identity.UnmappedDerive, identity.UnmappedUnknown},
		Description:     "What a verified service account no identity.kubernetes.agents rule maps becomes: derive names the agent NAMESPACE/NAME, unknown treats it as an unknown caller.",
		RestartRequired: true,
	})
)

func nonEmpty(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	return nil
}

// KubeResolver builds the Kubernetes identity resolver from cfg, nil when
// identity.kubernetes.enabled is off.
func KubeResolver(cfg *config.Config) (*identity.KubeResolver, error) {
	if !KubeEnabled.Get(cfg) {
		return nil, nil
	}
	rules, err := identity.KubeRulesFromMap(KubeAgents.Get(cfg))
	if err != nil {
		return nil, err
	}
	rev, err := kube.NewReviewer(kube.Options{
		APIServer: KubeAPIServer.Get(cfg), CAFile: KubeCAFile.Get(cfg), TokenFile: KubeTokenFile.Get(cfg),
		Audience: KubeAudience.Get(cfg), CacheTTL: KubeCacheTTL.Get(cfg),
	})
	if err != nil {
		return nil, err
	}
	return &identity.KubeResolver{Reviewer: rev, Rules: rules, Unmapped: KubeUnmapped.Get(cfg)}, nil
}
