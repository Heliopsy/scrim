// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Settings of the edge listener, read by `scrim proxy`.
var (
	// ListenAddr is the edge listener's address.
	ListenAddr = config.Register(config.Spec[string]{
		Key: "edge.listen",
		Description: "Address of the edge listener the forwarders in agent pods connect to (TLS; callers present a Kubernetes " +
			"service account token). Empty turns it off. Needs identity.kubernetes.enabled and edge.server-names.",
		Flag:            true,
		RestartRequired: true,
		Validate: func(s string) error {
			if s == "" {
				return nil
			}
			_, _, err := net.SplitHostPort(s)
			return err
		},
	})

	// ServerNames are the names in the edge listener's certificate.
	ServerNames = config.Register(config.Spec[[]string]{
		Key: "edge.server-names",
		Description: "Host names and IP addresses the edge listener's certificate carries, signed by the edge CA (edge.ca.*), " +
			"which the forwarders trust and nothing else does. A generated edge CA is name-constrained to these. Required with edge.listen.",
		RestartRequired: true,
	})

	// LegacyInterceptionCertificate serves forwarders from before the edge CA
	// a certificate from the interception CA.
	LegacyInterceptionCertificate = config.Register(config.Spec[bool]{
		Key: "edge.legacy-interception-certificate",
		Description: "For an upgrade window: a forwarder that does not announce the edge CA (one from scrim 1.0, which " +
			"trusts the interception CA) gets a listener certificate issued by the interception CA instead of the edge CA, " +
			"so agent pods started before the upgrade keep working until they are restarted. Forwarders that announce the " +
			"edge CA always get the edge CA's certificate. Turn it off once every agent pod runs the new forwarder.",
		Weakening:       true,
		RestartRequired: true,
	})
)

// Settings of the forwarder, read by `scrim edge` when it starts.

var (
	// Central is where the forwarder connects.
	Central = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.central",
		RestartRequired: true,
		Description:     "host:port of the central scrim's edge listener (edge.listen).",
		Flag:            true,
		Validate: func(s string) error {
			if s == "" {
				return nil
			}
			_, _, err := net.SplitHostPort(s)
			return err
		},
	})

	// ServerName overrides the name the central certificate is verified for.
	ServerName = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.server-name",
		RestartRequired: true,
		Description:     "Name the central scrim's certificate is verified for. Empty takes the host of edge-forwarder.central.",
		Flag:            true,
	})

	// CAFile is the CA the central certificate must chain to.
	CAFile = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.ca-file",
		RestartRequired: true,
		Default:         "/etc/scrim/edge-trust/scrim-edge-ca.pem",
		Description:     "PEM file of the edge CA the central scrim's certificate must chain to (never the interception CA). No system roots are used.",
		Flag:            true,
	})

	// TokenPath is the pod's projected service account token.
	TokenPath = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.token-file",
		KeyMaterial:     true,
		RestartRequired: true,
		Default:         "/var/run/secrets/scrim/token",
		Description:     "Projected service account token for scrim's audience, read again for every connection and sent to the central scrim only.",
		Flag:            true,
	})

	// ClientCertFile is the pod's client certificate, presented instead of
	// the token.
	ClientCertFile = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.client-cert-file",
		RestartRequired: true,
		Description: "PEM client certificate (chain) the forwarder presents to the central scrim instead of a service account " +
			"token, for a central scrim with identity.client-certificates. Read again for every connection, so a rotated " +
			"certificate is used at once. Needs edge-forwarder.client-key-file.",
		Flag: true,
	})
	// ClientKeyFile is the key of ClientCertFile.
	ClientKeyFile = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.client-key-file",
		KeyMaterial:     true,
		RestartRequired: true,
		Description:     "PEM private key of edge-forwarder.client-cert-file. It stays in the pod: the TLS handshake proves the forwarder holds it.",
		Flag:            true,
	})

	// SSHAgentSocket is the local ssh-agent socket.
	SSHAgentSocket = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.ssh-agent-socket",
		RestartRequired: true,
		Description:     "Unix socket the forwarder serves the ssh-agent on (point SSH_AUTH_SOCK at it). Empty serves none.",
		Flag:            true,
	})

	// APISocket is the local agent API socket.
	APISocket = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.api-socket",
		RestartRequired: true,
		Description:     "Unix socket the forwarder serves the agent API on, the exec broker included (point SCRIM_API_SOCKET at it). Empty serves none.",
		Flag:            true,
	})

	// Databases maps central database names to local listeners.
	Databases = config.Register(config.Spec[map[string]string]{
		Key:             "edge-forwarder.databases",
		RestartRequired: true,
		Description: "Databases to forward: the central scrim's database name to a loopback address in the pod " +
			"(app: 127.0.0.1:5432).",
		Validate: validDatabases,
	})

	// SocketPermissions are the Unix sockets' permission bits.
	SocketPermissions = config.Register(config.Spec[string]{
		Key:             "edge-forwarder.socket-permissions",
		RestartRequired: true,
		Description: "Permission bits of the forwarder's Unix sockets, octal. The default lets the agent's containers, " +
			"which run as other users, connect; the sockets live in a volume only this pod mounts.",
		Default: "0666",
		Validate: func(s string) error {
			_, err := ParseMode(s)
			return err
		},
	})

	// ConnectTimeout bounds connecting to the central scrim.
	ConnectTimeout = config.Register(config.Spec[time.Duration]{
		Key:             "edge-forwarder.connect-timeout",
		RestartRequired: true,
		Default:         10 * time.Second,
		Description:     "How long the forwarder waits for the central scrim before it refuses the local connection.",
		Validate: func(d time.Duration) error {
			if d <= 0 {
				return errors.New("must be positive")
			}
			return nil
		},
	})
)

// validDatabases checks edge-forwarder.databases: configuration names to
// loopback addresses.
func validDatabases(m map[string]string) error {
	var errs []error
	for name, addr := range m {
		if !databaseName.MatchString(name) {
			errs = append(errs, fmt.Errorf("%q is not a database name (databases.<name>)", name))
			continue
		}
		if err := loopbackAddr(addr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// databaseName is the shape of a configuration collection name, which
// databases.<name> follows.
var databaseName = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// ParseMode parses octal permission bits such as 0660.
func ParseMode(s string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0o"), 8, 32)
	if err != nil || v > 0o777 {
		return 0, fmt.Errorf("%q is not octal permission bits", s)
	}
	return uint32(v), nil
}

// loopbackAddr checks that addr is host:port on a loopback address.
func loopbackAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("port %q is not a number", port)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s is not a loopback address: a database port is reachable only from inside the pod", host)
	}
	return nil
}
