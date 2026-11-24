// SPDX-License-Identifier: AGPL-3.0-only

// Package edge connects agent pods to a central scrim (specs/credential-injection
// "Edge forwarder for local sockets", tasks.md 12.5).
//
// Tools in an agent pod expect local endpoints: an ssh-agent at
// SSH_AUTH_SOCK, a database on a localhost port, the agent API (and with it
// the exec broker) on a Unix socket. Where scrim runs as a central
// deployment those endpoints would have to live in scrim's own pod. The
// [Forwarder] runs in the agent pod instead, serves them locally and carries
// every connection to the central scrim's edge listener ([Server]) over TLS:
//
//	git, ssh ─▶ SSH_AUTH_SOCK ──┐                       ┌─▶ ssh-agent keyring (keys from stores)
//	psql ─────▶ 127.0.0.1:5432 ─┼─▶ Forwarder ══TLS══▶ Server ─▶ database auth proxy (password from store)
//	scrim exec ▶ api.sock ──────┘   (agent pod)          └─▶ agent API, exec broker (runs centrally)
//
// The forwarder holds nothing secret. It authenticates each connection with
// the pod's projected service account token for scrim's audience, read from
// its file every time, and verifies the central certificate against the
// edge CA only: a CA of its own, not the interception CA, so the key that
// signs certificates for intercepted hosts cannot impersonate scrim to the
// forwarders. The server verifies the token with TokenReview through the same
// resolver every other Kubernetes caller goes through, so policy, approvals,
// grants and audit see the agent exactly as they see it on the proxy. Keys,
// database passwords and exec secrets stay in the central scrim; the pod
// receives public keys, signatures, database rows and redacted command
// output. When the central scrim cannot be reached or refuses the token,
// the local connection is closed (or, on the API socket, answered with an
// error): there is nothing in the pod to fall back to.
//
// The channel: one TLS 1.3 connection per local connection (HTTP/1.1, no
// HTTP/2). A tunnel is an HTTP Upgrade to [Protocol] on [PathSSHAgent] or
// [PathDatabase]/<name> with the token as a Bearer credential; after 101
// Switching Protocols the connection carries the tool's own protocol. API
// requests are plain HTTPS to the agent API's own paths, each with the token.
package edge

import (
	"bufio"
	"net"

	"github.com/heliopsy/scrim/internal/identity"
)

// Protocol is the Upgrade token of a tunnel.
const Protocol = "scrim-edge.v1"

// EdgeCAProto is the ALPN protocol a forwarder offers, besides http/1.1,
// to say it verifies the listener against the edge CA. The listener never
// selects it; with edge.legacy-interception-certificate it serves a
// forwarder that does not offer it (scrim 1.0's) the interception CA's
// certificate.
const EdgeCAProto = "scrim-edge-ca"

// Tunnel paths on the edge listener.
const (
	PathSSHAgent = "/edge/v1/ssh-agent"
	PathDatabase = "/edge/v1/database"
)

// Conn is a tunnel the edge listener accepted: the tool's byte stream and
// the agent the cluster verified for it. The central scrim's database proxy
// reads the caller from it ([IdentityOf]) instead of from the transport.
type Conn struct {
	net.Conn
	r  *bufio.Reader
	id identity.Identity
}

// Read reads what the HTTP layer buffered first, then the connection.
func (c *Conn) Read(p []byte) (int, error) {
	if c.r != nil {
		if c.r.Buffered() > 0 {
			return c.r.Read(p)
		}
		c.r = nil
	}
	return c.Conn.Read(p)
}

// Identity is the agent this tunnel belongs to.
func (c *Conn) Identity() identity.Identity { return c.id }

// IdentityOf returns the agent of an edge tunnel, and false for any other
// connection.
func IdentityOf(c net.Conn) (identity.Identity, bool) {
	ec, ok := c.(*Conn)
	if !ok {
		return identity.Identity{}, false
	}
	return ec.id, true
}
