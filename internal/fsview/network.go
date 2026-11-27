// SPDX-License-Identifier: AGPL-3.0-only

package fsview

import "net"

// Network asks [Wrap] to start the agent in a network namespace of its own
// with loopback only (run.network: proxy-only). Nothing in it reaches
// another host: the only way out is a listener the caller serves.
type Network struct {
	// Listen are loopback TCP addresses (host:port with an IP host) bound
	// inside the namespace before the agent starts. Their listening sockets
	// are handed to the caller ([Launch.Listeners]), which serves them from
	// outside the namespace; the agent never holds them.
	Listen []Listen `json:"listen,omitempty"`
	// Mask are paths of Unix sockets, or directories holding them, that
	// let a process start commands outside the session (the session bus,
	// the systemd user manager, container engines, tmux). Each one that
	// exists is covered for the agent: a file by /dev/null, a directory by
	// an empty read-only tmpfs.
	Mask []string `json:"mask,omitempty"`
}

// Listen is one address bound inside the network namespace.
type Listen struct {
	Addr string `json:"addr"`
	// Optional addresses (the IPv6 half of localhost) may fail to bind.
	Optional bool `json:"optional,omitempty"`
}

// Listener is a listening socket bound inside the agent's network
// namespace, served by the caller.
type Listener struct {
	// Addr is the address it was bound to, as asked in [Listen].
	Addr     string
	Listener net.Listener
}
