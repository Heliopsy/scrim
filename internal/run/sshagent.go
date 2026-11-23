// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/sshagent"
)

// maxSocketPath is the longest Unix socket path every platform binds.
const maxSocketPath = 103

// startSSHAgent serves scrim's ssh-agent on the session directory's socket
// when the plan points SSH_AUTH_SOCK at it. The agent holds no key: every
// list and signature goes to the control plane over the local API, as this
// session.
func (p *Prepared) startSSHAgent() error {
	sock := filepath.Join(p.Dir, FileSSHAgent)
	if !slices.ContainsFunc(p.Plan.Set, func(v Var) bool { return v.Name == "SSH_AUTH_SOCK" && v.Value == sock }) {
		return nil
	}
	if len(sock) > maxSocketPath {
		return refused("the ssh-agent socket path %s is longer than a Unix socket allows; set run.ssh-agent=false or a shorter XDG_RUNTIME_DIR", sock)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return refused("starting scrim's ssh-agent failed: %v", err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		return refused("starting scrim's ssh-agent failed: %v", err)
	}
	srv := &sshagent.Server{Backend: p.client, Accept: sameUser}
	if p.opts.Log != nil {
		srv.Log = p.opts.Log.With("component", "ssh-agent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ctx, ln); err != nil && p.opts.Log != nil {
			p.opts.Log.Warn("scrim's ssh-agent stopped", "error", err)
		}
	}()
	p.stopSSH = func() { cancel(); <-done }
	return nil
}

// sameUser accepts connections from this user only.
func sameUser(c net.Conn) error {
	peer, err := identity.PeerOf(c)
	if err != nil {
		return err
	}
	if int64(peer.UID) != int64(os.Getuid()) {
		return fmt.Errorf("peer uid %d is not this user", peer.UID)
	}
	return nil
}
