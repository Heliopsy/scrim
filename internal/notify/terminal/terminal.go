// SPDX-License-Identifier: AGPL-3.0-only

// Package terminal is the notifier for approvals decided at a terminal: it
// writes one line per approval to the control plane's log stream, naming the
// commands that decide it. `scrim approvals list` shows the same pending
// approvals from any shell.
package terminal

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/notify"
)

// Enabled turns the terminal notifier on.
var Enabled = config.Register(config.Spec[bool]{
	Key:         "notify.terminal.enabled",
	Default:     true,
	Description: "Print each approval request with its scrim approve and scrim deny commands to the control plane's terminal.",
})

// Notifier writes approval lines to W.
type Notifier struct {
	mu sync.Mutex
	W  io.Writer
}

// Name implements notify.Notifier.
func (*Notifier) Name() string { return "terminal" }

// Notify implements notify.Notifier.
func (n *Notifier) Notify(_ context.Context, r notify.Request) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	left := time.Until(r.ExpiresAt).Round(time.Second)
	_, err := fmt.Fprintf(n.W, "scrim: approval %s pending (%s, rule %s, expires in %s)\n  scrim approve %s\n  scrim deny %s\n",
		r.ApprovalID, notify.Title(r), r.Rule, left, r.ApprovalID, r.ApprovalID)
	return err
}
