// SPDX-License-Identifier: AGPL-3.0-only

// Command filenotify is an example scrim notifier plugin (docs/plugins.md):
// it appends each approval request to a file as one JSON line, signed with
// HMAC-SHA256 under the configured token so a reader can tell the lines came
// from scrim.
//
//	notify:
//	  plugins:
//	    file:
//	      command: /usr/local/libexec/scrim/filenotify
//	      options: {path: /var/lib/scrim/approvals.jsonl}
//	      token: file:/run/secrets/approvals-hmac
//
// The lines hold the single-use decision links, so the file must be readable
// only by the people who approve. It imports only the public SDK.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/pkg/plugin"
)

func main() {
	if err := plugin.ServeNotifier(&notifier{}); err != nil {
		fmt.Fprintln(os.Stderr, "filenotify:", err)
		os.Exit(1)
	}
}

type options struct {
	Path string `json:"path"`
}

type notifier struct {
	mu   sync.Mutex
	path string
	key  []byte
}

func (*notifier) Info() plugin.Info { return plugin.Info{Name: "filenotify", Version: "1.0.0"} }

func parse(c plugin.Config) (options, []string) {
	var o options
	dec := json.NewDecoder(strings.NewReader(string(c.Options)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return o, []string{"options: " + err.Error()}
	}
	var problems []string
	if o.Path == "" || !filepath.IsAbs(o.Path) {
		problems = append(problems, "options.path must be an absolute file path")
	}
	if _, ok := c.Secrets["token"]; !ok {
		problems = append(problems, "token is required: it keys the HMAC of every line")
	}
	for name := range c.Secrets {
		if name != "token" {
			problems = append(problems, "unexpected credential "+name)
		}
	}
	return o, problems
}

func (*notifier) ValidateConfig(c plugin.Config) []string {
	_, p := parse(c)
	return p
}

func (n *notifier) Configure(_ context.Context, c plugin.Config) error {
	o, p := parse(c)
	if len(p) > 0 {
		return errors.New(strings.Join(p, "; "))
	}
	if len(c.Secrets["token"]) == 0 {
		return errors.New("token is empty")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	clear(n.key)
	// c.Secrets is borrowed and zeroed after Configure: keep a copy.
	n.path, n.key = o.Path, slices.Clone(c.Secrets["token"])
	return nil
}

// line is what one approval request becomes.
type line struct {
	ApprovalID  string            `json:"approval_id"`
	Agent       string            `json:"agent"`
	Action      string            `json:"action"`
	Reference   string            `json:"reference,omitempty"`
	Destination string            `json:"destination,omitempty"`
	Tool        string            `json:"tool,omitempty"`
	Rule        string            `json:"rule,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	ExpiresAt   string            `json:"expires_at,omitempty"`
	ApproveURL  string            `json:"approve_url,omitempty"`
	DenyURL     string            `json:"deny_url,omitempty"`
	Title       string            `json:"title"`
	Fields      map[string]string `json:"fields,omitempty"`
	Signature   string            `json:"signature,omitempty"`
}

func (n *notifier) Notify(ctx context.Context, note plugin.Notification) error {
	if err := ctx.Err(); err != nil {
		return plugin.ErrUnavailable
	}
	l := line{
		ApprovalID: note.ApprovalID, Agent: note.Agent, Action: note.Action, Reference: note.Reference,
		Destination: note.Destination, Tool: note.Tool, Rule: note.Rule, Reason: note.Reason,
		ApproveURL: note.ApproveURL, DenyURL: note.DenyURL, Title: note.Title, Fields: map[string]string{},
	}
	if !note.ExpiresAt.IsZero() {
		l.ExpiresAt = note.ExpiresAt.UTC().Format(time.RFC3339)
	}
	for _, f := range note.Fields {
		l.Fields[f.Label] = f.Value
	}
	unsigned, err := json.Marshal(l)
	if err != nil {
		return plugin.ErrUnavailable
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	mac := hmac.New(sha256.New, n.key)
	mac.Write(unsigned)
	l.Signature = hex.EncodeToString(mac.Sum(nil))
	b, err := json.Marshal(l)
	if err != nil {
		return plugin.ErrUnavailable
	}
	f, err := os.OpenFile(n.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return plugin.ErrUnavailable
	}
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Close(); werr != nil || cerr != nil {
		return plugin.ErrUnavailable
	}
	return nil
}
