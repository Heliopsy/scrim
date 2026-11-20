// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/entrypage"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/version"
)

// TerminalNotifier prints entry links for secret_ask_human to the operator's
// terminal (the control plane's standard error). The link is a one-time
// credential for that entry, so it goes only here and to other configured
// notifiers, never to the agent.
type TerminalNotifier struct {
	mu sync.Mutex
	W  io.Writer
}

// NotifyAsk implements agenttools.Notifier.
func (t *TerminalNotifier) NotifyAsk(_ context.Context, n agenttools.Notice) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := fmt.Fprintf(t.W, "\nscrim: agent %s asks a human for %s\n  %s\n  open %s\n  (expires %s)\n\n",
		n.Agent, n.Ref, n.Prompt, n.URL, n.ExpiresAt.Local().Format(time.Kitchen))
	return err
}

// Runtime is the running local API and entry page.
type Runtime struct {
	Socket   string
	EntryURL string
	Service  *agenttools.Service
	Sessions *identity.Manager

	api   *localapi.Server
	page  *entrypage.Page
	sock  net.Listener
	entry net.Listener
}

// Options tune New beyond configuration.
type Options struct {
	// Notifier receives entry links; nil prints them to Stderr.
	Notifier agenttools.Notifier
	Stderr   io.Writer
	// Placeholders, when set, fills placeholders into results.
	Placeholders Placeholders
}

// New builds the local API and entry page from the composition root and
// opens their listeners. Call Serve to run them.
func New(a *app.App, o Options) (*Runtime, error) {
	cfg := a.Config.Current()
	rules, err := identity.RulesFromMap(Peers.Get(cfg))
	if err != nil {
		return nil, err
	}
	peers, err := identity.NewPeerMap(rules, nil)
	if err != nil {
		return nil, err
	}
	mgr := identity.NewManager(identity.NewMemorySessions(), identity.ManagerOptions{
		DefaultTTL: SessionTTL.Get(cfg), MaxTTL: SessionMaxTTL.Get(cfg)})

	entryLn, err := entrypage.Listen(EntryListen.Get(cfg))
	if err != nil {
		return nil, err
	}
	links := entrypage.Links{Addr: entryLn.Addr().String()}

	notifier := o.Notifier
	if notifier == nil {
		w := o.Stderr
		if w == nil {
			w = io.Discard
		}
		notifier = &TerminalNotifier{W: w}
	}
	auditor := Audit{State: a.State}
	svc, err := agenttools.New(agenttools.Deps{
		Policy: Policy{Engine: a.Policy},
		Approvals: Approvals{Engine: a.Policy, State: a.State, Notifier: a.Notifier,
			DefaultTTL: GrantDefaultTTL.Get(cfg), MaxTTL: GrantMaxTTL.Get(cfg), ApprovalTimeout: ApprovalTimeout.Get(cfg)},
		Catalog:  Stores{Set: a.Stores, Placeholders: o.Placeholders},
		Store:    Stores{Set: a.Stores, Placeholders: o.Placeholders},
		Auditor:  auditor,
		Notifier: notifier,
		Links:    links,
		Logger:   a.Log,
	})
	if err != nil {
		_ = entryLn.Close()
		return nil, err
	}
	page := entrypage.New(svc, links.Addr, a.Log)

	path := Socket.Get(cfg)
	if path == "" {
		path = localapi.DefaultSocketPath()
	}
	mode, err := parseMode(SocketMode.Get(cfg))
	if err != nil {
		_ = entryLn.Close()
		return nil, err
	}
	sockLn, err := localapi.Listen(path, localapi.ListenOptions{Mode: fs.FileMode(mode)})
	if err != nil {
		_ = entryLn.Close()
		return nil, err
	}
	api := &localapi.Server{Resolver: identity.Resolver{Peers: peers, Sessions: mgr}, Sessions: mgr, Tools: svc,
		Auditor: auditor, Logger: a.Log, ServerVersion: version.Version}
	return &Runtime{Socket: path, EntryURL: links.Base(), Service: svc, Sessions: mgr,
		api: api, page: page, sock: sockLn, entry: entryLn}, nil
}

// Serve runs both listeners until ctx ends or one fails.
func (r *Runtime) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- r.api.Serve(ctx, r.sock) }()
	go func() { errc <- r.page.Serve(ctx, r.entry) }()
	first := <-errc
	cancel()
	second := <-errc
	return errors.Join(first, second)
}

// LogAddresses logs where the runtime listens.
func (r *Runtime) LogAddresses(l *slog.Logger) {
	l.Info("agent API listening", "socket", r.Socket, "entry_page", r.EntryURL)
}
