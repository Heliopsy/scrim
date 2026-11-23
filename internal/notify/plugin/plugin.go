// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin delivers approval requests through out-of-process notifier
// plugins (design D15, docs/plugins.md), configured in the `notify.plugins`
// collection:
//
//	notify:
//	  plugins:
//	    pager:
//	      command: /usr/local/libexec/scrim/scrim-notify-pager
//	      options: {channel: ops}
//	      token: file:/run/secrets/pager-token
//
// Like every notifier it only delivers: a plugin's answer can never approve
// anything, and a plugin that crashes, hangs or refuses fails that delivery
// with an error naming the instance, while the other notifiers still run.
package plugin

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/notify"
	hostplugin "github.com/heliopsy/scrim/internal/plugin"
	"github.com/heliopsy/scrim/internal/secret"
	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// Key is the collection key.
const Key = "notify.plugins"

// SecretFields are the credential fields a notifier plugin instance may set.
var SecretFields = []string{"token", "password", "secret", "credentials"}

// Collection is the registered `notify.plugins` collection. Validation
// checks the binary and starts a throwaway copy of the plugin to handshake
// and validate its options, without credentials.
var Collection = config.RegisterCollection(config.CollectionSpec{
	Key: Key,
	Description: "Notifier plugins by name (docs/plugins.md): `command` (absolute path of the plugin binary, owned by root or " +
		"scrim's user and writable by no one else), `args`, `env` (the plugin's environment; never a credential), `options` " +
		"(the plugin's own settings, validated by the plugin), `sha256` (pins the binary), `timeout` (per delivery, default 10s), " +
		"`start-timeout` (default 5s), and the credential fields `token`, `password`, `secret` and `credentials` (references, " +
		"resolved at every start and sent only to the plugin).",
	SecretFields:    SecretFields,
	RequiredFields:  []string{hostplugin.FieldCommand},
	RestartRequired: true,
	Validate: func(inst config.Instance) error {
		cfg, _, err := hostplugin.ParseConfig(inst.Name, pb.Kind_KIND_NOTIFIER, inst.Fields, SecretFields, nil)
		if err == nil {
			_, err = hostplugin.Validate(context.Background(), cfg, nil)
		}
		return err
	},
})

// Notifier delivers through one plugin instance.
type Notifier struct {
	name    string
	cfg     hostplugin.Config
	client  *hostplugin.Client
	resolve func(context.Context, config.SecretRef) (secret.Value, error)
}

// New returns a notifier for one configured instance. resolve turns the
// credential references into values at every plugin start.
func New(cfg hostplugin.Config, resolve func(context.Context, config.SecretRef) (secret.Value, error), log *slog.Logger) *Notifier {
	n := &Notifier{name: cfg.Instance, cfg: cfg, resolve: resolve}
	n.client = hostplugin.NewClient(cfg, log, n.configure)
	return n
}

// FromConfig builds every configured notifier plugin. Nothing starts until
// the first delivery.
func FromConfig(cfg *config.Config, log *slog.Logger) ([]*Notifier, error) {
	var out []*Notifier
	for _, inst := range Collection.Get(cfg) {
		pc, _, err := hostplugin.ParseConfig(inst.Name, pb.Kind_KIND_NOTIFIER, inst.Fields, SecretFields, nil)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", Key, inst.Name, err)
		}
		resolve := func(ctx context.Context, ref config.SecretRef) (secret.Value, error) {
			for _, f := range SecretFields {
				if s, ok := inst.Fields[f].(string); ok && s == string(ref) {
					if v, ok := cfg.SecretAt(inst.Key(Key, f)); ok {
						var c secret.Value
						_ = v.Expose(func(b []byte) error { c = secret.New(b); return nil })
						return c, nil
					}
				}
			}
			return cfg.ResolveRef(ctx, ref)
		}
		out = append(out, New(pc, resolve, log))
	}
	return out, nil
}

func (n *Notifier) configure(ctx context.Context, conn *grpc.ClientConn) error {
	opts, err := hostplugin.OptionsJSON(n.cfg.Options)
	if err != nil {
		return err
	}
	req := &pb.ConfigRequest{Protocol: hostplugin.Protocol, Instance: n.name, OptionsJson: opts, Secrets: map[string][]byte{}}
	defer req.WipeSecrets()
	// The configuration keeps its own copies, which are in the redaction
	// set; these are wiped as soon as the plugin has them.
	var resolved []secret.Value
	defer func() {
		for _, v := range resolved {
			v.Wipe()
		}
	}()
	names := make([]string, 0, len(n.cfg.Secrets))
	for k := range n.cfg.Secrets {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, name := range names {
		v, err := n.resolve(ctx, config.SecretRef(n.cfg.Secrets[name]))
		if err != nil {
			return &hostplugin.Failure{Instance: n.name, Code: codes.Unavailable, Msg: fmt.Sprintf("resolving %s: %v", name, err)}
		}
		resolved = append(resolved, v)
		_ = v.Expose(func(b []byte) error { req.Secrets[name] = bytes.Clone(b); return nil })
	}
	_, err = pb.NewPluginClient(conn).Configure(ctx, req)
	return err
}

// Name implements [notify.Notifier].
func (n *Notifier) Name() string { return n.name }

// Notify implements [notify.Notifier]. The request carries names, metadata
// and the decision links, never a value.
func (n *Notifier) Notify(ctx context.Context, r notify.Request) error {
	req := request(r)
	err := n.client.Call(ctx, "notify", func(ctx context.Context, conn *grpc.ClientConn) error {
		_, err := pb.NewNotifierClient(conn).Notify(ctx, req)
		return err
	})
	if err == nil {
		return nil
	}
	if d := hostplugin.Detail(err); d != "" {
		return fmt.Errorf("plugin notifier %s: %s", n.name, d)
	}
	return fmt.Errorf("plugin notifier %s: delivery failed (%s)", n.name, strings.ToLower(hostplugin.Code(err).String()))
}

func request(r notify.Request) *pb.NotifyRequest {
	s := r.Summary
	req := &pb.NotifyRequest{
		Protocol: hostplugin.Protocol, ApprovalId: r.ApprovalID, Agent: r.Agent.ID, Action: string(s.Action),
		Rule: r.Rule, Reason: r.Reason, ApproveUrl: r.ApproveURL, DenyUrl: r.DenyURL, Title: notify.Title(r),
		Tool: strings.TrimSpace(s.Tool + " " + s.Command),
	}
	if !s.Ref.IsZero() {
		req.Reference = s.Ref.String()
	}
	if s.Host != "" {
		path, _, _ := strings.Cut(s.Path, "?")
		req.Destination = strings.TrimSpace(s.Method + " " + s.Host + path)
	}
	if !r.ExpiresAt.IsZero() {
		req.ExpiresUnix = r.ExpiresAt.Unix()
	}
	for _, f := range notify.Fields(r) {
		req.Fields = append(req.Fields, &pb.SummaryField{Label: f.Label, Value: f.Value})
	}
	return req
}

// Close stops the plugin.
func (n *Notifier) Close() error { return n.client.Close() }

// Client is the plugin supervisor, for tests.
func (n *Notifier) Client() *hostplugin.Client { return n.client }
