// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dbproxy"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// databases runs the database auth proxies and serves the read-only
// database tool (specs/credential-injection "Database auth proxies",
// "Read-only database tool").
type databases struct {
	d     *Daemon
	order []string
	specs map[string]*dbEntry
}

type dbEntry struct {
	dbproxy.Spec
	proxy  *dbproxy.Proxy
	listen string
}

// Tool names policy and audit see for the two ways into a database.
const dbProxyTool = "database-proxy"

// startDatabases binds every configured database's listener and serves it
// until ctx ends.
func (d *Daemon) startDatabases(ctx context.Context, cfg *config.Config) error {
	specs, err := dbproxy.Specs(cfg, d.app.Config.Current)
	if err != nil {
		return err
	}
	ds := &databases{d: d, specs: map[string]*dbEntry{}}
	log := obs.WithComponent(d.app.Log, "database")
	for _, s := range specs {
		e := &dbEntry{Spec: s}
		e.proxy = &dbproxy.Proxy{DB: s.DB, Authorize: ds.authorize, Log: log}
		ln, err := listenDatabase(s)
		if err != nil {
			return fmt.Errorf("%s.%s.listen: %w", dbproxy.CollectionKey, s.DB.Name, err)
		}
		if path, ok := strings.CutPrefix(s.Listen, "unix:"); ok {
			e.listen = s.Listen
			d.cleanup = append(d.cleanup, func() { _ = os.Remove(path) })
		} else {
			e.listen = ln.Addr().String()
		}
		if s.DB.TLS == dbproxy.TLSInsecurePlaintext {
			log.Warn("database connects without TLS: the session and the server's identity are unprotected", "database", s.DB.Name,
				"setting", dbproxy.CollectionKey+"."+s.DB.Name+".tls")
		}
		ds.specs[s.DB.Name] = e
		ds.order = append(ds.order, s.DB.Name)
		if d.addrs.Databases == nil {
			d.addrs.Databases = map[string]string{}
		}
		d.addrs.Databases[s.DB.Name] = e.listen
		proxy := e.proxy
		d.goRun("database "+s.DB.Name, func() error { return proxy.Serve(ctx, ln) })
		log.Info("database proxy listening", "database", s.DB.Name, "kind", string(s.DB.Kind), "listen", e.listen)
	}
	d.runtime.SetDatabases(ds)
	return nil
}

func listenDatabase(s dbproxy.Spec) (net.Listener, error) {
	if path, ok := strings.CutPrefix(s.Listen, "unix:"); ok {
		return localapi.Listen(path, localapi.ListenOptions{Mode: s.ListenMode})
	}
	return net.Listen("tcp", s.Listen)
}

// identify establishes who is on a proxy connection from the transport
// only: the kernel's peer credentials on a Unix socket, the owner of the
// client socket on a loopback TCP connection, else nobody.
func (ds *databases) identify(ctx context.Context, c net.Conn) (identity.Identity, error) {
	var claim identity.TransportClaim
	if p, err := identity.PeerOf(c); err == nil {
		claim.UnixPeer, claim.Peer = true, p
	} else if p, err := identity.LoopbackPeerOf(c); err == nil {
		claim.UnixPeer, claim.Peer = true, p
	}
	if ds.d.runtime == nil || ds.d.runtime.Resolver == nil {
		return identity.Unknown(claim.Peer), nil
	}
	return ds.d.runtime.Resolver.ResolveClaim(ctx, claim)
}

func (ds *databases) authorize(ctx context.Context, db *dbproxy.Database, c net.Conn) (dbproxy.Caller, error) {
	e := ds.specs[db.Name]
	if e == nil {
		return dbproxy.Caller{}, dbproxy.Refused("database %s is not configured", db.Name)
	}
	id, err := ds.identify(ctx, c)
	if err != nil {
		if _, refused := identity.IsRefused(err); refused {
			return dbproxy.Caller{}, dbproxy.Refused("database %s: the session was refused", db.Name)
		}
		return dbproxy.Caller{}, err
	}
	if v := ds.check(ctx, id, e, "connect", dbProxyTool); !v.Allowed() {
		return dbproxy.Caller{}, dbproxy.Refused("database %s: %s", db.Name, refusal(v))
	}
	return dbproxy.Caller{Agent: id.Principal()}, nil
}

// check decides database.auth for id on e: the proxy's connect or the tool's
// query. Approvals are waited for.
func (ds *databases) check(ctx context.Context, id identity.Identity, e *dbEntry, method, tool string) gate.Verdict {
	req := policy.Request{Agent: id.PolicyAgent(), Action: policy.ActionDatabase, Host: e.DB.Host(), Method: method,
		Path: "/" + e.DB.Name, Tool: tool, Command: string(e.DB.Kind)}
	if e.PasswordRef.Kind() == config.RefStore {
		if ref, err := stores.ParseRef(string(e.PasswordRef)); err == nil {
			req.Ref = ref
		}
	}
	return ds.d.app.PolicyParts.Gate.Check(ctx, req, gate.Options{Wait: true,
		Attrs: map[string]string{"database": e.DB.Name, "identity": string(id.Source)}})
}

func refusal(v gate.Verdict) string {
	why := "denied by policy"
	if v.Rule != "" {
		why += " (" + v.Rule + ")"
	}
	if v.Reason != "" && !strings.Contains(v.Reason, "\n") {
		why += ": " + v.Reason
	}
	return why
}

// List implements localapi.Databases.
func (ds *databases) List(context.Context, identity.Identity) (localapi.DatabaseListOutput, error) {
	out := localapi.DatabaseListOutput{Databases: []localapi.DatabaseInfo{}}
	for _, n := range ds.order {
		e := ds.specs[n]
		out.Databases = append(out.Databases, localapi.DatabaseInfo{Name: n, Kind: string(e.DB.Kind), Host: e.DB.Host(),
			Listen: e.listen, Tool: e.Tool})
	}
	return out, nil
}

// Query implements localapi.Databases: policy for the database, then the
// statement through the proxy with placeholders bound as parameters, then
// the result through the data plane's redactor and guard.
func (ds *databases) Query(ctx context.Context, id identity.Identity, in localapi.DatabaseQueryInput) (localapi.DatabaseQueryOutput, error) {
	e := ds.specs[in.Database]
	if e == nil || !e.Tool {
		return localapi.DatabaseQueryOutput{}, agenttools.Errorf(agenttools.CodeNotFound, "no database %q is configured for the database tool", in.Database)
	}
	if v := ds.check(ctx, id, e, "query", localapi.ToolDatabaseQuery); !v.Allowed() {
		return localapi.DatabaseQueryOutput{}, agenttools.Errorf(agenttools.CodeDenied, "database %s: %s", in.Database, refusal(v))
	}
	res, err := dbproxy.Query(ctx, e.proxy, dbproxy.Caller{Agent: id.Principal()},
		dbproxy.QueryInput{SQL: in.SQL, Params: in.Params, MaxRows: in.MaxRows}, e.Limits, ds.substitute(id))
	if err != nil {
		return localapi.DatabaseQueryOutput{}, ds.publicError(ctx, in.Database, err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return localapi.DatabaseQueryOutput{}, agenttools.Errorf(agenttools.CodeInternal, "encoding the result failed")
	}
	red, err := ds.d.redact(ctx, raw)
	secret.WipeBytes(raw)
	if err != nil {
		return localapi.DatabaseQueryOutput{}, agenttools.Errorf(agenttools.CodeUnavailable, "scrim could not redact the result; it is withheld")
	}
	var clean dbproxy.Result
	if err := json.Unmarshal(red.Text, &clean); err != nil {
		return localapi.DatabaseQueryOutput{}, agenttools.Errorf(agenttools.CodeUnavailable, "the redacted result is not valid; it is withheld")
	}
	return localapi.DatabaseQueryOutput{Database: in.Database, Columns: clean.Columns, Rows: clean.Rows, Truncated: clean.Truncated,
		Replacements: red.Replacements}, nil
}

// publicError maps a tool failure for the agent. A database error is about
// the agent's own statement but may quote a bound value (PostgreSQL names
// the input it could not parse), so its text goes through the redactor too.
func (ds *databases) publicError(ctx context.Context, name string, err error) error {
	var re *dbproxy.RefusedError
	if errors.As(err, &re) {
		return agenttools.Errorf(agenttools.CodeForbidden, "database %s: %s", name, re.Reason)
	}
	var qe *dbproxy.QueryError
	if errors.As(err, &qe) {
		red, rerr := ds.d.redact(ctx, []byte(qe.Error()))
		if rerr != nil {
			return agenttools.Errorf(agenttools.CodeInvalid, "database %s: the statement failed (the error text could not be redacted and is withheld)", name)
		}
		return agenttools.Errorf(agenttools.CodeInvalid, "database %s: %s", name, string(red.Text))
	}
	ds.d.log.Warn("database tool failed", "database", name, "err", err)
	return agenttools.Errorf(agenttools.CodeUnavailable, "database %s: the query could not run", name)
}

// substitute resolves a placeholder for the tool: it must be the current
// placeholder of a value in the redaction set; a credential must be bound to
// the database's host and pass the injection policy for this agent, as it
// would toward an HTTP host. Display values may be bound anywhere.
func (ds *databases) substitute(id identity.Identity) dbproxy.Substitute {
	return func(ctx context.Context, db *dbproxy.Database, ph string) (secret.Value, error) {
		ref, v, ok := ds.lookup(ph)
		if !ok {
			return secret.Value{}, dbproxy.Refused("%s is not the placeholder of a secret scrim holds", ph)
		}
		bd := ds.d.builder.binding(ref)
		if bd.Class != catalog.ClassDisplay && !bd.AllowsHost(db.Host()) {
			v.Wipe()
			return secret.Value{}, dbproxy.Refused("%s is not bound to %s (add the host to its catalog entry)", ref.String(), db.Host())
		}
		verdict := ds.d.app.PolicyParts.Gate.Check(ctx, policy.Request{Agent: id.PolicyAgent(), Action: policy.ActionInject,
			Ref: ref, Name: bd.Name, SecretClass: string(bd.Class), Host: db.Host(), Method: "query", Path: "/" + db.Name,
			Tool: localapi.ToolDatabaseQuery, Command: string(db.Kind)},
			gate.Options{Wait: true, Attrs: map[string]string{"database": db.Name}})
		if !verdict.Allowed() {
			v.Wipe()
			return secret.Value{}, dbproxy.Refused("%s may not be used here: %s", ref.String(), refusal(verdict))
		}
		return v, nil
	}
}

// lookup finds the value whose current placeholder is ph and returns a copy.
func (ds *databases) lookup(ph string) (stores.Ref, secret.Value, bool) {
	var (
		ref   stores.Ref
		out   secret.Value
		found bool
	)
	for _, src := range ds.d.builder.Values {
		src.EachValue(func(s refresh.Source, v secret.Value) {
			if found || s.Retained || s.Pending || s.Ref.IsZero() {
				return
			}
			if p, err := ds.d.builder.Placeholder(s.Ref, v); err == nil && p == ph {
				_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
				ref, found = s.Ref, true
			}
		})
	}
	return ref, out, found
}

// databasePasswords puts every configured database password in the
// redaction set. They carry no reference: redacted, never injected.
type databasePasswords struct{ cfg func() *config.Config }

func (databasePasswords) Store() string { return "scrim-databases" }

func (p databasePasswords) EachValue(fn func(refresh.Source, secret.Value)) {
	cfg := p.cfg()
	if cfg == nil {
		return
	}
	for _, inst := range dbproxy.Databases.Get(cfg) {
		if v, ok := cfg.SecretAt(inst.Key(dbproxy.CollectionKey, "password")); ok && !v.IsZero() {
			fn(refresh.Source{}, v)
		}
	}
}
