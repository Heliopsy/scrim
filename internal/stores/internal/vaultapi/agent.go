// SPDX-License-Identifier: AGPL-3.0-only

package vaultapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/agentcache"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// AgentLogins caches the tokens an agent's own identity logged in with:
// Kubernetes passthrough by the hash of the service account token, role
// and mount (the kubelet rotates the token, and a new one is a new login),
// JWT federation by the agent identity and options, until two thirds of the
// login's lease have passed. A session's federated logins are dropped when
// it ends.
type AgentLogins struct {
	logins *agentcache.Cache[secret.Value]
}

// NewAgentLogins returns an empty cache.
func NewAgentLogins() *AgentLogins {
	return &AgentLogins{logins: agentcache.New(CopyValue, secret.Value.Wipe)}
}

// ForgetSession drops the logins made for a scrim session.
func (l *AgentLogins) ForgetSession(id string) { l.logins.ForgetSession(id) }

// Close wipes every cached login.
func (l *AgentLogins) Close() { l.logins.Close() }

// FederationMethods are the identity.store-login methods Vault and OpenBao
// take: Kubernetes passthrough and JWT token exchange.
var FederationMethods = []string{stores.LoginKubernetes, stores.FederationJWT}

// AgentCan asks the store, with the agent's own token, for that token's
// capabilities on capPath (sys/capabilities-self): read for OpRead, create
// or update for OpWrite. The value is never read with the agent's token.
// The token is cred's static token, or a login: Kubernetes auth with the
// pod's service account token, or JWT auth with an identity token scrim's
// issuer signs for the agent.
func (c *Client) AgentCan(ctx context.Context, l *AgentLogins, cred stores.AgentCredential, op stores.Op, ref stores.Ref, capPath string) error {
	r := Request{Op: op, Ref: ref}
	tok := cred.Token
	if tok.IsZero() {
		var err error
		if tok, err = c.agentToken(ctx, l, op, ref, cred); err != nil {
			return err
		}
		defer tok.Wipe()
	}
	buf, err := wire.AppendJSON([]byte(`{"paths":[`), capPath)
	if err != nil {
		return c.StoreErr(r, stores.ErrInvalidRef, "cannot encode the path", nil)
	}
	resp, err := c.Do(ctx, Request{
		Op: op, Ref: ref, Method: http.MethodPost, Path: "sys/capabilities-self",
		Body: wire.NewBody(append(buf, "]}"...)), Token: tok, Involved: []secret.Value{tok},
	})
	defer resp.Wipe()
	if err != nil {
		return err
	}
	var cr map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body, &cr); err != nil {
		return c.StoreErr(r, stores.ErrUnavailable, "capabilities answer is not valid JSON", nil)
	}
	var caps []string
	if raw, ok := cr[capPath]; ok {
		_ = json.Unmarshal(raw, &caps)
	} else if raw, ok := cr["capabilities"]; ok {
		_ = json.Unmarshal(raw, &caps)
	}
	need := []string{"read"}
	if op == stores.OpWrite {
		need = []string{"create", "update"}
	}
	if slices.Contains(caps, "root") || slices.ContainsFunc(need, func(c string) bool { return slices.Contains(caps, c) }) {
		return nil
	}
	return c.StoreErr(r, stores.ErrPermission, "the agent's own identity may not "+string(op)+" this path", nil)
}

// agentToken returns a copy of the agent's login token, logging in when
// none is cached. The caller wipes it.
func (c *Client) agentToken(ctx context.Context, l *AgentLogins, op stores.Op, ref stores.Ref, cred stores.AgentCredential) (secret.Value, error) {
	r := Request{Op: op, Ref: ref}
	var key, session, mount, role string
	switch {
	case cred.Federation != nil:
		f := cred.Federation
		if f.Method != stores.FederationJWT {
			return secret.Value{}, c.StoreErr(r, stores.ErrUnsupported, "token exchange method "+f.Method+" is not one this store takes (jwt)", nil)
		}
		mount, role = strings.Trim(f.Param("mount", "jwt"), "/"), f.Params["role"]
		if role == "" || f.Token == nil {
			return secret.Value{}, c.StoreErr(r, stores.ErrPermission, "no agent credential", nil)
		}
		key, session = "jwt\x00"+f.Key, f.Session
	case !cred.KubernetesJWT.IsZero() && cred.Role != "":
		mount, role = cred.Mount, cred.Role
		if mount == "" {
			mount = DefaultK8sMount
		}
		h := sha256.New()
		_ = cred.KubernetesJWT.Expose(func(b []byte) error { h.Write(b); return nil })
		key = "kubernetes\x00" + string(h.Sum(nil)) + "\x00" + role + "\x00" + mount
	default:
		return secret.Value{}, c.StoreErr(r, stores.ErrPermission, "no agent credential", nil)
	}
	if t, ok := l.logins.Get(key); ok {
		return t, nil
	}
	var (
		tok secret.Value
		ttl time.Duration
		err error
	)
	if cred.Federation != nil {
		jwt, merr := cred.Federation.Token()
		if merr != nil {
			return secret.Value{}, c.StoreErr(r, stores.ErrPermission, "no identity token for the agent", merr)
		}
		tok, ttl, _, err = c.LoginJWT(ctx, op, ref, mount, role, jwt)
		jwt.Wipe()
	} else {
		tok, ttl, _, err = c.LoginKubernetes(ctx, op, ref, mount, role, cred.KubernetesJWT)
	}
	if err != nil {
		return secret.Value{}, err
	}
	l.logins.Put(key, session, tok, ttl)
	return CopyValue(tok), nil
}
