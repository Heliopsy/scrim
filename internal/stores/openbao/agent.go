// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

var _ stores.AgentAccess = (*Adapter)(nil)

// agentLogins caches the tokens Kubernetes passthrough logged in with, by
// the hash of the service account token, role and mount, until shortly
// before their lease ends. A new service account token (the kubelet rotates
// them) is a new login.
type agentLogins struct {
	mu sync.Mutex
	m  map[[32]byte]agentLogin
}

type agentLogin struct {
	token secret.Value
	until time.Time
}

// maxAgentLogins bounds the cache; when full, expired logins are dropped
// and, if that is not enough, all of them.
const maxAgentLogins = 1024

func loginKey(jwt secret.Value, role, mount string) [32]byte {
	h := sha256.New()
	_ = jwt.Expose(func(b []byte) error { h.Write(b); return nil })
	h.Write([]byte{0})
	h.Write([]byte(role))
	h.Write([]byte{0})
	h.Write([]byte(mount))
	var k [32]byte
	copy(k[:], h.Sum(nil))
	return k
}

// AgentCan implements [stores.AgentAccess]: it asks OpenBao, with the
// agent's own token, for that token's capabilities on ref's KV v2 data
// path (sys/capabilities-self). The value is never read with the agent's
// token. With a Kubernetes credential it first logs in at
// auth/<mount>/login with the agent pod's service account token and the
// rendered role, so the role OpenBao binds to that service account
// decides.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	mount, rest := a.split(ref.Path)
	if rest == "" {
		return a.err(op, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	tok := cred.Token
	if tok.IsZero() {
		var err error
		if tok, err = a.agentToken(ctx, op, ref, cred); err != nil {
			return err
		}
		defer tok.Wipe()
	}
	path := mount + "/data/" + rest
	buf, err := wire.AppendJSON([]byte(`{"paths":[`), path)
	if err != nil {
		return a.err(op, ref, stores.ErrInvalidRef, "cannot encode the path")
	}
	resp, err := a.c.do(ctx, request{
		op: op, ref: ref, method: http.MethodPost, path: "sys/capabilities-self",
		body: wire.NewBody(append(buf, "]}"...)), token: tok, involved: []secret.Value{tok},
	})
	defer resp.wipe()
	if err != nil {
		return err
	}
	var cr map[string]json.RawMessage
	if err := json.Unmarshal(resp.body, &cr); err != nil {
		return a.err(op, ref, stores.ErrUnavailable, "capabilities answer is not valid JSON")
	}
	var caps []string
	if raw, ok := cr[path]; ok {
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
	return a.err(op, ref, stores.ErrPermission, "the agent's own OpenBao identity may not "+string(op)+" this path")
}

// agentToken returns a copy of the passthrough login token for cred,
// logging in when none is cached. The caller wipes it.
func (a *Adapter) agentToken(ctx context.Context, op stores.Op, ref stores.Ref, cred stores.AgentCredential) (secret.Value, error) {
	if cred.KubernetesJWT.IsZero() || cred.Role == "" {
		return secret.Value{}, a.err(op, ref, stores.ErrPermission, "no agent credential")
	}
	mount := cred.Mount
	if mount == "" {
		mount = "kubernetes"
	}
	key := loginKey(cred.KubernetesJWT, cred.Role, mount)
	now := time.Now()
	a.agents.mu.Lock()
	if l, ok := a.agents.m[key]; ok && now.Before(l.until) {
		t := copyValue(l.token)
		a.agents.mu.Unlock()
		return t, nil
	}
	a.agents.mu.Unlock()
	tok, ttl, _, err := a.c.loginKubernetes(ctx, op, ref, mount, cred.Role, cred.KubernetesJWT)
	if err != nil {
		return secret.Value{}, err
	}
	until := now.Add(ttl * 2 / 3)
	if ttl <= 0 {
		until = now.Add(time.Minute)
	}
	a.agents.mu.Lock()
	defer a.agents.mu.Unlock()
	if a.agents.m == nil {
		a.agents.m = map[[32]byte]agentLogin{}
	}
	if len(a.agents.m) >= maxAgentLogins {
		for k, l := range a.agents.m {
			if !now.Before(l.until) {
				l.token.Wipe()
				delete(a.agents.m, k)
			}
		}
		if len(a.agents.m) >= maxAgentLogins {
			a.agents.closeLocked()
		}
	}
	if old, ok := a.agents.m[key]; ok {
		old.token.Wipe()
	}
	a.agents.m[key] = agentLogin{token: tok, until: until}
	return copyValue(tok), nil
}

func (l *agentLogins) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeLocked()
}

func (l *agentLogins) closeLocked() {
	for k, v := range l.m {
		v.token.Wipe()
		delete(l.m, k)
	}
}
