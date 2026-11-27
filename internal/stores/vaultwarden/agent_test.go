// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func randUUID(t *testing.T) string {
	h := randHex(t, 16)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// fakeAgent is one agent account on the fake server.
type fakeAgent struct {
	secret string
	// items maps a cipher id to the account's (edit, viewPassword) on it;
	// an id it lacks is not accessible to the account.
	items map[string][2]bool
	// orgs are the account's memberships (id -> status), collections its
	// collections (id -> readOnly), all in organisation o1.
	orgs        map[string]int
	collections map[string]bool
}

// agentFake is a Bitwarden API fake serving scrim's revision date and the
// endpoints an agent check uses: the client_credentials login, GET
// /api/ciphers/{id} and GET /api/sync. Fidelity limits: it answers an
// inaccessible item with Vaultwarden's 400 "Cipher is not owned by user"
// (Bitwarden answers 404), puts the account's permission on the item into
// edit and viewPassword the way Vaultwarden's Cipher::to_json does, and
// returns a cipher body carrying cipherValue as its password so a leak of
// the body would show. Its sync holds only the profile memberships and the
// collections with readOnly, plus that cipher.
type agentFake struct {
	t           *testing.T
	srv         *httptest.Server
	scrimToken  string
	cipherValue string

	mu       sync.Mutex
	agents   map[string]*fakeAgent // client_id -> agent
	tokens   map[string]string     // access token -> client_id
	logins   map[string]int        // client_id -> logins
	devices  map[string][]string   // client_id -> device identifiers used
	expires  int
	reject   bool // answer every agent request with 401
	requests []string
}

func newAgentFake(t *testing.T) *agentFake {
	f := &agentFake{
		t: t, scrimToken: "scrim-" + randHex(t, 8), cipherValue: "value-" + randHex(t, 12),
		agents: map[string]*fakeAgent{}, tokens: map[string]string{}, logins: map[string]int{},
		devices: map[string][]string{}, expires: 3600,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *agentFake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.String()+" "+r.Header.Get("Authorization")+" "+string(body))
	w.Header().Set("Content-Type", "application/json")
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
	}
	if r.URL.Path == "/identity/connect/token" {
		form, _ := url.ParseQuery(string(body))
		id := form.Get("client_id")
		ag, ok := f.agents[id]
		if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "api" || !ok || form.Get("client_secret") != ag.secret {
			w.WriteHeader(http.StatusBadRequest)
			// Some servers echo the request: the adapter must not pass it on.
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "bad secret " + form.Get("client_secret")})
			return
		}
		f.logins[id]++
		f.devices[id] = append(f.devices[id], form.Get("deviceIdentifier"))
		tok := "agent-tok-" + randHex(f.t, 12)
		f.tokens[tok] = id
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "expires_in": f.expires, "token_type": "Bearer",
			"Key": "2.encrypted|key|mac", "PrivateKey": "2.encrypted|pk|mac"})
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == f.scrimToken {
		if r.URL.Path == "/api/accounts/revision-date" {
			_, _ = w.Write([]byte("1"))
			return
		}
		fail(http.StatusNotFound, "not served to scrim")
		return
	}
	id, ok := f.tokens[bearer]
	if !ok || f.reject {
		fail(http.StatusUnauthorized, "invalid token")
		return
	}
	ag := f.agents[id]
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/ciphers/"):
		cid := strings.TrimPrefix(r.URL.Path, "/api/ciphers/")
		p, ok := ag.items[cid]
		if !ok {
			fail(http.StatusBadRequest, "Cipher is not owned by user")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": cid, "type": 1, "edit": p[0], "viewPassword": p[1],
			"login": map[string]any{"password": f.cipherValue}})
	case r.URL.Path == "/api/sync":
		var orgs []map[string]any
		for o, st := range ag.orgs {
			orgs = append(orgs, map[string]any{"id": o, "status": st, "key": "4.wrapped"})
		}
		var colls []map[string]any
		for c, ro := range ag.collections {
			colls = append(colls, map[string]any{"id": c, "organizationId": "o1", "readOnly": ro, "hidePasswords": false})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"profile": map[string]any{"id": id, "organizations": orgs},
			"collections": colls, "ciphers": []any{map[string]any{"id": "x", "login": map[string]any{"password": f.cipherValue}}}})
	default:
		fail(http.StatusNotFound, "no route")
	}
}

func (f *agentFake) addAgent(t *testing.T, a *fakeAgent) (clientID string, cred secret.Value) {
	clientID = "user." + randUUID(t)
	a.secret = "cs-" + randHex(t, 16)
	f.mu.Lock()
	f.agents[clientID] = a
	f.mu.Unlock()
	return clientID, agentCred(clientID, a.secret)
}

func agentCred(clientID, cs string) secret.Value {
	b, _ := json.Marshal(map[string]string{"client_id": clientID, "client_secret": cs})
	return secret.Adopt(b)
}

func (f *agentFake) loginCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins[id]
}

// newAgentAdapter returns an adapter against f, already logged in and
// unlocked with a vault of: "Shared/Team A/DB" (c-team) in collection k2,
// "Prod/API" (c-prod) in collection k1 of organisation o1 (Acme), and the
// personal item "Agents/CI/Mine" (c-mine).
func newAgentAdapter(t *testing.T, f *agentFake) *Adapter {
	t.Helper()
	lf := newLabelFixture(t)
	ok := lf.org
	o1 := "o1"
	lf.sync.Ciphers = append(lf.sync.Ciphers,
		cipherJSON{ID: "c-team", Type: cipherLogin, Name: *lf.enc(t, ok, "DB"), OrganizationID: &o1, CollectionIDs: []string{"k2"}, Login: &loginJSON{}},
		cipherJSON{ID: "c-prod", Type: cipherLogin, Name: *lf.enc(t, ok, "API"), OrganizationID: &o1, CollectionIDs: []string{"k1"}, Login: &loginJSON{}},
		cipherJSON{ID: "c-mine", Type: cipherLogin, Name: *lf.enc(t, lf.keys.user, "Mine"), FolderID: ptr("f1"), Login: &loginJSON{}},
	)
	u, _ := url.Parse(f.srv.URL)
	a, err := New("vw", Options{URL: u, ClientID: "user.scrim", ClientSecret: "file:/nonexistent", Unlock: "file:/nonexistent"},
		func(_ context.Context, _ config.SecretRef) (secret.Value, error) {
			return secret.Value{}, errors.New("not used")
		})
	if err != nil {
		t.Fatal(err)
	}
	a.sess = &session{token: secret.FromString(f.scrimToken), expires: time.Now().Add(time.Hour)}
	a.keys = lf.keys
	a.v = buildVault(lf.sync, lf.keys, 1, nil, false)
	if len(a.v.warnings) != 0 {
		t.Fatalf("fixture warnings: %v", a.v.warnings)
	}
	return a
}

// TestAgentCan: an agent's own account decides through the server, as the
// agent: edit and viewPassword on an existing item, collection readOnly for
// a new one; a personal item is never an agent's; logins are cached per
// agent and credential, re-made once after a 401, and wiped on Lock and
// Close; neither the agent's secret nor a value ends up in an error.
func TestAgentCan(t *testing.T) {
	f := newAgentFake(t)
	// The server shows agent a scrim's personal item too, as it would if
	// a's key were scrim's own: the adapter must still refuse it.
	idA, credA := f.addAgent(t, &fakeAgent{
		items: map[string][2]bool{"c-team": {true, true}, "c-mine": {true, true}},
		orgs:  map[string]int{"o1": memberConfirmed}, collections: map[string]bool{"k2": false},
	})
	idB, credB := f.addAgent(t, &fakeAgent{
		items: map[string][2]bool{"c-team": {false, false}},
		orgs:  map[string]int{"o1": memberConfirmed}, collections: map[string]bool{"k2": true},
	})
	a := newAgentAdapter(t, f)
	defer func() { _ = a.Close() }()
	ctx := t.Context()
	ag := func(name string, tok secret.Value) stores.AgentCredential {
		return stores.AgentCredential{Agent: name, Token: tok}
	}
	ref := stores.MustParseRef
	var errs []error
	want := func(err, kind error, what string) {
		t.Helper()
		if kind == nil && err != nil || kind != nil && !errors.Is(err, kind) {
			t.Fatalf("%s: got %v, want %v", what, err, kind)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}

	team, prod := ref("vw://Shared/Team A/DB#password"), ref("vw://Prod/API")
	newTeam := ref("vw://Shared/Team A/New?org=Acme")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpRead, team), nil, "a reads team")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpWrite, team), nil, "a writes team")
	want(a.AgentCan(ctx, ag("b", credB), stores.OpRead, team), stores.ErrPermission, "b reads team (passwords hidden)")
	want(a.AgentCan(ctx, ag("b", credB), stores.OpWrite, team), stores.ErrPermission, "b writes team (read-only)")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpRead, prod), stores.ErrPermission, "a reads prod")
	want(a.AgentCan(ctx, ag("b", credB), stores.OpWrite, prod), stores.ErrPermission, "b writes prod")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpWrite, newTeam), nil, "a creates in team")
	want(a.AgentCan(ctx, ag("b", credB), stores.OpWrite, newTeam), stores.ErrPermission, "b creates in team")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpWrite, ref("vw://Prod/New?org=o1")), stores.ErrPermission, "a creates in prod")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpWrite, ref("vw://Shared/Team A/New")), stores.ErrPermission, "a creates without org")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpRead, ref("vw://Agents/CI/Mine")), stores.ErrPermission, "a reads scrim's personal item")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpWrite, ref("vw://Agents/CI/Mine")), stores.ErrPermission, "a writes scrim's personal item")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpRead, ref("vw://Shared/Team A/Missing")), stores.ErrNotFound, "a reads a missing item")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpWrite, ref("vw://Nowhere/New?org=Acme")), stores.ErrNotFound, "a creates in a missing collection")
	want(a.AgentCan(ctx, ag("a", credA), stores.OpList, team), stores.ErrUnsupported, "list")

	// One login per agent, each on its own stable device.
	if f.loginCount(idA) != 1 || f.loginCount(idB) != 1 {
		t.Fatalf("logins a=%d b=%d, want one each (cached)", f.loginCount(idA), f.loginCount(idB))
	}
	if a.agents.Len() != 2 {
		t.Fatalf("cache holds %d logins, want 2", a.agents.Len())
	}
	f.mu.Lock()
	devA, devB := f.devices[idA][0], f.devices[idB][0]
	f.mu.Unlock()
	if devA != a.opts.agentDeviceID("vw", "a") || devA == devB || devA == a.cl.deviceID {
		t.Fatalf("device identifiers a=%s b=%s scrim=%s: want one stable per agent", devA, devB, a.cl.deviceID)
	}

	// A member that is not confirmed may not add items.
	f.mu.Lock()
	f.agents[idA].orgs["o1"] = 1
	f.mu.Unlock()
	want(a.AgentCan(ctx, ag("a", credA), stores.OpWrite, newTeam), stores.ErrPermission, "a creates while only accepted")
	f.mu.Lock()
	f.agents[idA].orgs["o1"] = memberConfirmed
	f.mu.Unlock()

	// The server revokes the cached token: dropped, logged in once more.
	f.mu.Lock()
	clear(f.tokens)
	f.mu.Unlock()
	want(a.AgentCan(ctx, ag("a", credA), stores.OpRead, team), nil, "a reads after its token was revoked")
	if n := f.loginCount(idA); n != 2 {
		t.Fatalf("logins after a 401: %d, want 2", n)
	}
	// Every token refused: one retry, then a permission error.
	f.mu.Lock()
	f.reject = true
	f.mu.Unlock()
	want(a.AgentCan(ctx, ag("a", credA), stores.OpRead, team), stores.ErrPermission, "a reads while the server refuses its tokens")
	if n := f.loginCount(idA); n != 3 {
		t.Fatalf("logins after a refused retry: %d, want 3", n)
	}
	f.mu.Lock()
	f.reject = false
	f.mu.Unlock()

	// A key rotated under the same client_id reuses the cached login.
	f.mu.Lock()
	oldSecretA := f.agents[idA].secret
	f.agents[idA].secret = "cs-" + randHex(t, 16)
	rotated := agentCred(idA, f.agents[idA].secret)
	f.mu.Unlock()
	want(a.AgentCan(ctx, ag("a", rotated), stores.OpRead, team), nil, "a reads with a rotated key")
	if n := f.loginCount(idA); n != 3 {
		t.Fatalf("logins after rotation: %d, want 3 (the cached login)", n)
	}
	// The old key is now refused by the server; its error must not echo it.
	want(a.AgentCan(ctx, ag("a2", credA), stores.OpRead, team), stores.ErrPermission, "a with the revoked key")

	// Credentials the store does not take.
	want(a.AgentCan(ctx, stores.AgentCredential{Agent: "c"}, stores.OpRead, team), stores.ErrPermission, "no credential")
	want(a.AgentCan(ctx, stores.AgentCredential{Agent: "c", KubernetesJWT: secret.FromString("eyJ." + randHex(t, 8))}, stores.OpRead, team), stores.ErrUnsupported, "kubernetes")
	want(a.AgentCan(ctx, stores.AgentCredential{Agent: "c", Federation: &stores.Federation{Method: stores.FederationJWT}}, stores.OpRead, team), stores.ErrUnsupported, "federation")
	badSecret := "bad-" + randHex(t, 12)
	for name, raw := range map[string]string{
		"plain secret":    badSecret,
		"org key":         `{"client_id":"organization.` + randUUID(t) + `","client_secret":"` + badSecret + `"}`,
		"no uuid":         `{"client_id":"user.x","client_secret":"` + badSecret + `"}`,
		"extra field":     `{"client_id":"` + idA + `","client_secret":"` + badSecret + `","password":"` + badSecret + `"}`,
		"number secret":   `{"client_id":"` + idA + `","client_secret":12345` + `}`,
		"empty secret":    `{"client_id":"` + idA + `","client_secret":""}`,
		"truncated JSON":  `{"client_id":"` + idA + `","client_secret":"` + badSecret,
		"array":           `["` + idA + `","` + badSecret + `"]`,
		"missing secret":  `{"client_id":"` + idA + `","client_sec":"` + badSecret + `"}`,
		"non-string id":   `{"client_id":7,"client_secret":"` + badSecret + `"}`,
		"escaped id junk": `{"client_id":"user.\u0000","client_secret":"` + badSecret + `"}`,
	} {
		err := a.AgentCan(ctx, ag("c", secret.FromString(raw)), stores.OpRead, team)
		if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "client_id") {
			t.Fatalf("%s: got %v, want a permission error naming the format", name, err)
		}
		errs = append(errs, err)
	}
	if n := f.loginCount(idA); n != 3 {
		t.Fatalf("a malformed credential logged in (%d logins)", n)
	}

	// Nothing secret in any error; the value and the secrets never went
	// anywhere they should not.
	f.mu.Lock()
	secrets := []string{oldSecretA, f.agents[idA].secret, f.agents[idB].secret, badSecret, f.cipherValue}
	for _, e := range errs {
		for _, s := range secrets {
			if strings.Contains(e.Error(), s) {
				t.Fatalf("error %q holds a secret", e)
			}
		}
		for tok := range f.tokens {
			if strings.Contains(e.Error(), tok) {
				t.Fatalf("error %q holds an access token", e)
			}
		}
	}
	for _, r := range f.requests {
		if strings.Contains(r, f.cipherValue) || strings.Contains(r, badSecret) {
			t.Fatalf("request %q carries a value", r)
		}
		if strings.Contains(r, f.agents[idB].secret) && !strings.HasPrefix(r, "POST /identity/connect/token") {
			t.Fatalf("an agent's API key secret went to %q", r)
		}
	}
	f.mu.Unlock()

	// Static logins are not tied to a session; Lock and Close wipe them.
	a.ForgetSession("s1")
	if a.agents.Len() == 0 {
		t.Fatal("ForgetSession dropped static agent logins")
	}
	a.Lock()
	if a.agents.Len() != 0 {
		t.Fatalf("Lock left %d agent logins", a.agents.Len())
	}
	a.agents.Put("agent", "", secret.FromString("tok-"+randHex(t, 8)), time.Hour)
	_ = a.Close()
	if a.agents.Len() != 0 {
		t.Fatalf("Close left %d agent logins", a.agents.Len())
	}
}

// TestAgentCanCacheExpiry: a login is reused until two thirds of its
// expires_in, then made again.
func TestAgentCanCacheExpiry(t *testing.T) {
	f := newAgentFake(t)
	id, cred := f.addAgent(t, &fakeAgent{items: map[string][2]bool{"c-team": {true, true}}})
	a := newAgentAdapter(t, f)
	defer func() { _ = a.Close() }()
	now := time.Now()
	a.agents.SetNow(func() time.Time { return now })
	team := stores.MustParseRef("vw://Shared/Team A/DB")
	c := stores.AgentCredential{Agent: "a", Token: cred}
	for range 3 {
		if err := a.AgentCan(t.Context(), c, stores.OpRead, team); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.loginCount(id); n != 1 {
		t.Fatalf("logins %d, want 1", n)
	}
	now = now.Add(41 * time.Minute)
	if err := a.AgentCan(t.Context(), c, stores.OpRead, team); err != nil {
		t.Fatal(err)
	}
	if n := f.loginCount(id); n != 2 {
		t.Fatalf("logins after expiry %d, want 2", n)
	}
}
