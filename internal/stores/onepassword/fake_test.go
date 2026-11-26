// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an in-memory 1Password Connect server speaking the part of the
// Connect API v1 the adapter uses, built from the Connect OpenAPI document
// (1.8.1) and the item shapes in testdata.
//
// What it reproduces: the endpoints, the bearer token check (401
// {"status","message"}), vault scope (403), unknown vault and item (404),
// further access tokens of the same server (op connect token create), each
// with its own vaults and read and write bits enforced on every endpoint:
// vaults outside the token are not listed, and a vault without the bit the
// method needs (r for GET, w otherwise) answers 403 "vault <id> is not in
// scope" whether or not it exists,
// SCIM "name eq" and "title eq" filters with JSON string escapes, item
// summaries without sections, fields or files, full items with them,
// server-assigned IDs, versions and timestamps, create (POST) and replace
// (PUT) with the category check, delete (204), the plain-text heartbeat and
// the health document.
//
// What it does not (fidelity limits, docs/stores/onepassword.md): Connect's
// exact 400 messages, the status Connect really answers for a vault outside
// a token on the item listing (the OpenAPI document gives 403 "not in
// scope" for the other vault endpoints but only 401 and 404 for that one;
// scopeStatus switches the fake to 404), token expiry and revocation (an
// unknown token is a 401), rate limits, the sync delay between Connect and
// 1Password.com, case or Unicode folding in filters, field types Connect
// may coerce or values it may normalise, the template fields 1Password may
// add to a new item of a category, and PATCH, which the adapter does not use.
type fake struct {
	t     *testing.T
	srv   *httptest.Server
	token string

	mu       sync.Mutex
	down     bool
	vaults   map[string]*fakeVault
	requests []string
	// itemGets counts full item reads, the only responses holding values.
	itemGets int
	// echo makes write errors quote the request body back, and a 401 for
	// a scoped token quote the token, as a careless server might.
	echo bool
	// scopes are further Connect access tokens: token -> vault ID ->
	// permissions ("r", "w", "rw").
	scopes map[string]map[string]string
	// scopeStatus is the status a scoped token gets for a vault outside
	// its scope (403 by default).
	scopeStatus int
	// unlisted are item IDs the item listing leaves out for scoped tokens,
	// standing in for an item renamed or moved between scrim's lookup and
	// the agent's.
	unlisted map[string]bool
}

type fakeVault struct {
	ID       string
	Name     string
	Type     string
	ReadOnly bool // writes refused with 403, as for a read-only token
	Hidden   bool // not in the token's scope: listed nowhere, 403 by ID
	items    map[string]map[string]any
	order    []string
}

var uuidRe = regexp.MustCompile(`^[0-9a-z]{26}$`)

func fakeID() string { return newID() }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, token: "connect-token-" + randHex(16), vaults: map[string]*fakeVault{},
		scopes: map[string]map[string]string{}, scopeStatus: http.StatusForbidden, unlisted: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("."))
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"name": "1Password Connect API", "version": "1.8.1",
			"dependencies": []any{map[string]any{"service": "sync", "status": "ACTIVE"}, map[string]any{"service": "sqlite", "status": "ACTIVE"}}})
	})
	mux.HandleFunc("GET /v1/vaults", f.auth(f.listVaults))
	mux.HandleFunc("GET /v1/vaults/{vault}", f.auth(f.getVault))
	mux.HandleFunc("GET /v1/vaults/{vault}/items", f.auth(f.listItems))
	mux.HandleFunc("POST /v1/vaults/{vault}/items", f.auth(f.createItem))
	mux.HandleFunc("GET /v1/vaults/{vault}/items/{item}", f.auth(f.getItem))
	mux.HandleFunc("PUT /v1/vaults/{vault}/items/{item}", f.auth(f.putItem))
	mux.HandleFunc("DELETE /v1/vaults/{vault}/items/{item}", f.auth(f.deleteItem))
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		down := f.down
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if down {
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					_ = c.Close()
					return
				}
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) addVault(name string) *fakeVault {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := &fakeVault{ID: fakeID(), Name: name, Type: "USER_CREATED", items: map[string]map[string]any{}}
	f.vaults[v.ID] = v
	return v
}

// addToken issues a further access token for the vaults in scope (vault ID
// -> "r", "w" or "rw") and returns it.
func (f *fake) addToken(scope map[string]string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	tok := "agent-connect-token-" + randHex(16)
	f.scopes[tok] = maps.Clone(scope)
	return tok
}

func (f *fake) setDown(d bool) {
	f.mu.Lock()
	f.down = d
	f.mu.Unlock()
}

func (f *fake) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fake) gets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.itemGets
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"status": status, "message": msg})
}

// scopeKey carries a scoped token's vault permissions in the request
// context; scrim's own token has none (every vault but Hidden ones).
type scopeKey struct{}

func scopeOf(r *http.Request) map[string]string {
	s, _ := r.Context().Value(scopeKey{}).(map[string]string)
	return s
}

func (f *fake) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		hdr := r.Header.Get("Authorization")
		if hdr != "Bearer "+f.token {
			tok, ok := strings.CutPrefix(hdr, "Bearer ")
			scope, known := f.scopes[tok]
			if !ok || !known {
				msg := "Invalid token signature"
				if f.echo {
					msg += ": " + tok
				}
				apiErr(w, 401, msg)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), scopeKey{}, scope))
		}
		h(w, r)
	}
}

// parseEq parses a SCIM `<attr> eq "<value>"` filter.
func parseEq(filter, attr string) (string, bool) {
	rest, ok := strings.CutPrefix(filter, attr+" eq ")
	if !ok {
		return "", false
	}
	var v string
	if err := json.Unmarshal([]byte(rest), &v); err != nil {
		return "", false
	}
	return v, true
}

func vaultJSON(v *fakeVault) map[string]any {
	return map[string]any{"id": v.ID, "name": v.Name, "type": v.Type, "items": len(v.items),
		"attributeVersion": 1, "contentVersion": len(v.items) + 1,
		"createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"}
}

func (f *fake) listVaults(w http.ResponseWriter, r *http.Request) {
	name, filtered := "", false
	if q := r.URL.Query().Get("filter"); q != "" {
		var ok bool
		if name, ok = parseEq(q, "name"); !ok {
			apiErr(w, 400, "Invalid filter")
			return
		}
		filtered = true
	}
	out := []any{}
	for _, id := range slices.Sorted(maps.Keys(f.vaults)) {
		v := f.vaults[id]
		if sc := scopeOf(r); sc != nil && sc[v.ID] == "" {
			continue
		}
		if v.Hidden || (filtered && v.Name != name) {
			continue
		}
		out = append(out, vaultJSON(v))
	}
	writeJSON(w, 200, out)
}

// vault resolves the path's vault ID, answering the error itself.
func (f *fake) vault(w http.ResponseWriter, r *http.Request) *fakeVault {
	id := r.PathValue("vault")
	if !uuidRe.MatchString(id) {
		apiErr(w, 400, "Invalid Vault UUID")
		return nil
	}
	if sc := scopeOf(r); sc != nil {
		need := "w"
		if r.Method == http.MethodGet {
			need = "r"
		}
		if !strings.Contains(sc[id], need) {
			if f.scopeStatus == http.StatusNotFound {
				apiErr(w, 404, "vault "+id+" not found")
			} else {
				apiErr(w, f.scopeStatus, "vault "+id+" is not in scope")
			}
			return nil
		}
	}
	v, ok := f.vaults[id]
	if !ok {
		apiErr(w, 404, "vault "+id+" not found")
		return nil
	}
	if v.Hidden {
		apiErr(w, 403, "vault "+id+" is not in scope")
		return nil
	}
	return v
}

func (f *fake) getVault(w http.ResponseWriter, r *http.Request) {
	if v := f.vault(w, r); v != nil {
		writeJSON(w, 200, vaultJSON(v))
	}
}

// summary is an item without sections, fields and files, as the item
// listing returns it.
func summary(it map[string]any) map[string]any {
	s := maps.Clone(it)
	delete(s, "sections")
	delete(s, "fields")
	delete(s, "files")
	return s
}

func (f *fake) listItems(w http.ResponseWriter, r *http.Request) {
	v := f.vault(w, r)
	if v == nil {
		return
	}
	title, filtered := "", false
	if q := r.URL.Query().Get("filter"); q != "" {
		var ok bool
		if title, ok = parseEq(q, "title"); !ok {
			apiErr(w, 400, "Invalid filter")
			return
		}
		filtered = true
	}
	out := []any{}
	for _, id := range v.order {
		it, ok := v.items[id]
		if !ok || (filtered && it["title"] != title) || (scopeOf(r) != nil && f.unlisted[id]) {
			continue
		}
		out = append(out, summary(it))
	}
	writeJSON(w, 200, out)
}

func (f *fake) item(w http.ResponseWriter, r *http.Request, v *fakeVault) map[string]any {
	id := r.PathValue("item")
	if !uuidRe.MatchString(id) {
		apiErr(w, 400, "Invalid Item UUID")
		return nil
	}
	it, ok := v.items[id]
	if !ok {
		apiErr(w, 404, "item "+id+" not found")
		return nil
	}
	return it
}

func (f *fake) getItem(w http.ResponseWriter, r *http.Request) {
	v := f.vault(w, r)
	if v == nil {
		return
	}
	if it := f.item(w, r, v); it != nil {
		f.itemGets++
		writeJSON(w, 200, it)
	}
}

var categories = append(slices.Clone(writableCategories), "DOCUMENT")

// validate checks an item the way Connect does where it matters to the
// adapter, and fills in server-side attributes. It returns a message for a
// 400 or "".
func validate(it map[string]any) string {
	cat, _ := it["category"].(string)
	if !slices.Contains(categories, cat) {
		return "Invalid item category"
	}
	secs := map[string]bool{}
	if ss, ok := it["sections"].([]any); ok {
		for _, s := range ss {
			m, _ := s.(map[string]any)
			id, _ := m["id"].(string)
			if id == "" {
				return "section is missing an id"
			}
			secs[id] = true
		}
	}
	if fs, ok := it["fields"].([]any); ok {
		for _, x := range fs {
			m, _ := x.(map[string]any)
			if m == nil {
				return "invalid field"
			}
			if id, _ := m["id"].(string); id == "" {
				m["id"] = fakeID()
			}
			if _, ok := m["type"]; !ok {
				m["type"] = "STRING"
			}
			if _, ok := m["value"]; ok {
				if _, isString := m["value"].(string); !isString {
					return "field value must be a string"
				}
			}
			if sec, ok := m["section"].(map[string]any); ok {
				if id, _ := sec["id"].(string); !secs[id] {
					return "section " + id + " does not exist"
				}
			}
		}
	}
	return ""
}

func (f *fake) decodeItem(w http.ResponseWriter, r *http.Request) map[string]any {
	var it map[string]any
	if err := json.NewDecoder(r.Body).Decode(&it); err != nil {
		apiErr(w, 400, "Unable to parse item")
		return nil
	}
	if f.echo {
		b, _ := json.Marshal(it)
		apiErr(w, 400, "Validation failed: "+string(b))
		return nil
	}
	if msg := validate(it); msg != "" {
		apiErr(w, 400, msg)
		return nil
	}
	return it
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (f *fake) createItem(w http.ResponseWriter, r *http.Request) {
	v := f.vault(w, r)
	if v == nil {
		return
	}
	if v.ReadOnly {
		apiErr(w, 403, "vault "+v.ID+" is not in scope")
		return
	}
	it := f.decodeItem(w, r)
	if it == nil {
		return
	}
	if vid, _ := it["vault"].(map[string]any)["id"].(string); vid != "" && vid != v.ID {
		apiErr(w, 400, "item vault does not match the path")
		return
	}
	id := fakeID()
	it["id"], it["vault"], it["version"] = id, map[string]any{"id": v.ID}, 1
	it["createdAt"], it["updatedAt"], it["lastEditedBy"] = now(), now(), "SCRIMFAKEUSER0000000000000"
	v.items[id] = it
	v.order = append(v.order, id)
	writeJSON(w, 200, it)
}

func (f *fake) putItem(w http.ResponseWriter, r *http.Request) {
	v := f.vault(w, r)
	if v == nil {
		return
	}
	old := f.item(w, r, v)
	if old == nil {
		return
	}
	if v.ReadOnly {
		apiErr(w, 403, "vault "+v.ID+" is not in scope")
		return
	}
	it := f.decodeItem(w, r)
	if it == nil {
		return
	}
	if id, _ := it["id"].(string); id != "" && id != old["id"] {
		apiErr(w, 400, "item id does not match the path")
		return
	}
	ver, _ := old["version"].(int)
	if fv, ok := old["version"].(float64); ok {
		ver = int(fv)
	}
	it["id"], it["vault"], it["version"] = old["id"], map[string]any{"id": v.ID}, ver+1
	it["createdAt"], it["updatedAt"] = old["createdAt"], now()
	v.items[old["id"].(string)] = it
	writeJSON(w, 200, it)
}

func (f *fake) deleteItem(w http.ResponseWriter, r *http.Request) {
	v := f.vault(w, r)
	if v == nil {
		return
	}
	if it := f.item(w, r, v); it != nil {
		delete(v.items, it["id"].(string))
		w.WriteHeader(http.StatusNoContent)
	}
}

// put stores an item out of band (a fixture), keeping its ID if it has one.
func (f *fake) put(v *fakeVault, it map[string]any) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, _ := it["id"].(string)
	if id == "" {
		id = fakeID()
		it["id"] = id
	}
	it["vault"] = map[string]any{"id": v.ID}
	if _, ok := v.items[id]; !ok {
		v.order = append(v.order, id)
	}
	v.items[id] = it
	return id
}

// removeTitled deletes every item titled title, out of band.
func (f *fake) removeTitled(v *fakeVault, title string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, it := range v.items {
		if it["title"] == title {
			delete(v.items, id)
		}
	}
}
