// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an in-memory Infisical speaking the subset of the API the adapter
// uses, with the status codes and error envelopes observed on v0.167.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu           sync.Mutex
	clientID     string
	clientSecret string
	tokenTTL     int64
	tokens       map[string]time.Time
	logins       int
	down         bool
	projects     map[string]string // slug -> id
	folders      map[string]bool   // projectID|env|/path
	secrets      map[string]*fakeSecret
	readOnlyEnv  string // writes to this environment are denied
	lastRequests []string
	issued       []string // every access token handed out

	// Kubernetes Auth: the identity that has it, the service account
	// tokens it accepts, and every JWT presented.
	identityID string
	jwts       map[string]bool
	seenJWTs   []string
	// echoJWT makes a refused Kubernetes login quote the JWT back.
	echoJWT bool
}

type fakeSecret struct {
	key      string
	path     string
	versions []string
	created  time.Time
	updated  time.Time
	metadata []kv
}

func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newFake(t *testing.T) *fake {
	f := &fake{
		t:            t,
		clientID:     "cid-" + randID(4),
		clientSecret: "cs-" + randID(16),
		tokenTTL:     3600,
		tokens:       map[string]time.Time{},
		projects:     map[string]string{"proj": "6a1b2c3d-0000-4000-8000-" + randID(6)},
		folders:      map[string]bool{},
		secrets:      map[string]*fakeSecret{},
		readOnlyEnv:  "prod",
		identityID:   "7f3c1a2e-0000-4000-8000-" + randID(6),
		jwts:         map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"message": "Ok"})
	})
	mux.HandleFunc("POST /api/v1/auth/universal-auth/login", f.login)
	mux.HandleFunc("POST /api/v1/auth/kubernetes-auth/login", f.kubernetesLogin)
	mux.HandleFunc("GET /api/v1/projects/slug/{slug}", f.auth(f.project))
	mux.HandleFunc("GET /api/v4/secrets", f.auth(f.list))
	mux.HandleFunc("GET /api/v4/secrets/{name}", f.auth(f.get))
	mux.HandleFunc("POST /api/v4/secrets/{name}", f.auth(f.create))
	mux.HandleFunc("PATCH /api/v4/secrets/{name}", f.auth(f.update))
	mux.HandleFunc("DELETE /api/v4/secrets/{name}", f.auth(f.remove))
	mux.HandleFunc("POST /api/v1/folders", f.auth(f.folder))
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		down := f.down
		f.lastRequests = append(f.lastRequests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if down {
			// Drop the connection, as a dead or paused server would.
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

func (f *fake) loginCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins
}

func (f *fake) setDown(d bool) {
	f.mu.Lock()
	f.down = d
	f.mu.Unlock()
}

func (f *fake) expireTokens() {
	f.mu.Lock()
	clear(f.tokens)
	f.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, kind, msg string) {
	writeJSON(w, status, map[string]any{"reqId": "req-fake", "statusCode": status, "message": msg, "error": kind})
}

func (f *fake) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ ClientID, ClientSecret string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, 400, "BadRequest", "bad body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins++
	if in.ClientID != f.clientID || in.ClientSecret != f.clientSecret {
		apiErr(w, 401, "UnauthorizedError", "Invalid credentials")
		return
	}
	f.issueLocked(w)
}

func (f *fake) issueLocked(w http.ResponseWriter) {
	tok := "tok-" + randID(16)
	f.tokens[tok] = time.Now().Add(time.Duration(f.tokenTTL) * time.Second)
	f.issued = append(f.issued, tok)
	writeJSON(w, 200, map[string]any{"accessToken": tok, "expiresIn": f.tokenTTL, "accessTokenMaxTTL": 7200, "tokenType": "Bearer"})
}

// kubernetesLogin answers as Infisical does after its TokenReview: an
// unknown identity is 404, a rejected service account token 401.
func (f *fake) kubernetesLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IdentityID string `json:"identityId"`
		JWT        string `json:"jwt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.IdentityID == "" || in.JWT == "" {
		apiErr(w, 400, "BadRequest", "bad body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seenJWTs = append(f.seenJWTs, in.JWT)
	if in.IdentityID != f.identityID {
		apiErr(w, 404, "NotFound", "Kubernetes auth method not found for identity with ID "+in.IdentityID)
		return
	}
	if !f.jwts[in.JWT] {
		msg := "Access denied: service account token review failed"
		if f.echoJWT {
			msg = "Access denied: token " + in.JWT + " failed review"
		}
		apiErr(w, 401, "UnauthorizedError", msg)
		return
	}
	f.logins++
	f.issueLocked(w)
}

func (f *fake) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		exp, ok := f.tokens[tok]
		f.mu.Unlock()
		if !ok || time.Now().After(exp) {
			apiErr(w, 403, "TokenError", "The provided access token is malformed. Please use a valid token or generate a new one and try again.")
			return
		}
		h(w, r)
	}
}

func (f *fake) projectID(idOrSlug string) (string, bool) {
	for slug, id := range f.projects {
		if idOrSlug == id || idOrSlug == slug {
			return id, true
		}
	}
	return "", false
}

func (f *fake) project(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.projects[r.PathValue("slug")]
	if !ok {
		apiErr(w, 404, "NotFound", "Project not found")
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "slug": r.PathValue("slug")})
}

func skey(pid, env, path, name string) string { return pid + "|" + env + "|" + path + "|" + name }

func (f *fake) folderExists(pid, env, path string) bool {
	return path == "/" || f.folders[pid+"|"+env+"|"+path]
}

func (s *fakeSecret) json(withValue bool, version int) map[string]any {
	v := s.versions[version-1]
	if !withValue {
		v = "<hidden-by-infisical>"
	}
	md := s.metadata
	if md == nil {
		md = []kv{}
	}
	return map[string]any{
		"id": randID(8), "secretKey": s.key, "secretValue": v, "version": version,
		"type": "shared", "secretPath": s.path, "createdAt": s.created, "updatedAt": s.updated,
		"secretMetadata": md, "secretValueHidden": !withValue,
	}
}

func (f *fake) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	pid, ok := f.projectID(q.Get("projectId"))
	if !ok || q.Get("environment") == "" {
		apiErr(w, 400, "BadRequest", "Missing project id or environment")
		return
	}
	env, path := q.Get("environment"), q.Get("secretPath")
	if !f.folderExists(pid, env, path) {
		apiErr(w, 404, "NotFound", "Folder with path '"+path+"' in environment with slug '"+env+"' not found")
		return
	}
	out := []map[string]any{}
	for k, s := range f.secrets {
		if !strings.HasPrefix(k, pid+"|"+env+"|") {
			continue
		}
		in := s.path == path
		if q.Get("recursive") == "true" {
			in = in || strings.HasPrefix(s.path, strings.TrimSuffix(path, "/")+"/")
		}
		if in {
			out = append(out, s.json(q.Get("viewSecretValue") != "false", len(s.versions)))
		}
	}
	writeJSON(w, 200, map[string]any{"secrets": out, "imports": []any{}})
}

func (f *fake) get(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	pid, _ := f.projectID(q.Get("projectId"))
	s, ok := f.secrets[skey(pid, q.Get("environment"), q.Get("secretPath"), r.PathValue("name"))]
	if !ok {
		apiErr(w, 404, "NotFound", "Secret with name '"+r.PathValue("name")+"' not found")
		return
	}
	version := len(s.versions)
	if v := q.Get("version"); v != "" {
		n, _ := strconv.Atoi(v)
		if n < 1 || n > len(s.versions) {
			apiErr(w, 404, "NotFound", "Secret version not found")
			return
		}
		version = n
	}
	writeJSON(w, 200, map[string]any{"secret": s.json(true, version)})
}

type writeBody struct {
	ProjectID      string `json:"projectId"`
	Environment    string `json:"environment"`
	SecretPath     string `json:"secretPath"`
	SecretValue    string `json:"secretValue"`
	SecretMetadata []kv   `json:"secretMetadata"`
}

func (f *fake) decodeWrite(w http.ResponseWriter, r *http.Request) (writeBody, string, bool) {
	var in writeBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, 400, "BadRequest", "bad body")
		return in, "", false
	}
	pid, ok := f.projectID(in.ProjectID)
	if !ok {
		apiErr(w, 404, "NotFound", "Project not found")
		return in, "", false
	}
	// Infisical trims values (see storable).
	if strings.HasSuffix(in.SecretValue, "\n") {
		in.SecretValue = strings.TrimSpace(in.SecretValue) + "\n"
	} else {
		in.SecretValue = strings.TrimSpace(in.SecretValue)
	}
	if in.Environment == f.readOnlyEnv {
		apiErr(w, 403, "PermissionDenied", "You are not allowed to create on secrets")
		return in, "", false
	}
	return in, pid, true
}

func (f *fake) create(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, pid, ok := f.decodeWrite(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !f.folderExists(pid, in.Environment, in.SecretPath) {
		apiErr(w, 404, "CreateSecret", "Folder with path '"+in.SecretPath+"' in environment with slug '"+in.Environment+"' not found")
		return
	}
	k := skey(pid, in.Environment, in.SecretPath, name)
	if _, exists := f.secrets[k]; exists {
		apiErr(w, 400, "BadRequest", "Secret '"+name+"' already exists in path '"+in.SecretPath+"' of environment '"+in.Environment+"'")
		return
	}
	now := time.Now().UTC()
	s := &fakeSecret{key: name, path: in.SecretPath, versions: []string{in.SecretValue}, created: now, updated: now, metadata: in.SecretMetadata}
	f.secrets[k] = s
	writeJSON(w, 200, map[string]any{"secret": s.json(false, 1)})
}

func (f *fake) update(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, pid, ok := f.decodeWrite(w, r)
	if !ok {
		return
	}
	s, exists := f.secrets[skey(pid, in.Environment, in.SecretPath, r.PathValue("name"))]
	if !exists {
		apiErr(w, 404, "NotFound", "Secret not found")
		return
	}
	s.versions = append(s.versions, in.SecretValue)
	s.updated = time.Now().UTC()
	if in.SecretMetadata != nil {
		s.metadata = in.SecretMetadata
	}
	writeJSON(w, 200, map[string]any{"secret": s.json(false, len(s.versions))})
}

func (f *fake) remove(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var in writeBody
	_ = json.NewDecoder(r.Body).Decode(&in)
	pid, _ := f.projectID(in.ProjectID)
	k := skey(pid, in.Environment, in.SecretPath, r.PathValue("name"))
	if _, ok := f.secrets[k]; !ok {
		apiErr(w, 404, "NotFound", "Secret not found")
		return
	}
	delete(f.secrets, k)
	writeJSON(w, 200, map[string]any{})
}

func (f *fake) folder(w http.ResponseWriter, r *http.Request) {
	var in struct{ WorkspaceID, Environment, Path, Name string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, 400, "BadRequest", "bad body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	pid, ok := f.projectID(in.WorkspaceID)
	if !ok {
		apiErr(w, 404, "NotFound", "Project not found")
		return
	}
	if !f.folderExists(pid, in.Environment, in.Path) {
		apiErr(w, 404, "NotFound", "Parent folder not found")
		return
	}
	full := strings.TrimSuffix(in.Path, "/") + "/" + in.Name
	k := pid + "|" + in.Environment + "|" + full
	if f.folders[k] {
		apiErr(w, 400, "BadRequest", "Folder with name '"+in.Name+"' already exists")
		return
	}
	f.folders[k] = true
	writeJSON(w, 200, map[string]any{"folder": map[string]any{"name": in.Name}})
}
