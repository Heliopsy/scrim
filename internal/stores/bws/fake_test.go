// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// fakeBWS is an in-process Bitwarden identity and Secrets Manager API, for
// the endpoints a machine account uses. There is no test account to run the
// conformance suite against and no self-hostable Secrets Manager emulator
// (Vaultwarden does not implement it), so the fake is built from the
// official sources and serves their recorded fixtures:
//
//   - the access token, login response (encrypted_payload) and organisation
//     of the SDK's fake server (bitwarden/sdk-sm crates/fake-server, see
//     officialToken), so a login really derives the access token key and
//     decrypts the organisation key;
//   - the project and secret ciphertexts recorded there, served verbatim
//     (seedOfficial);
//   - the request and response models, the 404 the server answers for a
//     refused authorisation, the one-project limit, the encrypted string
//     length limits and the update rule that a request naming the current
//     project leaves it alone and answers without projects, from
//     bitwarden/server src/Api/SecretsManager (commit f0bcb2c7).
//
// Like the real server it never decrypts anything: it stores the encrypted
// strings clients send. Out-of-band seeding (Seed, the official fixtures)
// encrypts with the organisation key, as another Bitwarden client would.
//
// Besides scrim's own machine account (the official token) it knows agents'
// machine accounts (addAgent), each with an access token whose key really
// derives the key of its login's encrypted_payload, an organisation, and
// read or read-write access per project (grant). GET /secrets/{id} and GET
// /projects/{id} answer with the caller's own read and write flags and 404
// when it may not read (SecretsController.GetAsync, ProjectsController.
// GetAsync).
//
// Fidelity limits: no rate limiting, no event logs, no access policies on
// individual secrets (access is per project, read or read-write), no
// secret versions or trash, no project management endpoints beyond GET
// /projects/{id}, bearer tokens are not signed, an agent of another
// organisation gets a random organisation key and sees nothing of this
// one, and the server's exact validation messages are not reproduced, only
// their status codes.
type fakeBWS struct {
	t   testing.TB
	srv *httptest.Server

	org    string
	orgKey bwcrypto.SymmetricKey

	mu sync.Mutex
	// bearers maps an issued bearer token to the access token ID it was
	// issued for.
	bearers   map[string]string
	agents    map[string]*fakeAgent
	expiresIn int
	projects  map[string]*fakeProject
	secrets   map[string]*fakeSecret
	logins    int
	// agentLogins counts logins per agent access token ID.
	agentLogins map[string]int
	// requests records every request line and body, for leak checks.
	requests []string
	// deviceTypes records the Device-Type header of each request.
	deviceTypes []string

	down atomic.Bool
}

type fakeProject struct {
	id, name string // name is an encrypted string
	read     bool
	write    bool
	created  time.Time
}

// fakeAgent is an agent's machine account.
type fakeAgent struct {
	id, secret string
	org        string
	tokenKey   bwcrypto.SymmetricKey // derived from the access token's key part
	access     map[string][2]bool    // project ID -> read, write
}

type fakeSecret struct {
	id                string
	key, value, note  string // encrypted strings
	projectID         string
	created, revision time.Time
}

// Official fixtures: bitwarden/sdk-sm crates/fake-server/src/routes.rs and
// README.md at commit db735a12a8da505d99bec9498e3b21b4584acc6c.
const (
	officialToken   = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="
	officialOrg     = "f4e44a7f-1190-432a-9d4a-af96013127cb"
	officialPayload = "2.E9fE8+M/VWMfhhim1KlCbQ==|eLsHR484S/tJbIkM6spnG/HP65tj9A6Tba7kAAvUp+rYuQmGLixiOCfMsqt5OvBctDfvvr/AesBu7cZimPLyOEhqEAjn52jF0eaI38XZfeOG2VJl0LOf60Wkfh3ryAMvfvLj3G4ZCNYU8sNgoC2+IQ==|lNApuCQ4Pyakfo/wwuuajWNaEX/2MW8/3rjXB/V7n+k="
	// officialJWT is the bearer token the SDK's fake server returns.
	officialJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMwMURENkE1MEU4NEUxRDA5MUM4MUQzQjAwQkY5MDEwQzg1REJEOUFSUzI1NiIsInR5cCI6" +
		"ImF0K2p3dCIsIng1dCI6Ik1CM1dwUTZFNGRDUnlCMDdBTC1RRU1oZHZabyJ9.eyJuYmYiOjE2NzUxMDM3ODEsImV4cCI6MTY3NTEwNzM4MSwiaXNzIjo" +
		"iaHR0cDovL2xvY2FsaG9zdCIsImNsaWVudF9pZCI6ImVjMmMxZDQ2LTZhNGItNDc1MS1hMzEwLWFmOTYwMTMxN2YyZCIsInN1YiI6ImQzNDgwNGNhLTR" +
		"mNmMtNDM5Mi04NmI3LWFmOTYwMTMxNzVkMCIsIm9yZ2FuaXphdGlvbiI6ImY0ZTQ0YTdmLTExOTAtNDMyYS05ZDRhLWFmOTYwMTMxMjdjYiIsImp0aSI" +
		"6IjU3QUU0NzQ0MzIwNzk1RThGQkQ4MUIxNDA2RDQyNTQyIiwiaWF0IjoxNjc1MTAzNzgxLCJzY29wZSI6WyJhcGkuc2VjcmV0cyJdfQ.GRKYzqgJZHEE" +
		"ZHsJkhVZH8zjYhY3hUvM4rhdV3FU10WlCteZdKHrPIadCUh-Oz9DxIAA2HfALLhj1chL4JgwPmZgPcVS2G8gk8XeBmZXowpVWJ11TXS1gYrM9syXbv9j" +
		"0JUCdpeshH7e56WnlpVynyUwIum9hmYGZ_XJUfmGtlKLuNjYnawTwLEeR005uEjxq3qI1kti-WFnw8ciL4a6HLNulgiFw1dAvs4c7J0souShMfrnFO3g" +
		"SOHff5kKD3hBB9ynDBnJQSFYJ7dFWHIjhqs0Vj-9h0yXXCcHvu7dVGpaiNjNPxbh6YeXnY6UWcmHLDtFYsG2BWcNvVD4-VgGxXt3cMhrn7l3fSYuo32Z" +
		"Yk4Wop73XuxqF2fmfmBdZqGI1BafhENCcZw_bpPSfK2uHipfztrgYnrzwvzedz0rjFKbhDyrjzuRauX5dqVJ4ntPeT9g_I5n71gLxiP7eClyAx5RxdF6" +
		"He87NwC8i-hLBhugIvLTiDj-Sk9HvMth6zaD0ebxd56wDjq8-CMG_WcgusDqNzKFHqWNDHBXt8MLeTgZAR2rQMIMFZqFgsJlRflbig8YewmNUA9wAU74" +
		"TfxLY1foO7Xpg49vceB7C-PlvGi1VtX6F2i0tc_67lA5kWXnnKBPBUyspoIrmAUCwfms5nTTqA9xXAojMhRHAos_OdM"
	// officialOrgKey is what officialPayload decrypts to under the key
	// derived from officialToken; TestOfficialLogin checks it.
	officialOrgKey  = "k/6PcwG7Hm/eZfvvOvP6EqGx1JKgbzYrWwpOIHsxbJHQMpIMg5Ud94AQHduSR+XMMaFiSB+nszbO4JPXj04YwA=="
	officialTokenID = "ec2c1d46-6a4b-4751-a310-af9601317f2d"
	officialSecret  = "C2IgxjjLF7qSshsbwe8JGcbM075YXw"
)

// officialCipher holds ciphertexts recorded in the SDK's fake server and
// what they decrypt to under officialOrgKey.
var officialCipher = struct {
	prodName, devName       string
	tuxKey, tuxValue        string
	tuxNote                 string
	ferrisKey, ferrisNote   string
	syncedKey, syncedValue  string
	btwKey, btwNote, noteT  string
	plainTux, plainSyncedV  string
	plainProd, plainDev     string
	plainFerris, plainTEST  string
	plainBtw, plainSyncedK  string
	plainTuxKey, plainEmpty string
}{
	prodName:    "2.DmcNJqtzi+nPWY9gJR4nMw==|IEkn2x+C0YLmnQ/qm0EfOcMGcRZDkexFkDW9BPw3wRQ=|TxxTeBKqL0QYLT+89F0KfI81BbBryXnNNAjU9DGKuuY=",
	devName:     "2.4hWxQC9O5KpHcyCyI/xBsQ==|RLkyV/QbEMpxPnO91E/jPURCvsDIjI1ZIh6eMvGIuEg=|FXnie8Z9OtaBElnzF0v4Iut0fmy7IAI2IedEKJKuSp0=",
	tuxKey:      "2.OldQj0RJKww0WN7RSxI1wQ==|TpxAbmdx6zIVo37YJ5n1aQ==|06Imyx7jqaZ5J5amrBboCVPwvPoDKB8REJdToQwp3dA=",
	tuxValue:    "2.oEDp566lC9VYHn6XmusxfA==|Gj23w5q2NZ4z9PNne1d0ug==|y7K5TgMJFI0T0yFwLXzAMf9OBANNT567hLQ+z7G2rac=",
	tuxNote:     "2.owktgGRm4r+ho4WY4U9zvA==|6Up5NQHyZ65SL3vbNI1GhQ==|vdvWvPpoB/J3aWXKBiruqOr1SK/ndkCCTjHf2vphhu4=",
	ferrisKey:   "2.N2aCz0PU6Ga9YfJlvisnwQ==|3M8dF2PFub9FP/SbgdenSQ==|KbaUQSb5IjVwhSbXDbCJbKXGBaCHEKDArrhvQDr9/QM=",
	ferrisNote:  "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=",
	syncedKey:   "2.4MPPDSh3oQPfK0Sxny925g==|Rj4P0P6M3l/WD99KiwtRiQ==|6wcq4L8ZJ45h549RbiVd1sI26Q6QxaUPmQB2dAXVO1c=",
	syncedValue: "2.78LSmLCl2XW8za0HyZUV2Q==|rwLKE0FGfyAZT9CUR9yUVg==|xZIthCfi1fzJOZ/riBQ3FXfuICBUv8jeE3Qrbg1f5D8=",
	btwKey:      "2.WYqmVCB2wZc08tkzNOCmTw==|FAsVol/nJnnDk3/mp7z6QQ==|uPJOCC8iAbMzz4t60c35iZm8KzWKMn0ueCVJZlfmTdY=",
	btwNote:     "2.S57kOfi1kIHjToxwR6sEuQ==|lTop/7iWWUveCGWXrHbHwg==|YrtUfrlRRN+ff8Re7txi2dTT9Ul0cwmiFWDgVpdWGlc=",

	plainProd: "Production Environment", plainDev: "Development Environment",
	plainTuxKey: "TUX", plainTux: "🐧", plainEmpty: "",
	plainFerris: "FERRIS", plainTEST: "TEST",
	plainSyncedK: "synced-secret", plainSyncedV: "⏱️",
	plainBtw: "btw",
}

func newFake(t testing.TB) *fakeBWS {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(officialOrgKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := bwcrypto.NewSymmetricKey(secret.Adopt(raw))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeBWS{
		t: t, org: officialOrg, orgKey: key, expiresIn: 3600,
		bearers: map[string]string{}, agents: map[string]*fakeAgent{}, agentLogins: map[string]int{}, projects: map[string]*fakeProject{}, secrets: map[string]*fakeSecret{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (f *fakeBWS) enc(s string) string {
	f.t.Helper()
	e, err := f.orgKey.EncryptMetadata(s)
	if err != nil {
		f.t.Fatal(err)
	}
	return e.String()
}

// addProject adds a project the machine account can read, and write if
// write is set, and returns its ID.
func (f *fakeBWS) addProject(name string, write bool) string {
	return f.addProjectCipher(f.enc(name), true, write)
}

func (f *fakeBWS) addProjectCipher(nameEnc string, read, write bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := newUUID()
	f.projects[id] = &fakeProject{id: id, name: nameEnc, read: read, write: write, created: f.now()}
	return id
}

// addSecretCipher stores a secret from encrypted strings.
func (f *fakeBWS) addSecretCipher(projectID, key, value, note string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := newUUID()
	now := f.now()
	f.secrets[id] = &fakeSecret{id: id, key: key, value: value, note: note, projectID: projectID, created: now, revision: now}
	return id
}

// put creates or replaces the secret with key in project, as another client
// would, encrypting with the organisation key.
func (f *fakeBWS) put(projectID, key string, value secret.Value) string {
	f.t.Helper()
	ev, err := f.orgKey.Encrypt(value)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	for _, s := range f.secrets {
		if s.projectID == projectID && f.plain(s.key) == key {
			s.value = ev.String()
			s.revision = f.next(s.revision)
			f.mu.Unlock()
			return s.id
		}
	}
	f.mu.Unlock()
	return f.addSecretCipher(projectID, f.enc(key), ev.String(), f.enc(""))
}

func (f *fakeBWS) plain(enc string) string {
	s, err := f.orgKey.DecryptMetadata(enc)
	if err != nil {
		f.t.Errorf("fake: undecryptable string stored: %v", err)
	}
	return s
}

// remove deletes the secret with key in project, out of band.
func (f *fakeBWS) remove(projectID, key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, s := range f.secrets {
		if s.projectID == projectID && f.plain(s.key) == key {
			delete(f.secrets, id)
		}
	}
}

// revokeBearers forgets every issued bearer token, as when they expire
// server side.
func (f *fakeBWS) revokeBearers() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bearers = map[string]string{}
}

// now is the server clock at DateTime precision (100 ns).
func (f *fakeBWS) now() time.Time { return time.Now().UTC().Truncate(100 * time.Nanosecond) }

// next is a revision date after prev, as two edits a few milliseconds apart
// get from DateTime.UtcNow.
func (f *fakeBWS) next(prev time.Time) time.Time {
	n := f.now()
	if !n.After(prev) {
		n = prev.Add(100 * time.Nanosecond)
	}
	return n
}

// dotnet formats a timestamp the way the server's JSON does: seven
// fractional digits and Z.
func dotnet(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.0000000Z") }

func (f *fakeBWS) jwt(clientID, org string) string {
	enc := base64.RawURLEncoding.EncodeToString
	head := enc([]byte(`{"alg":"RS256","typ":"at+jwt"}`))
	now := time.Now().Unix()
	body, _ := json.Marshal(map[string]any{
		"nbf": now, "exp": now + int64(f.expiresIn), "iss": f.srv.URL + "/identity",
		"client_id": clientID, "sub": newUUID(), "organization": org,
		"jti": newUUID(), "iat": now, "scope": []string{"api.secrets"},
	})
	return head + "." + enc(body) + ".unsigned"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{"message": "Resource not found.", "object": "error"})
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"message": "The model state is invalid.", "validationErrors": map[string][]string{"": {msg}}, "object": "error"})
}

func (f *fakeBWS) serve(w http.ResponseWriter, r *http.Request) {
	if f.down.Load() {
		// An outage: the connection drops without an answer.
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
				return
			}
		}
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.String()+" "+string(body))
	f.deviceTypes = append(f.deviceTypes, r.Header.Get("Device-Type"))
	f.mu.Unlock()

	if r.URL.Path == "/identity/connect/token" {
		f.token(w, r, body)
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/api/")
	if !ok {
		notFound(w)
		return
	}
	auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	who, valid := f.bearers[auth]
	f.mu.Unlock()
	if !ok || !valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	seg := strings.Split(path, "/")
	switch {
	case r.Method == "GET" && len(seg) == 3 && seg[0] == "organizations" && seg[2] == "projects":
		f.listProjects(w, who, seg[1])
	case r.Method == "GET" && len(seg) == 3 && seg[0] == "organizations" && seg[2] == "secrets":
		f.listSecrets(w, who, seg[1])
	case r.Method == "POST" && len(seg) == 3 && seg[0] == "organizations" && seg[2] == "secrets":
		f.create(w, who, seg[1], body)
	case r.Method == "GET" && len(seg) == 2 && seg[0] == "secrets":
		f.get(w, who, seg[1])
	case r.Method == "GET" && len(seg) == 2 && seg[0] == "projects":
		f.getProject(w, who, seg[1])
	case r.Method == "PUT" && len(seg) == 2 && seg[0] == "secrets":
		f.update(w, who, seg[1], body)
	default:
		notFound(w)
	}
}

func (f *fakeBWS) token(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	form, err := parseForm(body)
	if err != nil || form["grant_type"] != "client_credentials" || form["scope"] != "api.secrets" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id := form["client_id"]
	f.mu.Lock()
	defer f.mu.Unlock()
	org, payload := f.org, officialPayload
	switch ag := f.agents[id]; {
	case id == officialTokenID && form["client_secret"] == officialSecret:
		f.logins++
	case ag != nil && form["client_secret"] == ag.secret:
		f.agentLogins[id]++
		org, payload = ag.org, ag.payload(f)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}
	tok := f.jwt(id, org)
	f.bearers[tok] = id
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok, "expires_in": f.expiresIn, "token_type": "Bearer", "scope": "api.secrets",
		"encrypted_payload": payload,
	})
}

func parseForm(b []byte) (map[string]string, error) {
	req, err := http.NewRequest("POST", "/", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range req.PostForm {
		if len(v) != 1 {
			return nil, fmt.Errorf("field %s repeated", k)
		}
		out[k] = v[0]
	}
	return out, nil
}

func (f *fakeBWS) projectJSON(p *fakeProject, read, write bool) map[string]any {
	return map[string]any{"object": "project", "id": p.id, "organizationId": f.org, "name": p.name,
		"creationDate": dotnet(p.created), "revisionDate": dotnet(p.created), "read": read, "write": write}
}

// projectAccess is what the machine account who may do in a project.
func (f *fakeBWS) projectAccess(who, pid string) (read, write bool) {
	p, ok := f.projects[pid]
	if !ok {
		return false, false
	}
	if who == officialTokenID {
		return p.read, p.write
	}
	ag := f.agents[who]
	if ag == nil || ag.org != f.org {
		return false, false
	}
	rw := ag.access[pid]
	return rw[0], rw[1]
}

// getProject is ProjectsController.GetAsync: 404 without read access.
func (f *fakeBWS) getProject(w http.ResponseWriter, who, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.projects[strings.ToLower(id)]
	if !ok {
		notFound(w)
		return
	}
	read, write := f.projectAccess(who, p.id)
	if !read {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, f.projectJSON(p, read, write))
}

func (f *fakeBWS) listProjects(w http.ResponseWriter, who, org string) {
	if org != f.org {
		notFound(w)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data := []any{}
	for _, p := range f.sortedProjects() {
		if read, write := f.projectAccess(who, p.id); read {
			data = append(data, f.projectJSON(p, read, write))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data, "continuationToken": nil})
}

func (f *fakeBWS) sortedProjects() []*fakeProject {
	out := make([]*fakeProject, 0, len(f.projects))
	for _, p := range f.projects {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *fakeProject) int { return strings.Compare(a.id, b.id) })
	return out
}

// access is what the machine account who may do with a secret: through
// its project only.
func (f *fakeBWS) access(who string, s *fakeSecret) (read, write bool) {
	return f.projectAccess(who, s.projectID)
}

func (f *fakeBWS) inner(s *fakeSecret) []map[string]any {
	if p, ok := f.projects[s.projectID]; ok {
		return []map[string]any{{"id": p.id, "name": p.name}}
	}
	return []map[string]any{}
}

func (f *fakeBWS) listSecrets(w http.ResponseWriter, who, org string) {
	if org != f.org {
		notFound(w)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	secrets := []any{}
	var ids []string
	for id := range f.secrets {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	seen := map[string]bool{}
	projects := []any{}
	for _, id := range ids {
		s := f.secrets[id]
		read, write := f.access(who, s)
		if !read {
			continue
		}
		secrets = append(secrets, map[string]any{
			"id": s.id, "organizationId": f.org, "key": s.key,
			"creationDate": dotnet(s.created), "revisionDate": dotnet(s.revision),
			"projects": f.inner(s), "read": read, "write": write,
		})
		if p, ok := f.projects[s.projectID]; ok && !seen[p.id] {
			seen[p.id] = true
			projects = append(projects, map[string]any{"id": p.id, "name": p.name})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "SecretsWithProjectsList", "secrets": secrets, "projects": projects})
}

func (f *fakeBWS) secretJSON(s *fakeSecret, projects any, read, write bool) map[string]any {
	return map[string]any{
		"object": "secret", "id": s.id, "organizationId": f.org, "key": s.key, "value": s.value, "note": s.note,
		"creationDate": dotnet(s.created), "revisionDate": dotnet(s.revision), "projects": projects,
		"read": read, "write": write,
	}
}

func (f *fakeBWS) get(w http.ResponseWriter, who, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[strings.ToLower(id)]
	if !ok {
		notFound(w)
		return
	}
	read, write := f.access(who, s)
	if !read {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, f.secretJSON(s, f.inner(s), read, write))
}

type writeReq struct {
	Key          *string  `json:"key"`
	Value        *string  `json:"value"`
	Note         *string  `json:"note"`
	ProjectIDs   []string `json:"projectIds"`
	ValueChanged bool     `json:"valueChanged"`
}

// validate applies [Required], [EncryptedString] and
// [EncryptedStringLength] of SecretCreateRequestModel and the one-project
// rule.
func (r writeReq) validate() string {
	for _, c := range []struct {
		name  string
		v     *string
		limit int
	}{{"Key", r.Key, 1000}, {"Value", r.Value, 35000}, {"Note", r.Note, 10000}} {
		if c.v == nil {
			return c.name + " is required"
		}
		if _, err := bwcrypto.ParseEncString(*c.v); err != nil {
			return c.name + " is not an encrypted string"
		}
		if len(*c.v) > c.limit {
			return c.name + " exceeds the maximum encrypted value length"
		}
	}
	if len(r.ProjectIDs) > 1 {
		return "Only one project assignment is supported."
	}
	return ""
}

func (f *fakeBWS) create(w http.ResponseWriter, who, org string, body []byte) {
	var req writeReq
	if err := json.Unmarshal(body, &req); err != nil {
		badRequest(w, "malformed body")
		return
	}
	if msg := req.validate(); msg != "" {
		badRequest(w, msg)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if org != f.org {
		notFound(w)
		return
	}
	// A machine account creates secrets only in a project it may write.
	if len(req.ProjectIDs) != 1 {
		notFound(w)
		return
	}
	p, ok := f.projects[strings.ToLower(req.ProjectIDs[0])]
	if !ok {
		notFound(w)
		return
	}
	if _, write := f.projectAccess(who, p.id); !write {
		notFound(w)
		return
	}
	now := f.now()
	s := &fakeSecret{id: newUUID(), key: *req.Key, value: *req.Value, note: *req.Note, projectID: p.id, created: now, revision: now}
	f.secrets[s.id] = s
	// The response lists the project by ID only (CreateAsync returns the
	// entity it built from the request).
	writeJSON(w, http.StatusOK, f.secretJSON(s, []map[string]any{{"id": p.id, "name": nil}}, true, true))
}

func (f *fakeBWS) update(w http.ResponseWriter, who, id string, body []byte) {
	var req writeReq
	if err := json.Unmarshal(body, &req); err != nil {
		badRequest(w, "malformed body")
		return
	}
	if msg := req.validate(); msg != "" {
		badRequest(w, msg)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[strings.ToLower(id)]
	if !ok {
		notFound(w)
		return
	}
	if _, write := f.access(who, s); !write {
		notFound(w)
		return
	}
	var projects any
	if len(req.ProjectIDs) > 0 && strings.EqualFold(req.ProjectIDs[0], s.projectID) {
		// SecretUpdateRequestModel.ToSecret: the same project leaves
		// Projects null, and the response has none.
		projects = nil
	} else {
		if len(req.ProjectIDs) == 0 {
			// Moving a secret out of every project: a machine account
			// would lose access to it, so the authorisation fails.
			notFound(w)
			return
		}
		np, ok := f.projects[strings.ToLower(req.ProjectIDs[0])]
		if _, write := f.projectAccess(who, strings.ToLower(req.ProjectIDs[0])); !ok || !write {
			notFound(w)
			return
		}
		s.projectID = np.id
		projects = []map[string]any{{"id": np.id, "name": nil}}
	}
	s.key, s.value, s.note = *req.Key, *req.Value, *req.Note
	s.revision = f.next(s.revision)
	writeJSON(w, http.StatusOK, f.secretJSON(s, projects, true, true))
}

// seedOfficial adds the recorded fixtures of the SDK's fake server: the two
// projects and three secrets, as ciphertext.
func (f *fakeBWS) seedOfficial() (prod, dev string) {
	c := officialCipher
	prod = f.addProjectCipher(c.prodName, true, false)
	dev = f.addProjectCipher(c.devName, true, false)
	f.addSecretCipher(prod, c.tuxKey, c.tuxValue, c.tuxNote)
	f.addSecretCipher(prod, c.ferrisKey, c.syncedValue, c.ferrisNote)
	f.addSecretCipher(dev, c.syncedKey, c.syncedValue, c.tuxNote)
	f.addSecretCipher(dev, c.btwKey, c.tuxValue, c.btwNote)
	return prod, dev
}

// sawPlain reports whether any request carried p.
func (f *fakeBWS) sawPlain(p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if strings.Contains(r, p) {
			return true
		}
	}
	return false
}

// addAgent creates a machine account of org (the fake's own organisation
// when org is "") and returns its access token, generated at runtime.
func (f *fakeBWS) addAgent(org string) (token, id string) {
	f.t.Helper()
	if org == "" {
		org = f.org
	}
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	sec := make([]byte, 30)
	_, _ = rand.Read(sec)
	id = newUUID()
	token = "0." + id + "." + base64.RawURLEncoding.EncodeToString(sec)[:30] + ":" + base64.StdEncoding.EncodeToString(raw)
	tok, err := parseAccessToken(secret.FromString(token))
	if err != nil {
		f.t.Fatal(err)
	}
	tok.clientSecret.Wipe()
	tok.keyText.Wipe()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents[id] = &fakeAgent{id: id, secret: token[len("0."+id+"."):strings.IndexByte(token, ':')], org: org, tokenKey: tok.key, access: map[string][2]bool{}}
	return token, id
}

// grant gives the agent's machine account read, or read-write, access to
// a project.
func (f *fakeBWS) grant(agentID, projectID string, write bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents[agentID].access[projectID] = [2]bool{true, write}
}

func (f *fakeBWS) agentLoginCount(agentID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.agentLogins[agentID]
}

// payload is the login's encrypted_payload for the agent: the organisation
// key under the access token key, as the identity server sends it (a
// random key for another organisation). f.mu is held.
func (ag *fakeAgent) payload(f *fakeBWS) string {
	key := f.orgKey.Value()
	if ag.org != f.org {
		raw := make([]byte, bwcrypto.SymmetricKeySize)
		_, _ = rand.Read(raw)
		key = secret.Adopt(raw)
	}
	var js []byte
	_ = key.Expose(func(b []byte) error {
		js = []byte(`{"encryptionKey":"` + base64.StdEncoding.EncodeToString(b) + `"}`)
		return nil
	})
	e, err := ag.tokenKey.Encrypt(secret.Adopt(js))
	if err != nil {
		f.t.Errorf("fake: %v", err)
	}
	return e.String()
}

// revokeAgent invalidates the agent's access token and its bearers, as
// when the token is deleted in the web vault.
func (f *fakeBWS) revokeAgent(agentID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents[agentID].secret = "revoked-" + newUUID()
	for b, who := range f.bearers {
		if who == agentID {
			delete(f.bearers, b)
		}
	}
}
