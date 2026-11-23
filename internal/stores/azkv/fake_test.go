// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an in-process Azure Key Vault (secrets, REST API 7.5) and the
// parts of Microsoft Entra ID and the App Service managed identity endpoint
// that azidentity calls, on one TLS server. It follows the documented
// behaviour of the real service: the 401 Bearer challenge for a request
// without a token, one-second timestamps, versions per PUT, tags and
// content type kept per version, 25 entries a page with nextLink, soft
// delete holding the name (409 on reuse), 403 SecretDisabled for a disabled
// version and the error envelope {"error":{"code","message","innererror"}}.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	tenant   string
	resource string // challenge resource
	// challengeHeader, when set, replaces the WWW-Authenticate header.
	challengeHeader string

	clientID     string
	clientSecret string
	assertions   map[string]bool // accepted client assertions (workload identity)
	// certAssertions accepts any signed JWT assertion carrying a
	// certificate thumbprint, as a client certificate login sends.
	certAssertions bool
	seenAssert     []string
	miHeader       string // App Service X-IDENTITY-HEADER value
	tokens         map[string]bool
	issued         []string
	tokenReqs      int
	scopes         []string

	secrets map[string][]*fakeVersion
	deleted map[string]bool
	down    bool
	// denyWrite refuses PUT for names with this prefix, as an RBAC role
	// without secrets/set would.
	denyWrite string
	// requests is every vault request, "METHOD /path".
	requests []string
	// valuesServed counts responses that carried a value.
	valuesServed int
	// echoValue makes a refused PUT quote the value back in its message.
	echoValue bool
	pageSize  int

	// Agents' own identities: a token issued for an accepted assertion in
	// agentReads may read only secrets whose name starts with its prefix
	// (403 otherwise, as an RBAC role scoped to them would answer).
	// forms keeps every token request's form.
	agentReads  map[string]string
	tokenPrefix map[string]string
	forms       []url.Values
}

type fakeVersion struct {
	id          string
	value       string
	contentType *string
	tags        map[string]string
	enabled     bool
	created     int64
	updated     int64
	managed     bool
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{
		t:          t,
		tenant:     "72f988bf-86f1-41af-91ab-2d7cd011db47",
		clientID:   "0f5b2c4e-1a2b-4c3d-9e8f-1234567890ab",
		assertions: map[string]bool{},
		tokens:     map[string]bool{},
		secrets:    map[string][]*fakeVersion{},
		deleted:    map[string]bool{},
		pageSize:   25,

		agentReads:  map[string]string{},
		tokenPrefix: map[string]string{},
	}
	f.clientSecret = "cs-" + randHex(12)
	f.miHeader = "mi-" + randHex(8)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	// Outages close connections mid-handshake; that is the point.
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	f.resource = "https://127.0.0.1"
	t.Cleanup(f.srv.Close)
	return f
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// caFile writes the server's certificate to a file for tls.ca-file.
func (f *fake) caFile() string {
	p := filepath.Join(f.t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fake) setDown(d bool) {
	f.mu.Lock()
	f.down = d
	f.mu.Unlock()
	if d {
		f.srv.CloseClientConnections()
	}
}

func (f *fake) kvError(w http.ResponseWriter, status int, code, msg, inner string) {
	body := map[string]any{"code": code, "message": msg}
	if inner != "" {
		body["innererror"] = map[string]string{"code": inner}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": body})
}

func (f *fake) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/secrets"):
		f.vault(w, r)
	case r.URL.Path == "/msi/token":
		f.managedIdentity(w, r)
	case strings.HasSuffix(r.URL.Path, "/v2.0/.well-known/openid-configuration"):
		f.discovery(w, r)
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fake) discovery(w http.ResponseWriter, r *http.Request) {
	tenant := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[0]
	base := f.srv.URL + "/" + tenant
	f.writeJSON(w, map[string]any{
		"token_endpoint":                        base + "/oauth2/v2.0/token",
		"authorization_endpoint":                base + "/oauth2/v2.0/authorize",
		"device_authorization_endpoint":         base + "/oauth2/v2.0/devicecode",
		"issuer":                                base + "/v2.0",
		"jwks_uri":                              base + "/discovery/v2.0/keys",
		"response_types_supported":              []string{"code", "id_token", "token"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt", "client_secret_basic"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"tenant_region_scope":                   "EU",
		"cloud_instance_name":                   "microsoftonline.com",
	})
}

func (f *fake) issue() string {
	tok := "eyJ0eXAiOiJKV1QifQ." + randHex(24) + ".sig"
	f.tokens[tok] = true
	f.issued = append(f.issued, tok)
	return tok
}

func (f *fake) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tenant := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[0]
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenReqs++
	f.forms = append(f.forms, r.PostForm)
	f.scopes = append(f.scopes, r.PostForm.Get("scope"))
	bad := func(code, desc string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": code, "error_description": desc, "error_codes": []int{7000215}})
	}
	if tenant != f.tenant {
		bad("invalid_request", "AADSTS90002: Tenant not found.")
		return
	}
	if r.PostForm.Get("client_id") != f.clientID {
		bad("unauthorized_client", "AADSTS700016: Application not found in the directory.")
		return
	}
	if !strings.Contains(r.PostForm.Get("scope"), f.resource+"/.default") {
		bad("invalid_scope", "AADSTS70011: The provided value for the input parameter 'scope' is not valid.")
		return
	}
	switch {
	case r.PostForm.Get("client_secret") != "":
		if r.PostForm.Get("client_secret") != f.clientSecret {
			// Entra does not echo the secret; neither does the fake.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})
			return
		}
	case r.PostForm.Get("client_assertion") != "":
		a := r.PostForm.Get("client_assertion")
		f.seenAssert = append(f.seenAssert, a)
		if accepted := f.assertions[a] || (f.certAssertions && certAssertion(a)); !accepted {
			bad("invalid_client", "AADSTS700211: No matching federated identity record found for presented assertion issuer.")
			return
		}
	default:
		bad("invalid_request", "AADSTS900144: The request body must contain client_secret or client_assertion.")
		return
	}
	tok := f.issue()
	if p, ok := f.agentReads[r.PostForm.Get("client_assertion")]; ok {
		f.tokenPrefix[tok] = p
	}
	f.writeJSON(w, map[string]any{"token_type": "Bearer", "expires_in": 3600, "ext_expires_in": 3600, "access_token": tok})
}

func (f *fake) managedIdentity(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenReqs++
	if r.Header.Get("X-IDENTITY-HEADER") != f.miHeader {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	res := r.URL.Query().Get("resource")
	f.scopes = append(f.scopes, res)
	if res != f.resource {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tok := f.issue()
	miTokens.Store(tok, true)
	f.writeJSON(w, map[string]any{
		"access_token": tok, "token_type": "Bearer", "resource": res,
		"expires_on": strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
	})
}

// miTokens are managed identity tokens issued by any fake in this process.
// MSAL caches managed identity tokens process-wide, so a later fake (with
// -count > 1) is presented a token an earlier one issued, as a real vault
// would be presented a still-valid token after scrim restarts its adapter.
var miTokens sync.Map

var namePattern = regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)

func (f *fake) vault(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	down := f.down
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	_, mi := miTokens.Load(tok)
	if !ok || (!f.tokens[tok] && !mi) {
		h := f.challengeHeader
		if h == "" {
			h = fmt.Sprintf(`Bearer authorization="%s/%s", resource="%s"`, "https://login.microsoftonline.com", f.tenant, f.resource)
		}
		w.Header().Set("WWW-Authenticate", h)
		f.kvError(w, http.StatusUnauthorized, "Unauthorized", "AKV10000: Request is missing a Bearer or PoP token.", "")
		return
	}
	if r.URL.Query().Get("api-version") != apiVersion {
		f.kvError(w, http.StatusBadRequest, "BadParameter", "The specified version is not supported.", "")
		return
	}
	seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if p, ok := f.tokenPrefix[tok]; ok && (len(seg) < 2 || !strings.HasPrefix(seg[1], p)) {
		f.kvError(w, http.StatusForbidden, "Forbidden", "Caller is not authorized to perform action on resource.", "ForbiddenByRbac")
		return
	}
	switch {
	case len(seg) == 1 && r.Method == http.MethodGet:
		f.list(w, r)
	case len(seg) == 2 && r.Method == http.MethodPut:
		f.put(w, r, seg[1])
	case len(seg) == 2 && r.Method == http.MethodDelete:
		if _, ok := f.secrets[seg[1]]; !ok {
			f.kvError(w, http.StatusNotFound, "SecretNotFound", "A secret with (name/id) "+seg[1]+" was not found in this key vault.", "")
			return
		}
		delete(f.secrets, seg[1])
		f.deleted[seg[1]] = true
		f.writeJSON(w, map[string]any{"id": f.srv.URL + "/secrets/" + seg[1]})
	case len(seg) == 3 && seg[2] == "versions" && r.Method == http.MethodGet:
		f.listVersions(w, r, seg[1])
	case (len(seg) == 2 || len(seg) == 3) && r.Method == http.MethodGet:
		ver := ""
		if len(seg) == 3 {
			ver = seg[2]
		}
		f.get(w, seg[1], ver)
	default:
		f.kvError(w, http.StatusMethodNotAllowed, "BadParameter", "Method not allowed", "")
	}
}

func (f *fake) props(name string, v *fakeVersion, withVersion bool) map[string]any {
	id := f.srv.URL + "/secrets/" + name
	if withVersion {
		id += "/" + v.id
	}
	m := map[string]any{
		"id": id,
		"attributes": map[string]any{
			"enabled": v.enabled, "created": v.created, "updated": v.updated,
			"recoveryLevel": "Recoverable+Purgeable", "recoverableDays": 90,
		},
	}
	if v.contentType != nil {
		m["contentType"] = *v.contentType
	}
	if len(v.tags) > 0 {
		m["tags"] = v.tags
	}
	if v.managed {
		m["managed"] = true
	}
	return m
}

func (f *fake) page(w http.ResponseWriter, r *http.Request, path string, items []map[string]any) {
	max := f.pageSize
	if s := r.URL.Query().Get("maxresults"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 25 {
			f.kvError(w, http.StatusBadRequest, "BadParameter", "maxresults must be between 1 and 25", "")
			return
		}
		max = min(n, f.pageSize)
	}
	skip, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	end := min(skip+max, len(items))
	out := map[string]any{"value": items[min(skip, len(items)):end], "nextLink": nil}
	if end < len(items) {
		out["nextLink"] = fmt.Sprintf("%s%s?api-version=%s&$skiptoken=%d&maxresults=%d", f.srv.URL, path, apiVersion, end, max)
	}
	f.writeJSON(w, out)
}

func (f *fake) list(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(f.secrets))
	for n := range f.secrets {
		names = append(names, n)
	}
	slices.Sort(names)
	items := make([]map[string]any, 0, len(names))
	for _, n := range names {
		vs := f.secrets[n]
		items = append(items, f.props(n, vs[len(vs)-1], false))
	}
	f.page(w, r, "/secrets", items)
}

func (f *fake) listVersions(w http.ResponseWriter, r *http.Request, name string) {
	vs, ok := f.secrets[name]
	if !ok {
		f.kvError(w, http.StatusNotFound, "SecretNotFound", "A secret with (name/id) "+name+" was not found in this key vault.", "")
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, f.props(name, v, true))
	}
	// Key Vault does not document an order; the fake lists by version ID.
	slices.SortFunc(items, func(a, b map[string]any) int { return strings.Compare(a["id"].(string), b["id"].(string)) })
	f.page(w, r, "/secrets/"+name+"/versions", items)
}

func (f *fake) get(w http.ResponseWriter, name, ver string) {
	vs, ok := f.secrets[name]
	if !ok {
		f.kvError(w, http.StatusNotFound, "SecretNotFound", "A secret with (name/id) "+name+" was not found in this key vault.", "")
		return
	}
	v := vs[len(vs)-1]
	if ver != "" {
		v = nil
		for _, x := range vs {
			if strings.EqualFold(x.id, ver) {
				v = x
			}
		}
		if v == nil {
			f.kvError(w, http.StatusNotFound, "SecretNotFound", "A secret with (name/id) "+name+"/"+ver+" was not found in this key vault.", "")
			return
		}
	}
	if !v.enabled {
		f.kvError(w, http.StatusForbidden, "Forbidden", "Operation get is not allowed on a disabled secret.", "SecretDisabled")
		return
	}
	m := f.props(name, v, true)
	m["value"] = v.value
	f.valuesServed++
	f.writeJSON(w, m)
}

func (f *fake) put(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		Value       *string           `json:"value"`
		ContentType *string           `json:"contentType"`
		Tags        map[string]string `json:"tags"`
		Attributes  *struct {
			Enabled *bool `json:"enabled"`
		} `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Value == nil {
		f.kvError(w, http.StatusBadRequest, "BadParameter", "Property value is required.", "")
		return
	}
	if !namePattern.MatchString(name) {
		f.kvError(w, http.StatusBadRequest, "BadParameter", "The request URI contains an invalid name: "+name, "")
		return
	}
	if f.denyWrite != "" && strings.HasPrefix(name, f.denyWrite) {
		msg := "Caller is not authorized to perform action on resource. Action: 'Microsoft.KeyVault/vaults/secrets/setSecret/action'"
		if f.echoValue {
			msg += " value: " + *body.Value
		}
		f.kvError(w, http.StatusForbidden, "Forbidden", msg, "ForbiddenByRbac")
		return
	}
	if f.deleted[name] {
		f.kvError(w, http.StatusConflict, "Conflict", "Secret "+name+" is currently in a deleted but recoverable state, and its name cannot be reused; in this state, the secret can only be recovered or purged.", "ObjectIsDeletedButRecoverable")
		return
	}
	if len(body.Tags) > 15 {
		f.kvError(w, http.StatusBadRequest, "BadParameter", "Too many tags", "")
		return
	}
	if len(*body.Value) > 25*1024 {
		f.kvError(w, http.StatusBadRequest, "BadParameter", "Secret value is too long", "")
		return
	}
	now := time.Now().Unix()
	v := &fakeVersion{id: randHex(16), value: *body.Value, contentType: body.ContentType, tags: body.Tags, enabled: true, created: now, updated: now}
	if body.Attributes != nil && body.Attributes.Enabled != nil {
		v.enabled = *body.Attributes.Enabled
	}
	f.secrets[name] = append(f.secrets[name], v)
	m := f.props(name, v, true)
	m["value"] = v.value
	f.writeJSON(w, m)
}

// seed stores a version out of band, as another Key Vault client would.
func (f *fake) seed(name, value string, tags map[string]string, contentType *string) *fakeVersion {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().Unix()
	v := &fakeVersion{id: randHex(16), value: value, tags: tags, contentType: contentType, enabled: true, created: now, updated: now}
	f.secrets[name] = append(f.secrets[name], v)
	delete(f.deleted, name)
	return v
}

func (f *fake) remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, name)
	f.deleted[name] = true
}

// certAssertion reports whether a is a three-part JWT whose header names a
// certificate thumbprint (x5t or x5t#S256), as MSAL signs with a client
// certificate. The fake does not check the signature.
func certAssertion(a string) bool {
	parts := strings.Split(a, ".")
	if len(parts) != 3 || parts[2] == "" {
		return false
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr map[string]any
	if json.Unmarshal(h, &hdr) != nil {
		return false
	}
	return hdr["x5t"] != nil || hdr["x5t#S256"] != nil
}
