// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an in-memory Google Secret Manager speaking the REST API (v1) the
// adapter uses, with the resource shapes, status codes and error envelopes
// of the real service: names carry the project number, int64 fields are JSON
// strings, a regional secret refuses a replication policy and a global one
// requires it, versions are numbered from 1 and "latest" is the most
// recently created, access to a disabled or destroyed version fails with
// FAILED_PRECONDITION, and addVersion checks the payload's CRC32C. It also
// serves the token endpoints Application Default Credentials talk to: the
// OAuth token endpoint for service account keys (JWT bearer grant, verified
// against the key), STS token exchange for workload identity federation,
// IAM Credentials generateAccessToken for impersonation and the metadata
// server's token endpoint for GKE workload identity.
//
// Fidelity limits: IAM is one allow list of tokens plus deny prefixes for
// writes, list filters, ETag preconditions, TTLs, rotation schedules,
// Pub/Sub notifications and version destruction delays are not modelled,
// and paging uses a page size the fake picks.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	down     bool
	project  string
	number   string
	tokens   map[string]bool
	secrets  map[string]*fakeSecret // parent-relative ID path -> secret
	denyPfx  string                 // writes to IDs with this prefix are refused
	denyVers string                 // only new versions of IDs with this prefix are refused
	pageSize int
	issued   []string
	accesses int // version payloads served
	corrupt  bool

	// Token endpoints.
	saEmail  string
	saKey    *rsa.PrivateKey
	stsAud   string
	stsToken string // subject token STS accepts
	impAllow map[string]bool
	meta     bool // metadata server answers
	jwtSeen  int
	stsSeen  int
	impSeen  int
	metaSeen int
}

type fakeSecret struct {
	parent      string // projects/<id>[/locations/<l>]
	id          string
	created     time.Time
	labels      map[string]string
	annotations map[string]string
	replication map[string]any
	cmek        map[string]any
	topics      []string
	expire      time.Time
	rotation    map[string]any
	aliases     map[string]int
	versions    []*fakeVersion
}

type fakeVersion struct {
	num     int
	data    []byte
	state   string
	created time.Time
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newFake(t *testing.T) *fake {
	f := &fake{
		t:        t,
		project:  "scrim-test-" + randHex(3),
		number:   strconv.Itoa(100000000000 + int(time.Now().UnixNano()%899999999999)),
		tokens:   map[string]bool{},
		secrets:  map[string]*fakeSecret{},
		denyPfx:  "denied",
		pageSize: 7,
		saEmail:  "scrim@scrim-test.iam.gserviceaccount.com",
		impAllow: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", f.auth(f.api))
	mux.HandleFunc("POST /token", f.oauthToken)
	mux.HandleFunc("POST /sts/v1/token", f.sts)
	mux.HandleFunc("POST /iam/v1/{rest...}", f.generateAccessToken)
	mux.HandleFunc("GET /computeMetadata/v1/{rest...}", f.metadata)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		down := f.down
		f.mu.Unlock()
		if down {
			// An outage: the connection drops without an answer.
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

// token issues an access token the API accepts.
func (f *fake) token() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issueLocked()
}

func (f *fake) issueLocked() string {
	tok := "ya29.fake-" + randHex(16)
	f.tokens[tok] = true
	f.issued = append(f.issued, tok)
	return tok
}

func (f *fake) setDown(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// gErr writes Google's error envelope.
func gErr(w http.ResponseWriter, code int, status, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{"code": code, "message": msg, "status": status}})
}

func (f *fake) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		valid := ok && f.tokens[tok]
		f.mu.Unlock()
		if !valid {
			gErr(w, 401, "UNAUTHENTICATED", "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential.")
			return
		}
		next(w, r)
	}
}

var (
	fakeIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	fakeAnnKey     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	fakeLabelKey   = regexp.MustCompile(`^[\p{Ll}\p{Lo}][\p{Ll}\p{Lo}\p{N}_-]{0,62}$`)
	fakeLabelValue = regexp.MustCompile(`^[\p{Ll}\p{Lo}\p{N}_-]{0,63}$`)
	fakeAlias      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,62}$`)
)

// api routes /v1/projects/<p>[/locations/<l>]/secrets[/<id>[/versions/<v>]][:verb].
func (f *fake) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	path, verb, _ := strings.Cut(path, ":")
	seg := strings.Split(path, "/")
	if len(seg) < 3 || seg[0] != "projects" {
		gErr(w, 404, "NOT_FOUND", "Requested entity was not found.")
		return
	}
	if seg[1] != f.project && seg[1] != f.number {
		gErr(w, 403, "PERMISSION_DENIED", "Permission denied on resource project "+seg[1]+".")
		return
	}
	parent := "projects/" + f.project
	rest := seg[2:]
	regional := false
	if rest[0] == "locations" {
		if len(rest) < 3 {
			gErr(w, 404, "NOT_FOUND", "Requested entity was not found.")
			return
		}
		parent += "/locations/" + rest[1]
		regional = true
		rest = rest[2:]
	}
	if rest[0] != "secrets" {
		gErr(w, 404, "NOT_FOUND", "Requested entity was not found.")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case len(rest) == 1 && r.Method == http.MethodGet:
		f.list(w, r, parent)
	case len(rest) == 1 && r.Method == http.MethodPost:
		f.create(w, r, parent, regional)
	case len(rest) == 2 && verb == "addVersion" && r.Method == http.MethodPost:
		f.addVersion(w, r, parent, rest[1])
	case len(rest) == 2 && verb == "" && r.Method == http.MethodGet:
		s := f.secret(w, parent, rest[1])
		if s != nil {
			writeJSON(w, 200, f.render(s))
		}
	case len(rest) == 2 && verb == "" && r.Method == http.MethodPatch:
		f.patch(w, r, parent, rest[1])
	case len(rest) == 2 && verb == "" && r.Method == http.MethodDelete:
		if f.secret(w, parent, rest[1]) != nil {
			delete(f.secrets, parent+"/"+rest[1])
			writeJSON(w, 200, map[string]any{})
		}
	case len(rest) == 4 && rest[2] == "versions":
		f.version(w, r, parent, rest[1], rest[3], verb)
	default:
		gErr(w, 404, "NOT_FOUND", "Requested entity was not found.")
	}
}

func (f *fake) secret(w http.ResponseWriter, parent, id string) *fakeSecret {
	s := f.secrets[parent+"/"+id]
	if s == nil {
		gErr(w, 404, "NOT_FOUND", "Secret ["+f.name(parent)+"/secrets/"+id+"] not found or has no versions.")
	}
	return s
}

// name renders a parent with the project number, as Google does.
func (f *fake) name(parent string) string {
	return strings.Replace(parent, "projects/"+f.project, "projects/"+f.number, 1)
}

func (f *fake) render(s *fakeSecret) map[string]any {
	out := map[string]any{
		"name":       f.name(s.parent) + "/secrets/" + s.id,
		"createTime": s.created.Format(time.RFC3339Nano),
		"etag":       `"` + strconv.FormatInt(s.created.UnixNano()+int64(len(s.versions)), 16) + `"`,
	}
	if s.replication != nil {
		out["replication"] = s.replication
	}
	if s.cmek != nil {
		out["customerManagedEncryption"] = s.cmek
	}
	if len(s.labels) > 0 {
		out["labels"] = s.labels
	}
	if len(s.annotations) > 0 {
		out["annotations"] = s.annotations
	}
	if len(s.topics) > 0 {
		var ts []map[string]string
		for _, t := range s.topics {
			ts = append(ts, map[string]string{"name": t})
		}
		out["topics"] = ts
	}
	if !s.expire.IsZero() {
		out["expireTime"] = s.expire.Format(time.RFC3339Nano)
	}
	if s.rotation != nil {
		out["rotation"] = s.rotation
	}
	if len(s.aliases) > 0 {
		al := map[string]string{}
		for k, v := range s.aliases {
			al[k] = strconv.Itoa(v) // int64 values are JSON strings
		}
		out["versionAliases"] = al
	}
	return out
}

func (f *fake) renderVersion(s *fakeSecret, v *fakeVersion) map[string]any {
	out := map[string]any{
		"name":       f.name(s.parent) + "/secrets/" + s.id + "/versions/" + strconv.Itoa(v.num),
		"createTime": v.created.Format(time.RFC3339Nano),
		"state":      v.state,
		"etag":       `"` + strconv.Itoa(v.num) + `"`,
	}
	if v.state == "DESTROYED" {
		out["destroyTime"] = v.created.Format(time.RFC3339Nano)
	}
	return out
}

func (f *fake) list(w http.ResponseWriter, r *http.Request, parent string) {
	var ids []string
	for k, s := range f.secrets {
		if s.parent == parent {
			ids = append(ids, k)
		}
	}
	slices.Sort(ids)
	size := f.pageSize
	if n, err := strconv.Atoi(r.URL.Query().Get("pageSize")); err == nil && n > 0 && n < size {
		size = n
	}
	start := 0
	if tok := r.URL.Query().Get("pageToken"); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n > len(ids) {
			gErr(w, 400, "INVALID_ARGUMENT", "Invalid page token.")
			return
		}
		start = n
	}
	end := min(start+size, len(ids))
	var out []map[string]any
	for _, k := range ids[start:end] {
		out = append(out, f.render(f.secrets[k]))
	}
	resp := map[string]any{"totalSize": len(ids)}
	if len(out) > 0 {
		resp["secrets"] = out
	}
	if end < len(ids) {
		resp["nextPageToken"] = strconv.Itoa(end)
	}
	writeJSON(w, 200, resp)
}

func (f *fake) checkMeta(w http.ResponseWriter, labels, annotations map[string]string) bool {
	for k, v := range labels {
		if !fakeLabelKey.MatchString(k) || !fakeLabelValue.MatchString(v) {
			gErr(w, 400, "INVALID_ARGUMENT", "Invalid label: "+k)
			return false
		}
	}
	total := 0
	for k, v := range annotations {
		if !fakeAnnKey.MatchString(k) {
			gErr(w, 400, "INVALID_ARGUMENT", "Invalid annotation key: "+k)
			return false
		}
		total += len(k) + len(v)
	}
	if total > 16384 {
		gErr(w, 400, "INVALID_ARGUMENT", "Annotations exceed 16 KiB.")
		return false
	}
	return true
}

func (f *fake) create(w http.ResponseWriter, r *http.Request, parent string, regional bool) {
	id := r.URL.Query().Get("secretId")
	if !fakeIDPattern.MatchString(id) {
		gErr(w, 400, "INVALID_ARGUMENT", "Secret ID ["+id+"] is invalid.")
		return
	}
	if strings.HasPrefix(id, f.denyPfx) {
		gErr(w, 403, "PERMISSION_DENIED", "Permission 'secretmanager.secrets.create' denied for resource '"+f.name(parent)+"' (or it may not exist).")
		return
	}
	var body struct {
		Replication map[string]any    `json:"replication"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		gErr(w, 400, "INVALID_ARGUMENT", "Invalid JSON payload received.")
		return
	}
	switch {
	case regional && body.Replication != nil:
		gErr(w, 400, "INVALID_ARGUMENT", "Replication policy is not supported for regional secrets.")
		return
	case !regional && body.Replication == nil:
		gErr(w, 400, "INVALID_ARGUMENT", "Replication policy is required.")
		return
	}
	if !f.checkMeta(w, body.Labels, body.Annotations) {
		return
	}
	if f.secrets[parent+"/"+id] != nil {
		gErr(w, 409, "ALREADY_EXISTS", "Secret ["+f.name(parent)+"/secrets/"+id+"] already exists.")
		return
	}
	s := &fakeSecret{parent: parent, id: id, created: time.Now().UTC(), labels: body.Labels, annotations: body.Annotations, replication: body.Replication}
	f.secrets[parent+"/"+id] = s
	writeJSON(w, 200, f.render(s))
}

func (f *fake) addVersion(w http.ResponseWriter, r *http.Request, parent, id string) {
	if strings.HasPrefix(id, f.denyPfx) {
		gErr(w, 403, "PERMISSION_DENIED", "Permission 'secretmanager.versions.add' denied for resource '"+f.name(parent)+"/secrets/"+id+"' (or it may not exist).")
		return
	}
	s := f.secret(w, parent, id)
	if s == nil {
		return
	}
	if f.denyVers != "" && strings.HasPrefix(id, f.denyVers) {
		gErr(w, 403, "PERMISSION_DENIED", "Permission 'secretmanager.versions.add' denied for resource '"+f.name(parent)+"/secrets/"+id+"'.")
		return
	}
	var body struct {
		Payload struct {
			Data       []byte  `json:"data"` // base64 in JSON
			DataCrc32c *string `json:"dataCrc32c"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		gErr(w, 400, "INVALID_ARGUMENT", "Invalid JSON payload received.")
		return
	}
	if len(body.Payload.Data) > 65536 {
		gErr(w, 400, "INVALID_ARGUMENT", "Secret payload cannot exceed 65536 bytes.")
		return
	}
	if body.Payload.DataCrc32c != nil {
		want, err := strconv.ParseUint(*body.Payload.DataCrc32c, 10, 64)
		if err != nil || uint64(crc32.Checksum(body.Payload.Data, crc32.MakeTable(crc32.Castagnoli))) != want {
			gErr(w, 400, "INVALID_ARGUMENT", "Checksum mismatch.")
			return
		}
	}
	v := &fakeVersion{num: len(s.versions) + 1, data: body.Payload.Data, state: "ENABLED", created: time.Now().UTC()}
	s.versions = append(s.versions, v)
	writeJSON(w, 200, f.renderVersion(s, v))
}

func (f *fake) patch(w http.ResponseWriter, r *http.Request, parent, id string) {
	s := f.secret(w, parent, id)
	if s == nil {
		return
	}
	var body struct {
		Labels         map[string]string `json:"labels"`
		Annotations    map[string]string `json:"annotations"`
		VersionAliases map[string]string `json:"versionAliases"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		gErr(w, 400, "INVALID_ARGUMENT", "Invalid JSON payload received.")
		return
	}
	mask := r.URL.Query().Get("updateMask")
	if mask == "" {
		gErr(w, 400, "INVALID_ARGUMENT", "update_mask is required.")
		return
	}
	for _, field := range strings.Split(mask, ",") {
		switch field {
		case "labels":
			if !f.checkMeta(w, body.Labels, nil) {
				return
			}
			s.labels = body.Labels
		case "annotations":
			if !f.checkMeta(w, nil, body.Annotations) {
				return
			}
			s.annotations = body.Annotations
		case "versionAliases", "version_aliases":
			al := map[string]int{}
			for k, v := range body.VersionAliases {
				n, err := strconv.Atoi(v)
				if !fakeAlias.MatchString(k) || err != nil || n < 1 || n > len(s.versions) {
					gErr(w, 400, "INVALID_ARGUMENT", "Invalid version alias: "+k)
					return
				}
				al[k] = n
			}
			s.aliases = al
		default:
			gErr(w, 400, "INVALID_ARGUMENT", "Invalid update mask path: "+field)
			return
		}
	}
	writeJSON(w, 200, f.render(s))
}

// resolveVersion finds a version by number, "latest" or alias.
func (s *fakeSecret) resolveVersion(v string) *fakeVersion {
	if v == "latest" {
		if len(s.versions) == 0 {
			return nil
		}
		return s.versions[len(s.versions)-1]
	}
	if n, ok := s.aliases[v]; ok {
		v = strconv.Itoa(n)
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > len(s.versions) {
		return nil
	}
	return s.versions[n-1]
}

func (f *fake) version(w http.ResponseWriter, r *http.Request, parent, id, ver, verb string) {
	s := f.secret(w, parent, id)
	if s == nil {
		return
	}
	v := s.resolveVersion(ver)
	if v == nil {
		gErr(w, 404, "NOT_FOUND", "Secret Version ["+f.name(parent)+"/secrets/"+id+"/versions/"+ver+"] not found.")
		return
	}
	switch {
	case verb == "" && r.Method == http.MethodGet:
		writeJSON(w, 200, f.renderVersion(s, v))
	case verb == "access" && r.Method == http.MethodGet:
		if v.state != "ENABLED" {
			gErr(w, 400, "FAILED_PRECONDITION", "Secret Version ["+f.name(parent)+"/secrets/"+id+"/versions/"+strconv.Itoa(v.num)+"] is in "+v.state+" state.")
			return
		}
		f.accesses++
		sum := crc32.Checksum(v.data, crc32.MakeTable(crc32.Castagnoli))
		if f.corrupt {
			sum++
		}
		writeJSON(w, 200, map[string]any{
			"name": f.name(parent) + "/secrets/" + id + "/versions/" + strconv.Itoa(v.num),
			"payload": map[string]any{
				"data":       base64.StdEncoding.EncodeToString(v.data),
				"dataCrc32c": strconv.FormatUint(uint64(sum), 10),
			},
		})
	case (verb == "disable" || verb == "enable" || verb == "destroy") && r.Method == http.MethodPost:
		v.state = map[string]string{"disable": "DISABLED", "enable": "ENABLED", "destroy": "DESTROYED"}[verb]
		if verb == "destroy" {
			v.data = nil
		}
		writeJSON(w, 200, f.renderVersion(s, v))
	default:
		gErr(w, 404, "NOT_FOUND", "Requested entity was not found.")
	}
}

// --- token endpoints -------------------------------------------------------

// oauthToken is Google's OAuth token endpoint for a service account key:
// a JWT bearer grant whose assertion is signed with the key.
func (f *fake) oauthToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwtSeen++
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	claims, ok := verifyJWT(r.Form.Get("assertion"), &f.saKey.PublicKey)
	if !ok || claims["iss"] != f.saEmail || claims["aud"] != f.srv.URL+"/token" || !strings.Contains(fmt.Sprint(claims["scope"]), scope) {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": f.issueLocked(), "expires_in": 3599, "token_type": "Bearer"})
}

func verifyJWT(tok string, pub *rsa.PublicKey) (map[string]any, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, false
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) != nil {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil, false
	}
	return claims, true
}

// sts is Google's Security Token Service: it exchanges a federated subject
// token for a Google access token (workload identity federation).
func (f *fake) sts(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stsSeen++
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		r.Form.Get("audience") != f.stsAud || r.Form.Get("subject_token") != f.stsToken ||
		!strings.Contains(r.Form.Get("scope"), scope) {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "The audience or subject token is invalid."})
		return
	}
	writeJSON(w, 200, map[string]any{
		"access_token":      f.issueLocked(),
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        3600,
	})
}

// generateAccessToken is IAM Credentials: a caller allowed to act as the
// service account gets a token for it.
func (f *fake) generateAccessToken(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.impSeen++
	rest := r.PathValue("rest")
	acct, ok := strings.CutPrefix(rest, "projects/-/serviceAccounts/")
	acct, ok2 := strings.CutSuffix(acct, ":generateAccessToken")
	if !ok || !ok2 {
		gErr(w, 404, "NOT_FOUND", "Not found.")
		return
	}
	if !f.tokens[tok] {
		gErr(w, 401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
		return
	}
	if !f.impAllow[acct] {
		gErr(w, 403, "PERMISSION_DENIED", "Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).")
		return
	}
	var body struct {
		Scope    []string `json:"scope"`
		Lifetime string   `json:"lifetime"`
	}
	b, _ := io.ReadAll(r.Body)
	if json.Unmarshal(b, &body) != nil || !slices.Contains(body.Scope, scope) {
		gErr(w, 400, "INVALID_ARGUMENT", "Scope is required.")
		return
	}
	writeJSON(w, 200, map[string]any{"accessToken": f.issueLocked(), "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
}

// metadata is the GCE/GKE metadata server's token and project endpoints.
func (f *fake) metadata(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Metadata-Flavor") != "Google" || !f.meta {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Metadata-Flavor", "Google")
	switch r.PathValue("rest") {
	case "instance/service-accounts/default/token":
		f.metaSeen++
		writeJSON(w, 200, map[string]any{"access_token": f.issueLocked(), "expires_in": 3599, "token_type": "Bearer"})
	case "project/project-id":
		_, _ = io.WriteString(w, f.project)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// --- helpers for tests -----------------------------------------------------

// put stores a secret with one version directly, as another client would.
func (f *fake) put(parent, id string, data []byte) *fakeSecret {
	f.mu.Lock()
	defer f.mu.Unlock()
	if parent == "" {
		parent = "projects/" + f.project
	}
	s := f.secrets[parent+"/"+id]
	if s == nil {
		s = &fakeSecret{parent: parent, id: id, created: time.Now().UTC(), replication: map[string]any{"automatic": map[string]any{}}}
		if strings.Contains(parent, "/locations/") {
			s.replication = nil
		}
		f.secrets[parent+"/"+id] = s
	}
	s.versions = append(s.versions, &fakeVersion{num: len(s.versions) + 1, data: append([]byte{}, data...), state: "ENABLED", created: time.Now().UTC()})
	return s
}

func (f *fake) edit(parent, id string, fn func(*fakeSecret)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if parent == "" {
		parent = "projects/" + f.project
	}
	fn(f.secrets[parent+"/"+id])
}

func (f *fake) remove(parent, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if parent == "" {
		parent = "projects/" + f.project
	}
	delete(f.secrets, parent+"/"+id)
}

func (f *fake) ids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.secrets))
}

// host is the fake's host:port, for GCE_METADATA_HOST.
func (f *fake) host() string {
	u, _ := url.Parse(f.srv.URL)
	return net.JoinHostPort(u.Hostname(), u.Port())
}
