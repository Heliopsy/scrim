// SPDX-License-Identifier: AGPL-3.0-only

package doppler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an in-memory Doppler speaking the subset of the v3 API the adapter
// uses. Its response shapes follow the fixtures in testdata, which are the
// examples from Doppler's API reference (docs.doppler.com/reference) and the
// field types the Doppler CLI decodes (github.com/DopplerHQ/cli,
// pkg/models). TestFakeMatchesFixtures keeps the two in step.
//
// Fidelity limits (no Doppler test account was available, so none of this is
// checked against the live service; docs/stores/doppler.md repeats them):
//
//   - Error message texts are modelled on the CLI's handling of the
//     {"messages": [...], "success": false} envelope; the exact wording and
//     the status Doppler picks for some refusals (a change request that
//     creates an existing secret, a name the naming mode rejects) are
//     assumptions. The adapter only relies on the status class.
//   - Secret references resolve ${NAME}, ${config.NAME} and
//     ${project.config.NAME} recursively; Doppler's quoting of dotted names
//     (${"a.b"}) and dynamic secrets are not modelled.
//   - The ETag is a hash of the download body; Doppler's is opaque.
//   - Rate limits, pagination and trusted IPs are not modelled.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	down       bool
	permissive bool // Permissive secret naming
	tokens     map[string]*fakeToken
	workplace  struct{ slug, name string }
	// configs by "<project>/<config>".
	configs map[string]*fakeConfig
	// requests records every request as "METHOD path".
	requests []string
	// valueResponses counts responses that carried secret values.
	valueResponses int
	// echoValue makes a refused write quote the value back.
	echoValue bool
	// hiddenConfigs refuses GET /v3/configs/config for these configs, as
	// for a token that may read secrets but not describe the config.
	hiddenConfigs map[string]bool
}

type fakeToken struct {
	kind    string // "service_token", "service_account", "personal"
	project string // service tokens: the one config they open
	config  string
	write   bool
}

type fakeConfig struct {
	project     string
	name        string
	environment string
	root        bool
	locked      bool
	secrets     map[string]*fakeSecret
}

type fakeSecret struct {
	raw        string
	visibility string
	valueType  string
	note       string
}

func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const (
	tokSA         = "sa"
	tokPersonal   = "personal"
	tokServiceRO  = "service-ro"
	tokServiceDev = "service-dev"
)

// newFake starts a fake workplace with project "billing" holding the root
// configs dev and prd and the branch config dev_feature. Tokens: a service
// account token with write access to every dev config and read access to
// prd, a personal token with the same access, a read-only service token for
// billing/prd and a read/write service token for billing/dev.
func newFake(t *testing.T) (*fake, map[string]string) {
	f := &fake{
		t:             t,
		permissive:    true,
		tokens:        map[string]*fakeToken{},
		configs:       map[string]*fakeConfig{},
		hiddenConfigs: map[string]bool{},
	}
	f.workplace.slug, f.workplace.name = "2faa85f6610102d983522", "Doppler University"
	for _, c := range []fakeConfig{
		{project: "billing", name: "dev", environment: "dev", root: true},
		{project: "billing", name: "dev_feature", environment: "dev"},
		{project: "billing", name: "prd", environment: "prd", root: true, locked: true},
	} {
		c.secrets = map[string]*fakeSecret{}
		f.configs[c.project+"/"+c.name] = &c
	}
	toks := map[string]string{
		tokSA:         "dp.sa." + randID(20),
		tokPersonal:   "dp.pt." + randID(20),
		tokServiceRO:  "dp.st.prd." + randID(20),
		tokServiceDev: "dp.st.dev." + randID(20),
	}
	f.tokens[toks[tokSA]] = &fakeToken{kind: "service_account", write: true}
	f.tokens[toks[tokPersonal]] = &fakeToken{kind: "personal", write: true}
	f.tokens[toks[tokServiceRO]] = &fakeToken{kind: "service_token", project: "billing", config: "prd"}
	f.tokens[toks[tokServiceDev]] = &fakeToken{kind: "service_token", project: "billing", config: "dev", write: true}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v3/me", f.auth(f.me))
	mux.HandleFunc("GET /v3/configs/config", f.auth(f.config))
	mux.HandleFunc("GET /v3/configs/config/secret", f.auth(f.get))
	mux.HandleFunc("GET /v3/configs/config/secrets/names", f.auth(f.names))
	mux.HandleFunc("GET /v3/configs/config/secrets/download", f.auth(f.download))
	mux.HandleFunc("POST /v3/configs/config/secrets", f.auth(f.update))
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		down := f.down
		f.mu.Unlock()
		if down {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("<html>503 Service Unavailable</html>"))
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f, toks
}

func (f *fake) setDown(d bool) {
	f.mu.Lock()
	f.down = d
	f.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"messages": []string{msg}, "success": false})
}

type tokenHandler func(w http.ResponseWriter, r *http.Request, tok *fakeToken)

func (f *fake) auth(h tokenHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		tok := f.tokens[bearer]
		f.mu.Unlock()
		if !ok || tok == nil {
			apiErr(w, http.StatusUnauthorized, "Invalid Auth token")
			return
		}
		h(w, r, tok)
	}
}

// configFor finds the config a request names, enforcing a service token's
// scope. It answers the error itself and returns nil when there is none.
func (f *fake) configFor(w http.ResponseWriter, project, config string, tok *fakeToken, write bool) *fakeConfig {
	if tok.kind == "service_token" {
		// A service token's project and config are implied; naming
		// another is refused.
		if project == "" && config == "" {
			project, config = tok.project, tok.config
		}
		if project != tok.project || config != tok.config {
			apiErr(w, http.StatusForbidden, "This token does not have access to requested config")
			return nil
		}
	}
	if project == "" {
		apiErr(w, http.StatusBadRequest, "Missing project")
		return nil
	}
	c := f.configs[project+"/"+config]
	if c == nil {
		apiErr(w, http.StatusNotFound, "Could not find requested config '"+config+"'")
		return nil
	}
	if write && (!tok.write || (tok.kind != "service_token" && c.environment == "prd")) {
		apiErr(w, http.StatusForbidden, "You do not have sufficient access to perform this action")
		return nil
	}
	return c
}

func (f *fake) me(w http.ResponseWriter, _ *http.Request, tok *fakeToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"slug":          "5ba6e0fd-a80a-4c39-9e85-3d5230d44e62",
		"name":          "scrim",
		"created_at":    "2023-06-15T20:17:33.539Z",
		"last_seen_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"type":          tok.kind,
		"token_preview": "dp.xx...b8aked",
		"workplace":     map[string]any{"slug": f.workplace.slug, "name": f.workplace.name},
	})
}

func (f *fake) config(w http.ResponseWriter, r *http.Request, tok *fakeToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	c := f.configFor(w, q.Get("project"), q.Get("config"), tok, false)
	if c == nil {
		return
	}
	if f.hiddenConfigs[c.project+"/"+c.name] {
		apiErr(w, http.StatusForbidden, "You do not have sufficient access to perform this action")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": map[string]any{
		"name":             c.name,
		"root":             c.root,
		"locked":           c.locked,
		"initial_fetch_at": "2019-11-19T07:32:12.000Z",
		"last_fetch_at":    "2019-11-19T07:36:10.980Z",
		"created_at":       "2019-11-19T07:19:00.480Z",
		"environment":      c.environment,
		"project":          c.project,
	}})
}

var managed = []string{"DOPPLER_CONFIG", "DOPPLER_ENVIRONMENT", "DOPPLER_PROJECT"}

// lookup returns the raw value of name in c, managed secrets included.
func (f *fake) lookup(c *fakeConfig, name string) (*fakeSecret, bool) {
	switch name {
	case "DOPPLER_PROJECT":
		return &fakeSecret{raw: c.project, visibility: "unmasked", valueType: "string"}, true
	case "DOPPLER_CONFIG":
		return &fakeSecret{raw: c.name, visibility: "unmasked", valueType: "string"}, true
	case "DOPPLER_ENVIRONMENT":
		return &fakeSecret{raw: c.environment, visibility: "unmasked", valueType: "string"}, true
	}
	s, ok := c.secrets[name]
	return s, ok
}

var refPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_/:.\-]+)\}`)

// compute resolves secret references as Doppler does at read time: an
// unresolvable reference stays as written. It reports the computed
// visibility (restricted when anything it references is).
func (f *fake) compute(c *fakeConfig, raw, vis string, depth int) (string, string) {
	if depth > 8 {
		return raw, vis
	}
	out := refPattern.ReplaceAllStringFunc(raw, func(m string) string {
		path := strings.Split(m[2:len(m)-1], ".")
		target, name := c, path[len(path)-1]
		switch len(path) {
		case 2:
			target = f.configs[c.project+"/"+path[0]]
		case 3:
			target = f.configs[path[0]+"/"+path[1]]
		}
		if target == nil {
			return m
		}
		s, ok := f.lookup(target, name)
		if !ok {
			return m
		}
		v, sv := f.compute(target, s.raw, s.visibility, depth+1)
		if sv == "restricted" {
			vis = "restricted"
		}
		return v
	})
	return out, vis
}

func (f *fake) get(w http.ResponseWriter, r *http.Request, tok *fakeToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	c := f.configFor(w, q.Get("project"), q.Get("config"), tok, false)
	if c == nil {
		return
	}
	name := q.Get("name")
	s, ok := f.lookup(c, name)
	if !ok {
		apiErr(w, http.StatusNotFound, "Could not find requested secret")
		return
	}
	computed, cvis := f.compute(c, s.raw, s.visibility, 0)
	var rawV, compV any = s.raw, computed
	// Restricted values are returned to service and service account
	// tokens only; user tokens get null.
	if tok.kind == "personal" {
		if s.visibility == "restricted" {
			rawV = nil
		}
		if cvis == "restricted" {
			compV = nil
		}
	}
	f.valueResponses++
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name,
		"value": map[string]any{
			"raw":                rawV,
			"computed":           compV,
			"note":               s.note,
			"rawVisibility":      s.visibility,
			"computedVisibility": cvis,
			"rawValueType":       map[string]any{"type": s.valueType},
			"computedValueType":  map[string]any{"type": s.valueType},
		},
	})
}

func (f *fake) names(w http.ResponseWriter, r *http.Request, tok *fakeToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	c := f.configFor(w, q.Get("project"), q.Get("config"), tok, false)
	if c == nil {
		return
	}
	out := []string{}
	for n := range c.secrets {
		out = append(out, n)
	}
	if q.Get("include_managed_secrets") != "false" {
		out = append(out, managed...)
	}
	slices.Sort(out)
	writeJSON(w, http.StatusOK, map[string]any{"names": out})
}

func (f *fake) download(w http.ResponseWriter, r *http.Request, tok *fakeToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	c := f.configFor(w, q.Get("project"), q.Get("config"), tok, false)
	if c == nil {
		return
	}
	if q.Get("format") != "json" {
		apiErr(w, http.StatusBadRequest, "Unsupported format")
		return
	}
	out := map[string]string{}
	names := append([]string(nil), managed...)
	for n := range c.secrets {
		names = append(names, n)
	}
	for _, n := range names {
		s, _ := f.lookup(c, n)
		v, vis := f.compute(c, s.raw, s.visibility, 0)
		if vis == "restricted" && tok.kind == "personal" {
			// The CLI documents a 403 for downloads with restricted
			// secrets and a user token.
			apiErr(w, http.StatusForbidden, "Unable to download restricted secrets with a user token")
			return
		}
		out[n] = v
	}
	body, _ := json.Marshal(out)
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	f.valueResponses++
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

var (
	classicName    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	permissiveName = regexp.MustCompile(`^[A-Za-z0-9_/:.\-]+$`)
)

type fakeChange struct {
	Name         string  `json:"name"`
	OriginalName *string `json:"originalName"`
	Value        *string `json:"value"`
	Visibility   *string `json:"visibility"`
}

func (f *fake) update(w http.ResponseWriter, r *http.Request, tok *fakeToken) {
	var in struct {
		Project        string            `json:"project"`
		Config         string            `json:"config"`
		Secrets        map[string]string `json:"secrets"`
		ChangeRequests []fakeChange      `json:"change_requests"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.configFor(w, in.Project, in.Config, tok, true)
	if c == nil {
		return
	}
	if (in.Secrets == nil) == (in.ChangeRequests == nil) {
		apiErr(w, http.StatusBadRequest, "Either secrets or change_requests is required")
		return
	}
	for _, cr := range in.ChangeRequests {
		valid := classicName.MatchString(cr.Name)
		if f.permissive {
			valid = permissiveName.MatchString(cr.Name)
		}
		if !valid || len(cr.Name) > 200 || slices.Contains(managed, cr.Name) {
			msg := "Secret name is invalid"
			if f.echoValue && cr.Value != nil {
				msg = fmt.Sprintf("Secret %s with value %s is invalid", cr.Name, *cr.Value)
			}
			apiErr(w, http.StatusBadRequest, msg)
			return
		}
		_, exists := c.secrets[cr.Name]
		switch {
		case cr.OriginalName == nil && exists:
			apiErr(w, http.StatusBadRequest, "Secret "+cr.Name+" already exists")
			return
		case cr.OriginalName != nil && !exists:
			apiErr(w, http.StatusBadRequest, "Secret "+*cr.OriginalName+" does not exist")
			return
		}
	}
	for _, cr := range in.ChangeRequests {
		s := c.secrets[cr.Name]
		if s == nil {
			s = &fakeSecret{visibility: "masked", valueType: "string"}
			c.secrets[cr.Name] = s
		}
		if cr.Value != nil {
			s.raw = *cr.Value
		}
		if cr.Visibility != nil {
			s.visibility = *cr.Visibility
		}
	}
	// The response echoes every secret of the config, values included.
	out := map[string]any{}
	for n, s := range c.secrets {
		v, _ := f.compute(c, s.raw, s.visibility, 0)
		out[n] = map[string]any{"raw": s.raw, "computed": v, "note": s.note}
	}
	f.valueResponses++
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

// put stores a secret out of band.
func (f *fake) put(cfg, name, raw string, mod func(*fakeSecret)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.configs[cfg]
	if c == nil {
		f.t.Fatalf("fake: no config %s", cfg)
	}
	s := &fakeSecret{raw: raw, visibility: "masked", valueType: "string"}
	if mod != nil {
		mod(s)
	}
	c.secrets[name] = s
}

// remove deletes a secret out of band.
func (f *fake) remove(cfg, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.configs[cfg].secrets, name)
}

func (f *fake) count(req string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == req {
			n++
		}
	}
	return n
}

func (f *fake) values() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.valueResponses
}
