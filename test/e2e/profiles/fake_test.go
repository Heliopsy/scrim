// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package profiles

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"strings"
	"sync"
)

// fakeAPIs stands in for every API the tool profile tests talk to, by
// host. Each endpoint accepts only the real credential, so a request that
// reaches it with a placeholder fails, and records what it received.
type fakeAPIs struct {
	vals map[string]string // secret name -> real value
	git  http.Handler

	mu   sync.Mutex
	hits map[string]int    // host -> requests authenticated with the real value
	seen map[string]string // host -> last Authorization header
	// azToken is the access token the fake Entra ID hands out.
	azToken string
}

func newFake(vals map[string]string, git http.Handler) *fakeAPIs {
	return &fakeAPIs{vals: vals, git: git, hits: map[string]int{}, seen: map[string]string{}, azToken: "fake-entra-access-token"}
}

func (f *fakeAPIs) ok(host string) {
	f.mu.Lock()
	f.hits[host]++
	f.mu.Unlock()
}

func (f *fakeAPIs) count(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[host]
}

func (f *fakeAPIs) lastAuth(host string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[host]
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func deny(w http.ResponseWriter, scheme string) {
	if scheme != "" {
		w.Header().Set("WWW-Authenticate", scheme+` realm="scrim e2e"`)
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
}

// bearer reports whether the request carries name's value as a bearer (or
// "token") credential.
func (f *fakeAPIs) bearer(r *http.Request, name string) bool {
	a := r.Header.Get("Authorization")
	v := f.vals[name]
	return a == "Bearer "+v || a == "token "+v || a == v
}

func (f *fakeAPIs) basic(r *http.Request, user, name string) bool {
	u, p, ok := r.BasicAuth()
	return ok && u == user && p == f.vals[name]
}

func (f *fakeAPIs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	f.mu.Lock()
	f.seen[host] = r.Header.Get("Authorization")
	f.mu.Unlock()
	switch host {
	case "api.github.com":
		if !f.bearer(r, "github") {
			deny(w, "")
			return
		}
		f.ok(host)
		writeJSON(w, 200, map[string]any{"login": "scrim-e2e", "id": 1, "type": "User"})
	case "github.com":
		if !f.basic(r, "x-access-token", "github") {
			deny(w, "Basic")
			return
		}
		f.ok(host)
		f.git.ServeHTTP(w, r)
	case "k8s.scrim.test":
		f.kube(w, r, host)
	case "registry.scrim.test":
		if r.URL.Path != "/v2/" && r.URL.Path != "/v2" {
			http.NotFound(w, r)
			return
		}
		if !f.basic(r, "scrim", "registry") {
			w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
			deny(w, "Basic")
			return
		}
		f.ok(host)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		writeJSON(w, 200, map[string]any{})
	case "registry.npmjs.org":
		if !f.bearer(r, "npm") {
			deny(w, "")
			return
		}
		f.ok(host)
		writeJSON(w, 200, map[string]string{"username": "scrim-e2e"})
	case "app.terraform.io":
		f.terraform(w, r, host)
	case "cloudresourcemanager.googleapis.com":
		if !f.bearer(r, "gcp") {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"code": 401, "message": "Request had invalid authentication credentials.", "status": "UNAUTHENTICATED"}})
			return
		}
		f.ok(host)
		writeJSON(w, 200, map[string]any{"projects": []map[string]string{{"projectId": "scrim-e2e", "name": "scrim-e2e",
			"projectNumber": "1234", "lifecycleState": "ACTIVE", "createTime": "2026-01-01T00:00:00Z"}}})
	case "login.microsoftonline.com":
		f.entra(w, r, host)
	case "management.azure.com":
		if r.Header.Get("Authorization") != "Bearer "+f.azToken {
			deny(w, "Bearer")
			return
		}
		f.ok(host)
		if strings.HasPrefix(r.URL.Path, "/tenants") {
			writeJSON(w, 200, map[string]any{"value": []map[string]string{{"id": "/tenants/" + tenantID, "tenantId": tenantID}}})
			return
		}
		writeJSON(w, 200, map[string]any{"value": []map[string]any{{"id": "/subscriptions/" + subscriptionID, "subscriptionId": subscriptionID,
			"tenantId": tenantID, "displayName": "scrim-e2e", "state": "Enabled"}}})
	case "pypi.scrim.test":
		if !f.basic(r, "__token__", "pypi") {
			deny(w, "Basic")
			return
		}
		f.ok(host)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<!DOCTYPE html><html><body>
<a href="/files/scrim_e2e-1.2.3-py3-none-any.whl">scrim_e2e-1.2.3-py3-none-any.whl</a>
</body></html>`)
	case "upload.pypi.org":
		if !f.basic(r, "__token__", "pypi-upload") {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, "Invalid or non-existent authentication information.")
			return
		}
		_ = r.ParseMultipartForm(1 << 20)
		f.ok(host)
		_, _ = io.WriteString(w, "OK")
	case "index.crates.io":
		if r.URL.Path == "/config.json" {
			writeJSON(w, 200, map[string]any{"dl": "https://static.crates.io/crates", "api": "https://crates.io"})
			return
		}
		http.NotFound(w, r)
	case "crates.io":
		if !f.bearer(r, "crates") {
			writeJSON(w, 403, map[string]any{"errors": []map[string]string{{"detail": "authentication failed"}}})
			return
		}
		f.ok(host)
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "api.hetzner.cloud":
		if !f.bearer(r, "hcloud") {
			writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthorized", "message": "unable to authenticate"}})
			return
		}
		f.ok(host)
		writeJSON(w, 200, map[string]any{"servers": []any{}, "meta": map[string]any{"pagination": map[string]any{
			"page": 1, "per_page": 50, "previous_page": nil, "next_page": nil, "last_page": 1, "total_entries": 0}}})
	case "api.digitalocean.com":
		if !f.bearer(r, "digitalocean") {
			writeJSON(w, 401, map[string]string{"id": "Unauthorized", "message": "Unable to authenticate you"})
			return
		}
		f.ok(host)
		writeJSON(w, 200, map[string]any{"account": map[string]any{"email": "e2e@scrim.test", "uuid": "e2e", "status": "active",
			"droplet_limit": 1, "floating_ip_limit": 1, "email_verified": true}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAPIs) kube(w http.ResponseWriter, r *http.Request, host string) {
	if !f.bearer(r, "k8s") {
		writeJSON(w, 401, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "Unauthorized", "reason": "Unauthorized", "code": 401})
		return
	}
	f.ok(host)
	list := func(kind string) map[string]any {
		return map[string]any{"kind": kind, "apiVersion": "v1", "metadata": map[string]string{"resourceVersion": "1"}, "items": []any{}}
	}
	switch {
	case r.URL.Path == "/version":
		writeJSON(w, 200, map[string]string{"major": "1", "minor": "34", "gitVersion": "v1.34.0", "platform": "linux/amd64"})
	case strings.HasSuffix(r.URL.Path, "/pods"):
		l := list("PodList")
		l["items"] = []any{map[string]any{"metadata": map[string]string{"name": "scrim-e2e", "namespace": "default"}}}
		writeJSON(w, 200, l)
	case strings.HasSuffix(r.URL.Path, "/secrets"):
		writeJSON(w, 200, list("SecretList"))
	default:
		writeJSON(w, 404, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404})
	}
}

// terraform is a module registry with one module, scrim/e2e/null 1.0.0.
func (f *fakeAPIs) terraform(w http.ResponseWriter, r *http.Request, host string) {
	switch r.URL.Path {
	case "/.well-known/terraform.json":
		writeJSON(w, 200, map[string]string{"modules.v1": "/api/registry/v1/modules/"})
		return
	case "/files/null.tar.gz":
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(moduleTarball())
		return
	}
	if !f.bearer(r, "terraform") {
		writeJSON(w, 401, map[string]any{"errors": []string{"unauthorized"}})
		return
	}
	f.ok(host)
	switch r.URL.Path {
	case "/api/registry/v1/modules/scrim/e2e/null/versions":
		writeJSON(w, 200, map[string]any{"modules": []any{map[string]any{"versions": []any{map[string]string{"version": "1.0.0"}}}}})
	case "/api/registry/v1/modules/scrim/e2e/null/1.0.0/download":
		w.Header().Set("X-Terraform-Get", "https://app.terraform.io/files/null.tar.gz")
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func moduleTarball() []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("output \"ok\" {\n  value = \"scrim\"\n}\n")
	_ = tw.WriteHeader(&tar.Header{Name: "main.tf", Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

const (
	tenantID       = "00000000-0000-0000-0000-00000000e2e0"
	subscriptionID = "00000000-0000-0000-0000-00000000e2e1"
	clientID       = "00000000-0000-0000-0000-00000000e2e2"
)

// entra is enough of Microsoft Entra ID for MSAL's client credentials flow.
func (f *fakeAPIs) entra(w http.ResponseWriter, r *http.Request, host string) {
	base := "https://login.microsoftonline.com/" + tenantID
	switch {
	case strings.HasSuffix(r.URL.Path, "/discovery/instance"):
		writeJSON(w, 200, map[string]any{
			"tenant_discovery_endpoint": base + "/v2.0/.well-known/openid-configuration",
			"api-version":               "1.1",
			"metadata": []any{map[string]any{"preferred_network": "login.microsoftonline.com", "preferred_cache": "login.microsoftonline.com",
				"aliases": []string{"login.microsoftonline.com"}}},
		})
	case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
		writeJSON(w, 200, map[string]any{
			"token_endpoint":                        base + "/oauth2/v2.0/token",
			"authorization_endpoint":                base + "/oauth2/v2.0/authorize",
			"device_authorization_endpoint":         base + "/oauth2/v2.0/devicecode",
			"issuer":                                "https://login.microsoftonline.com/" + tenantID + "/v2.0",
			"jwks_uri":                              base + "/discovery/v2.0/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"pairwise"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		_ = r.ParseForm()
		if r.PostForm.Get("client_secret") != f.vals["azure"] {
			writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})
			return
		}
		f.ok(host)
		writeJSON(w, 200, map[string]any{"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": f.azToken})
	default:
		http.NotFound(w, r)
	}
}

// wheel builds a minimal wheel for twine to upload.
func wheel() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"scrim_e2e/__init__.py":                   "",
		"scrim_e2e-1.2.3.dist-info/METADATA":      "Metadata-Version: 2.1\nName: scrim-e2e\nVersion: 1.2.3\nSummary: scrim e2e\n",
		"scrim_e2e-1.2.3.dist-info/WHEEL":         "Wheel-Version: 1.0\nGenerator: scrim-e2e\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		"scrim_e2e-1.2.3.dist-info/top_level.txt": "scrim_e2e\n",
	}
	var record strings.Builder
	for _, name := range []string{"scrim_e2e/__init__.py", "scrim_e2e-1.2.3.dist-info/METADATA", "scrim_e2e-1.2.3.dist-info/WHEEL", "scrim_e2e-1.2.3.dist-info/top_level.txt"} {
		fw, _ := zw.Create(name)
		_, _ = io.WriteString(fw, files[name])
		fmt.Fprintf(&record, "%s,,\n", name)
	}
	fw, _ := zw.Create("scrim_e2e-1.2.3.dist-info/RECORD")
	_, _ = io.WriteString(fw, record.String()+"scrim_e2e-1.2.3.dist-info/RECORD,,\n")
	_ = zw.Close()
	return buf.Bytes()
}

// gitBackend serves the repositories under root with git http-backend.
func gitBackend(backend, root string) http.Handler {
	return &cgi.Handler{Path: backend, Root: "/",
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1"}}
}
