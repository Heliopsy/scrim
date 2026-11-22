// SPDX-License-Identifier: AGPL-3.0-only

// Package vwtest runs a throwaway Vaultwarden server in rootless podman and
// bootstraps test accounts on it through the public API, deriving every key
// client-side exactly as a Bitwarden client does. It is for tests only.
//
// The container is named scrim-vw-<random> (the prefix can be changed with
// SCRIM_VW_CONTAINER_PREFIX), uses volatile storage and is removed, with its
// anonymous volumes, when the test ends. Tests skip with a
// reason when podman is not available or SCRIM_TEST_PODMAN=0.
package vwtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// DefaultImage is the Vaultwarden image the suite runs against. Override it
// with SCRIM_VW_IMAGE.
const DefaultImage = "docker.io/vaultwarden/server:1.37.5"

// Server is a running Vaultwarden container.
type Server struct {
	Name string
	URL  string
}

// RandHex returns n random bytes as hex.
func RandHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Start runs a Vaultwarden container and waits until it answers. It skips
// the test when podman is unavailable or the image cannot be pulled, unless
// SCRIM_TEST_PODMAN=1 demands the run.
func Start(t testing.TB) *Server {
	t.Helper()
	if os.Getenv("SCRIM_TEST_PODMAN") == "0" {
		t.Skip("SCRIM_TEST_PODMAN=0: skipping the Vaultwarden conformance run")
	}
	if testing.Short() {
		t.Skip("-short: skipping the Vaultwarden conformance run, which needs podman")
	}
	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman not found on PATH: skipping the Vaultwarden conformance run")
	}
	if out, err := exec.Command(podman, "info", "--format", "{{.Host.Security.Rootless}}").CombinedOutput(); err != nil {
		t.Skipf("podman is not usable (%v): skipping the Vaultwarden conformance run", strings.TrimSpace(string(out)))
	}
	image := os.Getenv("SCRIM_VW_IMAGE")
	if image == "" {
		image = DefaultImage
	}
	if exec.Command(podman, "image", "exists", image).Run() != nil {
		if out, err := exec.Command(podman, "pull", "-q", image).CombinedOutput(); err != nil {
			if os.Getenv("SCRIM_TEST_PODMAN") == "1" {
				t.Fatalf("podman pull %s: %v: %s", image, err, out)
			}
			t.Skipf("cannot pull %s (%v); set SCRIM_TEST_PODMAN=1 to make this a failure", image, err)
		}
	}
	prefix := os.Getenv("SCRIM_VW_CONTAINER_PREFIX")
	if prefix == "" {
		prefix = "scrim-vw-"
	}
	name := prefix + RandHex(t, 4)
	args := []string{"run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::80",
		"-e", "SIGNUPS_ALLOWED=true", "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true",
		"-e", "LOGIN_RATELIMIT_MAX_BURST=1000", "-e", "LOGIN_RATELIMIT_SECONDS=1",
		"-e", "ADMIN_RATELIMIT_MAX_BURST=1000",
		image}
	if out, err := exec.Command(podman, args...).CombinedOutput(); err != nil {
		t.Fatalf("podman run %s: %v: %s", image, err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command(podman, "rm", "-f", "-v", name).Run()
	})
	out, err := exec.Command(podman, "port", name, "80").Output()
	if err != nil {
		t.Fatalf("podman port: %v", err)
	}
	hostport := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	s := &Server{Name: name, URL: "http://" + hostport}
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(s.URL + "/alive")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command(podman, "logs", name).CombinedOutput()
			t.Fatalf("vaultwarden did not become ready: %v\n%s", err, logs)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Account is a bootstrapped test account. Password and the API key secret
// are generated at runtime.
type Account struct {
	Email        string
	Password     secret.Value
	KDF          bwcrypto.KDFParams
	UserID       string
	ClientID     string
	ClientSecret secret.Value
	UserKey      bwcrypto.SymmetricKey
	PublicKey    string
	token        string
	server       *Server
}

func post(t testing.TB, u, token string, body any, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	do(t, req, out)
}

func do(t testing.TB, req *http.Request, out any) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s %s: HTTP %d: %.300s", req.Method, req.URL.Path, resp.StatusCode, data)
	}
	if out == nil {
		return
	}
	if s, ok := out.(*string); ok {
		*s = string(data)
		return
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("%s %s: decode: %v", req.Method, req.URL.Path, err)
	}
}

func expose(v secret.Value) string {
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

// Register creates an account with the given KDF, logs in with the
// password, and creates a personal API key for it.
func (s *Server) Register(t testing.TB, kdf bwcrypto.KDFParams) *Account {
	t.Helper()
	a := &Account{
		Email:    "agent-" + RandHex(t, 4) + "@example.com",
		Password: secret.FromString("pw-" + RandHex(t, 16)),
		KDF:      kdf,
		server:   s,
	}
	reg, err := bwcrypto.NewRegistration(a.Password, a.Email, kdf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Wipe)
	var token string
	post(t, s.URL+"/identity/accounts/register/send-verification-email", "",
		map[string]any{"email": a.Email, "name": "scrim test", "receiveMarketingEmails": false}, &token)
	token = strings.Trim(strings.TrimSpace(token), `"`)
	body := map[string]any{
		"email":                  a.Email,
		"emailVerificationToken": token,
		"masterPasswordHash":     expose(reg.MasterPasswordHash),
		"masterPasswordHint":     nil,
		"userSymmetricKey":       reg.ProtectedUserKey.String(),
		"userAsymmetricKeys": map[string]string{
			"publicKey":           reg.Keys.PublicKey,
			"encryptedPrivateKey": reg.Keys.EncryptedPrivateKey.String(),
		},
		"kdf":            int(kdf.Type),
		"kdfIterations":  kdf.Iterations,
		"kdfMemory":      nullIfZero(kdf.MemoryMiB),
		"kdfParallelism": nullIfZero(kdf.Parallelism),
	}
	post(t, s.URL+"/identity/accounts/register/finish", "", body, nil)
	a.UserKey = reg.UserKey
	a.PublicKey = reg.Keys.PublicKey

	form := url.Values{
		"grant_type": {"password"}, "scope": {"api offline_access"}, "client_id": {"web"},
		"username": {a.Email}, "password": {expose(reg.MasterPasswordHash)},
		"deviceType": {"9"}, "deviceIdentifier": {"vwtest-" + RandHex(t, 8)}, "deviceName": {"vwtest"},
	}
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/identity/connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	do(t, req, &tok)
	a.token = tok.AccessToken

	var profile struct {
		ID string `json:"id"`
	}
	req, _ = http.NewRequest(http.MethodGet, s.URL+"/api/accounts/profile", nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	do(t, req, &profile)
	a.UserID = profile.ID

	var key struct {
		APIKey string `json:"apiKey"`
	}
	post(t, s.URL+"/api/accounts/api-key", a.token, map[string]string{"masterPasswordHash": expose(reg.MasterPasswordHash)}, &key)
	a.ClientID = "user." + a.UserID
	a.ClientSecret = secret.FromString(key.APIKey)
	return a
}

func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

// Org is an organisation created by a test account.
type Org struct {
	ID           string
	Name         string
	Key          bwcrypto.SymmetricKey
	CollectionID string
}

// CreateOrg creates an organisation with one collection, owned by a.
func (a *Account) CreateOrg(t testing.TB, name, collection string) *Org {
	t.Helper()
	orgKey, err := bwcrypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := bwcrypto.ParsePublicKey(a.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := bwcrypto.EncryptRSA(pub, orgKey.Value())
	if err != nil {
		t.Fatal(err)
	}
	kp, err := bwcrypto.GenerateKeyPair(orgKey)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := orgKey.EncryptMetadata(collection)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID string `json:"id"`
	}
	post(t, a.server.URL+"/api/organizations", a.token, map[string]any{
		"name": name, "billingEmail": a.Email, "collectionName": coll.String(),
		"key": wrapped.String(), "planType": 0,
		"keys": map[string]string{"publicKey": kp.PublicKey, "encryptedPrivateKey": kp.EncryptedPrivateKey.String()},
	}, &out)
	var colls struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	req, _ := http.NewRequest(http.MethodGet, a.server.URL+"/api/organizations/"+out.ID+"/collections", nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	do(t, req, &colls)
	if len(colls.Data) != 1 {
		t.Fatalf("expected one collection, got %d", len(colls.Data))
	}
	return &Org{ID: out.ID, Name: name, Key: orgKey, CollectionID: colls.Data[0].ID}
}

// CreateCollection adds a collection to an organisation owned by a and
// returns its id.
func (a *Account) CreateCollection(t testing.TB, org *Org, name string) string {
	t.Helper()
	e, err := org.Key.EncryptMetadata(name)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID string `json:"id"`
	}
	post(t, a.server.URL+"/api/organizations/"+org.ID+"/collections", a.token,
		map[string]any{"name": e.String(), "groups": []any{}, "users": []any{}}, &out)
	return out.ID
}

// Item is a cipher to create directly through the API, bypassing the adapter.
type Item struct {
	Folder     string // personal folder name; created if missing
	Org        *Org   // organisation item when set, in its collection
	Name       string
	Username   secret.Value
	Password   secret.Value
	Notes      secret.Value
	Fields     map[string]secret.Value // hidden custom fields
	Labels     map[string]string       // text custom fields, names used as given
	ItemKey    bool                    // encrypt with a per-item key, as current clients do
	SecureNote bool
	// Collections adds the item to these collection ids of Org besides
	// the organisation's first collection.
	Collections []string
	URIs        []string // login URIs
	Favorite    bool
	Reprompt    bool
}

// CreateItem creates an item the way a Bitwarden client would, so the
// adapter is tested against data it did not write itself.
func (a *Account) CreateItem(t testing.TB, it Item) string {
	t.Helper()
	base := a.UserKey
	if it.Org != nil {
		base = it.Org.Key
	}
	key := base
	reprompt := 0
	if it.Reprompt {
		reprompt = 1
	}
	cipher := map[string]any{"type": 1, "favorite": it.Favorite, "reprompt": reprompt, "encryptedFor": a.UserID}
	if it.ItemKey {
		ik, err := bwcrypto.GenerateSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := base.Encrypt(ik.Value())
		if err != nil {
			t.Fatal(err)
		}
		cipher["key"] = wrapped.String()
		key = ik
	}
	encv := func(v secret.Value) any {
		if v.IsZero() {
			return nil
		}
		e, err := key.Encrypt(v)
		if err != nil {
			t.Fatal(err)
		}
		return e.String()
	}
	encm := func(s string) string {
		e, err := key.EncryptMetadata(s)
		if err != nil {
			t.Fatal(err)
		}
		return e.String()
	}
	cipher["name"] = encm(it.Name)
	cipher["notes"] = encv(it.Notes)
	if it.SecureNote {
		cipher["type"] = 2
		cipher["secureNote"] = map[string]int{"type": 0}
	} else {
		uris := []any{}
		for _, u := range it.URIs {
			uris = append(uris, map[string]any{"uri": encm(u), "match": nil})
		}
		cipher["login"] = map[string]any{"username": encv(it.Username), "password": encv(it.Password), "uris": uris}
	}
	var fields []map[string]any
	for n, v := range it.Fields {
		fields = append(fields, map[string]any{"type": 1, "name": encm(n), "value": encv(v)})
	}
	for n, v := range it.Labels {
		fields = append(fields, map[string]any{"type": 0, "name": encm(n), "value": encm(v)})
	}
	cipher["fields"] = fields
	if it.Folder != "" {
		cipher["folderId"] = a.folder(t, it.Folder)
	}
	var out struct {
		ID string `json:"id"`
	}
	if it.Org != nil {
		cipher["organizationId"] = it.Org.ID
		colls := append([]string{it.Org.CollectionID}, it.Collections...)
		post(t, a.server.URL+"/api/ciphers/create", a.token, map[string]any{"cipher": cipher, "collectionIds": colls}, &out)
	} else {
		post(t, a.server.URL+"/api/ciphers", a.token, cipher, &out)
	}
	return out.ID
}

func (a *Account) folder(t testing.TB, name string) string {
	t.Helper()
	var list struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	req, _ := http.NewRequest(http.MethodGet, a.server.URL+"/api/folders", nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	do(t, req, &list)
	for _, f := range list.Data {
		if n, err := a.UserKey.DecryptMetadata(f.Name); err == nil && n == name {
			return f.ID
		}
	}
	e, err := a.UserKey.EncryptMetadata(name)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID string `json:"id"`
	}
	post(t, a.server.URL+"/api/folders", a.token, map[string]string{"name": e.String()}, &out)
	return out.ID
}

// DecryptItemField fetches an item by id and decrypts a login field or a
// custom field with the account's own keys, independently of the adapter.
func (a *Account) DecryptItemField(t testing.TB, id, field string, org *Org) secret.Value {
	t.Helper()
	var c struct {
		Key   *string `json:"key"`
		Login *struct {
			Username *string `json:"username"`
			Password *string `json:"password"`
		} `json:"login"`
		Fields []struct {
			Name  string  `json:"name"`
			Value *string `json:"value"`
		} `json:"fields"`
	}
	req, _ := http.NewRequest(http.MethodGet, a.server.URL+"/api/ciphers/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	do(t, req, &c)
	key := a.UserKey
	if org != nil {
		key = org.Key
	}
	if c.Key != nil {
		k, err := key.DecryptKey(*c.Key)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	dec := func(s *string) secret.Value {
		if s == nil {
			t.Fatalf("field %s is empty", field)
		}
		v, err := key.DecryptString(*s)
		if err != nil {
			t.Fatalf("field %s: %v", field, err)
		}
		return v
	}
	switch field {
	case "username":
		return dec(c.Login.Username)
	case "password":
		return dec(c.Login.Password)
	}
	for _, f := range c.Fields {
		if n, err := key.DecryptMetadata(f.Name); err == nil && n == field {
			return dec(f.Value)
		}
	}
	t.Fatalf("no field %s", field)
	return secret.Value{}
}

// ItemIDs lists the ids of the account's items whose decrypted name is name.
func (a *Account) ItemIDs(t testing.TB, name string, org *Org) []string {
	t.Helper()
	var sync struct {
		Ciphers []struct {
			ID             string  `json:"id"`
			Name           string  `json:"name"`
			Key            *string `json:"key"`
			OrganizationID *string `json:"organizationId"`
		} `json:"ciphers"`
	}
	req, _ := http.NewRequest(http.MethodGet, a.server.URL+"/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	do(t, req, &sync)
	var ids []string
	for _, c := range sync.Ciphers {
		key := a.UserKey
		if c.OrganizationID != nil {
			if org == nil || *c.OrganizationID != org.ID {
				continue
			}
			key = org.Key
		}
		if c.Key != nil {
			k, err := key.DecryptKey(*c.Key)
			if err != nil {
				continue
			}
			key = k
		}
		if n, err := key.DecryptMetadata(c.Name); err == nil && n == name {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// WriteSecretFile writes v to a new 0600 file under dir and returns its path.
func WriteSecretFile(t testing.TB, dir string, v secret.Value) string {
	t.Helper()
	f, err := os.CreateTemp(dir, "vw-unlock-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Expose(func(b []byte) error { _, err := f.Write(b); return err }); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// Ctx returns a context bounded by d that ends with the test.
func Ctx(t testing.TB, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
