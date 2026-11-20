// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/vwtest"
)

// TestBitwardenCLIInterop checks that the official Bitwarden CLI decrypts an
// item scrim wrote. It needs `bw` on PATH and SCRIM_TEST_BW_CLI=1, and uses
// an isolated CLI data directory.
func TestBitwardenCLIInterop(t *testing.T) {
	if os.Getenv("SCRIM_TEST_BW_CLI") != "1" {
		t.Skip("set SCRIM_TEST_BW_CLI=1 to run the Bitwarden CLI interoperability check")
	}
	bw, err := exec.LookPath("bw")
	if err != nil {
		t.Skip("bw not found on PATH")
	}
	srv := vwtest.Start(t)
	e := newEnv(t, srv, bwcrypto.DefaultArgon2id())
	front, ca := srv.TLSFront(t)
	a := e.adapter(t, front, func(o *vaultwarden.Options) { o.CAFile = ca })
	defer func() { _ = a.Close() }()
	ctx := vwtest.Ctx(t, 60*time.Second)
	pw := secret.FromString("cli_" + vwtest.RandHex(t, 16))
	tok := secret.FromString("tok_" + vwtest.RandHex(t, 16))
	if _, err := a.Write(ctx, stores.MustParseRef("vw://Agents/Interop"), map[string]secret.Value{"password": pw, "token": tok}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	appdata := t.TempDir()
	run := func(env []string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, bw, args...)
		cmd.Env = append(os.Environ(), "BITWARDENCLI_APPDATA_DIR="+appdata, "BW_NOINTERACTION=true", "NODE_EXTRA_CA_CERTS="+ca)
		cmd.Env = append(cmd.Env, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("bw %s: %v: %s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run(nil, "config", "server", front)
	run([]string{"BW_CLIENTID=" + e.account.ClientID, "BW_CLIENTSECRET=" + expose(t, e.account.ClientSecret)}, "login", "--apikey")
	session := run([]string{"SCRIM_BW_PW=" + expose(t, e.account.Password)}, "unlock", "--passwordenv", "SCRIM_BW_PW", "--raw")
	run(nil, "sync", "--session", session)
	out := run(nil, "get", "item", "Interop", "--session", session)
	var item struct {
		Name  string `json:"name"`
		Login struct {
			Password string `json:"password"`
		} `json:"login"`
		Fields []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if err := json.Unmarshal([]byte(out), &item); err != nil {
		t.Fatalf("bw get item: not JSON")
	}
	if item.Name != "Interop" || item.Login.Password != expose(t, pw) {
		t.Fatal("bw CLI decrypted a different name or password")
	}
	if len(item.Fields) != 1 || item.Fields[0].Name != "token" || item.Fields[0].Value != expose(t, tok) {
		t.Fatal("bw CLI decrypted different custom fields")
	}
}
