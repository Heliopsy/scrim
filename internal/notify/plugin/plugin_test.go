// SPDX-License-Identifier: AGPL-3.0-only

package plugin_test

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/notify/notifytest"
	notifyplugin "github.com/heliopsy/scrim/internal/notify/plugin"
	hostplugin "github.com/heliopsy/scrim/internal/plugin"
	"github.com/heliopsy/scrim/internal/plugin/plugintest"
	"github.com/heliopsy/scrim/internal/secret"
	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

func TestMain(m *testing.M) {
	code := m.Run()
	plugintest.Cleanup()
	os.Exit(code)
}

func token(t testing.TB) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "hmac-" + hex.EncodeToString(b)
}

// line mirrors what the example plugin writes.
type line struct {
	ApprovalID  string            `json:"approval_id"`
	Agent       string            `json:"agent"`
	Action      string            `json:"action"`
	Reference   string            `json:"reference,omitempty"`
	Destination string            `json:"destination,omitempty"`
	Tool        string            `json:"tool,omitempty"`
	Rule        string            `json:"rule,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	ExpiresAt   string            `json:"expires_at,omitempty"`
	ApproveURL  string            `json:"approve_url,omitempty"`
	DenyURL     string            `json:"deny_url,omitempty"`
	Title       string            `json:"title"`
	Fields      map[string]string `json:"fields,omitempty"`
	Signature   string            `json:"signature,omitempty"`
}

// inbox reads the plugin's output file and checks every line's signature,
// which proves the credential reached the plugin intact.
func inbox(t notifytest.TB, path, key string) []notifytest.Delivery {
	f, err := os.Open(path) //nolint:gosec // test file
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("open inbox: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []notifytest.Delivery
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("inbox line: %v", err)
		}
		sig := l.Signature
		l.Signature = ""
		unsigned, _ := json.Marshal(l)
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write(unsigned)
		if hex.EncodeToString(mac.Sum(nil)) != sig {
			t.Errorf("line for %s has a bad signature", l.ApprovalID)
		}
		d := notifytest.Delivery{ApprovalID: l.ApprovalID, Agent: l.Agent, Action: l.Action, Reference: l.Reference,
			Rule: l.Rule, Reason: l.Reason, ApproveURL: l.ApproveURL, DenyURL: l.DenyURL}
		if l.ExpiresAt != "" {
			d.ExpiresAt, _ = time.Parse(time.RFC3339, l.ExpiresAt)
		}
		out = append(out, d)
	}
	return out
}

func newNotifier(t testing.TB, out, key string) *notifyplugin.Notifier {
	bin := plugintest.Build(t, "./examples/plugins/filenotify")
	cfg, _, err := hostplugin.ParseConfig("file", pb.Kind_KIND_NOTIFIER, map[string]any{
		"command": bin, "options": map[string]any{"path": out}, "token": "env:FILE_TOKEN",
	}, notifyplugin.SecretFields, nil)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
		if ref != "env:FILE_TOKEN" {
			return secret.Value{}, errors.New("unexpected reference")
		}
		return secret.FromString(key), nil
	}
	return notifyplugin.New(cfg, resolve, nil)
}

// The notifier contract suite through the plugin bridge, against the
// example plugin (tasks.md 15.6).
func TestContract(t *testing.T) {
	notifytest.Run(t, func(t notifytest.TB) notifytest.Harness {
		tb := t.(testing.TB)
		dir := filepath.Join(tb.TempDir(), "inbox")
		if err := os.Mkdir(dir, 0o700); err != nil {
			tb.Fatal(err)
		}
		out := filepath.Join(dir, "approvals.jsonl")
		key := token(tb)
		n := newNotifier(tb, out, key)
		return notifytest.Harness{
			Notifier:  n,
			Delivered: func(t notifytest.TB) []notifytest.Delivery { return inbox(t, out, key) },
			Fail: func(t notifytest.TB) func() {
				if err := os.Rename(dir, dir+".down"); err != nil {
					t.Fatalf("fail: %v", err)
				}
				return func() {
					if err := os.Rename(dir+".down", dir); err != nil {
						t.Fatalf("restore: %v", err)
					}
				}
			},
			Close: func() { _ = n.Close() },
		}
	})
}

// A failed delivery never carries the credential or the plugin's own words.
func TestFailureCarriesNoCredential(t *testing.T) {
	key := token(t)
	n := newNotifier(t, filepath.Join(t.TempDir(), "missing", "approvals.jsonl"), key)
	defer func() { _ = n.Close() }()
	err := n.Notify(t.Context(), notify.Request{ApprovalID: "ap1"})
	if err == nil {
		t.Fatal("delivery into a missing directory succeeded")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatal("error contains the credential")
	}
	if !strings.Contains(err.Error(), "plugin notifier file: delivery failed (unavailable)") {
		t.Fatalf("err = %v", err)
	}
}

// A notifier plugin configured as a store, or a store plugin configured as
// a notifier, is refused at the handshake with both kinds named.
func TestKindMismatchRefused(t *testing.T) {
	bin := plugintest.Build(t, "./examples/plugins/dirstore")
	cfg, _, err := hostplugin.ParseConfig("pager", pb.Kind_KIND_NOTIFIER, map[string]any{"command": bin}, notifyplugin.SecretFields, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hostplugin.Validate(t.Context(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "is a store plugin, configured as a notifier plugin") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectionValidation(t *testing.T) {
	bin := plugintest.Build(t, "./examples/plugins/filenotify")
	dir := t.TempDir()
	write := func(yaml string) error {
		p := filepath.Join(dir, "scrim.yaml")
		if err := os.WriteFile(p, []byte("apiVersion: scrim.dev/v1\nkind: Config\n"+yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := config.Build(config.Options{ConfigPaths: []string{p}, Environ: []string{"FILE_TOKEN=" + token(t)}, SystemDir: dir})
		return err
	}
	good := "notify:\n  plugins:\n    file:\n      command: " + bin + "\n      options: {path: " + dir + "/a.jsonl}\n      token: env:FILE_TOKEN\n"
	if err := write(good); err != nil {
		t.Fatalf("valid configuration refused: %v", err)
	}
	missingToken := "notify:\n  plugins:\n    file:\n      command: " + bin + "\n      options: {path: " + dir + "/a.jsonl}\n"
	if err := write(missingToken); err == nil || !strings.Contains(err.Error(), "token is required") {
		t.Fatalf("err = %v, want the plugin's problem", err)
	}
}
