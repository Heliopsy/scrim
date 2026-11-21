// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const userSettings = `{
  "theme": "dark",
  "hooks": {
    "PostToolUse": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "prettier --write"}]}
    ]
  },
  "permissions": {"deny": ["Read(./.env)"]}
}
`

func TestMergeAndRemoveHooksKeepTheUsersSettings(t *testing.T) {
	merged, err := MergeHooks([]byte(userSettings), "/opt/scrim it's/scrim", AgentClaude)
	if err != nil {
		t.Fatal(err)
	}
	if !HasHooks(merged) {
		t.Fatalf("hooks not installed:\n%s", merged)
	}
	s := string(merged)
	if !strings.Contains(s, "prettier --write") || !strings.Contains(s, `"Read(./.env)"`) {
		t.Fatalf("the user's settings were lost:\n%s", s)
	}
	if strings.Index(s, `"theme"`) > strings.Index(s, `"hooks"`) || strings.Index(s, `"hooks"`) > strings.Index(s, `"permissions"`) {
		t.Fatalf("key order changed:\n%s", s)
	}
	if c := HookCommand("/opt/scrim it's/scrim", AgentClaude, "PostToolUse"); c != `'/opt/scrim it'\''s/scrim' hooks run --agent claude --event PostToolUse # scrim-hook` {
		t.Fatalf("command not quoted for sh: %s", c)
	}
	if want, _ := json.Marshal(HookCommand("/opt/scrim it's/scrim", AgentClaude, "PostToolUse")); !strings.Contains(s, string(want)) {
		t.Fatalf("hook command missing:\n%s", s)
	}
	if !strings.Contains(s, `"onFailure": "block"`) {
		t.Fatalf("the prompt hook does not block on failure:\n%s", s)
	}
	// Merging again replaces scrim's handlers instead of adding more.
	again, err := MergeHooks(merged, "/usr/local/bin/scrim", AgentClaude)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(again), HookMarker); n != 2 || strings.Contains(string(again), "/opt/scrim") {
		t.Fatalf("second merge left %d scrim handlers:\n%s", n, again)
	}

	back, changed, empty, err := RemoveHooks(again)
	if err != nil || !changed || empty {
		t.Fatalf("remove: changed %v empty %v err %v", changed, empty, err)
	}
	var want, got any
	_ = json.Unmarshal([]byte(userSettings), &want)
	if err := json.Unmarshal(back, &got); err != nil {
		t.Fatal(err)
	}
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	if !bytes.Equal(wb, gb) {
		t.Fatalf("remove did not restore the settings:\n%s", back)
	}

	fresh, err := MergeHooks(nil, "/usr/local/bin/scrim", AgentCodex)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, empty, _ := RemoveHooks(fresh); !empty {
		t.Fatal("a file holding only scrim's hooks is not reported empty after removal")
	}
	if _, err := MergeHooks([]byte(`[1]`), "/s", AgentClaude); err == nil {
		t.Fatal("a non-object settings file was accepted")
	}
}

func agentInstaller(t *testing.T, mode Mode) (*Installer, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	out := &bytes.Buffer{}
	in := &Installer{Mode: mode, Out: out, Root: t.TempDir(), Home: home,
		StateDir:        filepath.Join(home, ".local", "state", "scrim"),
		ClaudeConfigDir: filepath.Join(home, ".claude"), CodexHome: filepath.Join(home, ".codex"),
		HookExecutable: "/usr/local/bin/scrim", Agents: []string{AgentClaude, AgentCodex},
		Managed: ManagedOptions{AnthropicBaseURL: "http://127.0.0.1:9790/anthropic", OpenAIBaseURL: "http://127.0.0.1:9790/openai/v1"}}
	return in, out
}

func TestHooksInstallAndUninstall(t *testing.T) {
	in, out := agentInstaller(t, ModeHooks)
	ctx := context.Background()
	if err := os.MkdirAll(in.ClaudeConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	claude := filepath.Join(in.ClaudeConfigDir, "settings.json")
	if err := os.WriteFile(claude, []byte(userSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := in.Install(ctx); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	codex := filepath.Join(in.CodexHome, "hooks.json")
	for _, p := range []string{claude, codex} {
		b, err := os.ReadFile(p) //nolint:gosec // test file
		if err != nil || !HasHooks(b) {
			t.Fatalf("%s: hooks missing (%v)", p, err)
		}
	}
	st, found, err := ReadAgentMode(in.ManifestPath(), in.Root)
	if err != nil || !found || st.Mode != ModeHooks || len(st.Agents) != 2 || len(st.Changed) != 0 {
		t.Fatalf("state = %+v, %v, %v", st, found, err)
	}
	// Installing again changes nothing.
	out.Reset()
	if err := in.Install(ctx); err != nil || strings.Contains(out.String(), "+ ") {
		t.Fatalf("second install made changes (%v):\n%s", err, out)
	}

	// A hand edit that drops scrim's hooks shows as changed.
	if err := os.WriteFile(codex, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := ReadAgentMode(in.ManifestPath(), in.Root); len(st.Changed) != 1 || st.Changed[0] != codex {
		t.Fatalf("changed = %v", st.Changed)
	}
	if err := os.Remove(codex); err != nil {
		t.Fatal(err)
	}

	un, _ := agentInstaller(t, ModeHooks)
	un.Home, un.StateDir, un.ClaudeConfigDir, un.CodexHome = in.Home, in.StateDir, in.ClaudeConfigDir, in.CodexHome
	if err := un.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(claude) //nolint:gosec // test file
	if strings.Contains(string(b), HookMarker) || !strings.Contains(string(b), "prettier --write") {
		t.Fatalf("uninstall left:\n%s", b)
	}
	for _, p := range []string{in.CodexHome, in.ManifestPath(), in.StateDir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still exists", p)
		}
	}
}

func TestManagedSettingsInstallAndUninstall(t *testing.T) {
	in, out := agentInstaller(t, ModeManaged)
	ctx := context.Background()
	if err := in.Install(ctx); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var claude struct {
		AllowedProviders []string          `json:"allowedProviders"`
		Env              map[string]string `json:"env"`
	}
	b, err := os.ReadFile(filepath.Join(in.Root, ClaudeManagedDropIn))
	if err != nil || json.Unmarshal(b, &claude) != nil {
		t.Fatalf("drop-in: %v\n%s", err, b)
	}
	if len(claude.AllowedProviders) != 1 || claude.AllowedProviders[0] != "customEndpoint" ||
		claude.Env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9790/anthropic" || len(claude.Env) != 1 {
		t.Fatalf("drop-in = %+v", claude)
	}
	codex, _ := os.ReadFile(filepath.Join(in.Root, CodexRequirements))
	if !strings.Contains(string(codex), "model_provider = \"scrim\"") || !strings.Contains(string(codex), `base_url = "http://127.0.0.1:9790/openai/v1"`) {
		t.Fatalf("requirements:\n%s", codex)
	}
	if in.ManifestPath() != filepath.Join(in.Root, ManagedManifest) {
		t.Fatalf("manifest at %s", in.ManifestPath())
	}
	st, found, err := ReadAgentMode(in.ManifestPath(), in.Root)
	if err != nil || !found || len(st.Agents) != 2 || len(st.Files) != 2 || len(st.Changed) != 0 {
		t.Fatalf("state = %+v %v %v", st, found, err)
	}

	un, _ := agentInstaller(t, ModeManaged)
	un.Root = in.Root
	if err := un.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"etc/claude-code", "etc/codex", "etc/scrim"} {
		if _, err := os.Stat(filepath.Join(in.Root, p)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after uninstall", p)
		}
	}
}

func TestManagedSettingsLeaveTheAdministratorsFiles(t *testing.T) {
	in, out := agentInstaller(t, ModeManaged)
	for p, content := range map[string]string{
		ClaudeManagedFile: `{"allowedProviders": ["anthropic"], "model": "opus"}`,
		CodexRequirements: "allowed_sandbox_modes = [\"read-only\"]\n",
	} {
		full := filepath.Join(in.Root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil { //nolint:gosec // test file
			t.Fatal(err)
		}
	}
	err := in.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "add these lines to it yourself") {
		t.Fatalf("an existing requirements.toml was not refused: %v", err)
	}
	if !strings.Contains(out.String(), `allows the provider "anthropic"`) {
		t.Fatalf("no warning about the wider allowedProviders:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(in.Root, ClaudeManagedFile)); !strings.Contains(string(b), `"opus"`) {
		t.Fatal("the administrator's managed-settings.json was changed")
	}
}

func TestClaudeManagedSettingsForwardProxy(t *testing.T) {
	b, err := ClaudeManagedSettings(ManagedOptions{AnthropicBaseURL: "http://127.0.0.1:1/anthropic", ForwardProxy: "http://127.0.0.1:2"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"HTTPS_PROXY": "http://127.0.0.1:2"`) || !strings.Contains(string(b), `"NO_PROXY"`) {
		t.Fatalf("%s", b)
	}
}
