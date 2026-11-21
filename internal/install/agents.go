// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Agent-side modes (specs/interception "Managed agent settings" and
// "Hooks-only mode is reported as partial"). They change the agents'
// configuration, not scrim's, and have a manifest of their own, so they
// stack with any service install and `scrim uninstall` reverts them too.
const (
	// ModeHooks installs scrim's hooks into the agents' user configuration
	// (this user only).
	ModeHooks Mode = "hooks"
	// ModeManaged writes the agents' managed (administrator) settings so
	// they can only use scrim's endpoint (system-wide, as root).
	ModeManaged Mode = "managed-settings"

	// KindHooks is scrim's handlers in an agent's hooks file (Claude Code's
	// settings.json, Codex's hooks.json). Uninstall removes the handlers
	// that carry HookMarker and keeps everything else in the file; Group is
	// the agent, Created says install created the file.
	KindHooks = "agent-hooks"

	// HooksManifestName is the hooks manifest in the user state directory.
	HooksManifestName = "agent-hooks.json"
	// ManagedManifest is the managed settings manifest.
	ManagedManifest = "/etc/scrim/managed-settings.json"

	// ClaudeManagedDropIn is scrim's file in Claude Code's managed settings
	// drop-in directory on Linux and WSL. Claude Code merges
	// managed-settings.json first, then every *.json in the directory in
	// alphabetical order, so an administrator's own managed-settings.json
	// is left untouched.
	ClaudeManagedDropIn = "/etc/claude-code/managed-settings.d/90-scrim.json"
	// ClaudeManagedFile is the administrator's own file, read for warnings
	// only.
	ClaudeManagedFile = "/etc/claude-code/managed-settings.json"
	// CodexRequirements is Codex's admin-enforced requirements file on
	// Linux and macOS. It has no drop-in directory, so scrim writes it only
	// when it does not exist.
	CodexRequirements = "/etc/codex/requirements.toml"

	// HookMarker ends the command of every hook scrim installs (a shell
	// comment), so uninstall finds its own handlers and no others.
	HookMarker = "# scrim-hook"
	// HookTimeout is the hook timeout in seconds, for both agents.
	HookTimeout = 30
)

// Agents with an agent-side mode.
const (
	AgentClaude = "claude"
	AgentCodex  = "codex"
)

// HookEvents are the events scrim's hook runs on.
var HookEvents = []string{"PostToolUse", "UserPromptSubmit"}

// What each agent-side mode covers and does not, for `scrim status` and
// `scrim doctor` (docs/interception.md, methods 6 and the add-on).
var (
	HooksCovers = []string{
		"tool results (Claude Code: replaced by the redacted result; Codex: blocked, the redacted result sent as the hook's reason)",
		"prompts holding a known value are blocked before they are sent",
	}
	HooksNotCovered = []string{
		"model requests: anything that did not come back as a tool result, such as files attached to a prompt or context the agent builds itself",
		"model replies: nothing restores placeholders, so the agent sees placeholders it cannot use",
		"network egress: model and tool traffic go to the provider directly; no credential injection",
		"tool results when the hook cannot start, and tool failures (PostToolUseFailure)",
	}
	ManagedCovers = []string{
		"the agent's own endpoint is pinned to scrim; the user, a project file or the model cannot change it through the agent's settings",
	}
	ManagedNotCovered = []string{
		"processes the agent starts, such as curl from its shell tool: use transparent or Kubernetes interception",
		"redaction itself: run scrim (scrim run, the service, or the forward proxy) behind the pinned endpoint",
		"anyone with root, or write access to the managed files",
	}
)

// ManagedOptions are the endpoints managed settings pin.
type ManagedOptions struct {
	// AnthropicBaseURL and OpenAIBaseURL are scrim's LLM proxy routes.
	AnthropicBaseURL, OpenAIBaseURL string
	// ForwardProxy, when set, also pins HTTPS_PROXY to scrim's forward
	// proxy, so the agent's own tool traffic goes through scrim as well.
	ForwardProxy string
}

// ClaudeManagedSettings is the content of ClaudeManagedDropIn:
// allowedProviders admits only a custom endpoint, and Claude Code admits a
// custom endpoint only for the exact value a managed env block pins. A
// managed env value overwrites the same variable exported in the shell.
func ClaudeManagedSettings(o ManagedOptions) ([]byte, error) {
	env := map[string]string{"ANTHROPIC_BASE_URL": o.AnthropicBaseURL}
	if o.ForwardProxy != "" {
		env["HTTPS_PROXY"] = o.ForwardProxy
		env["NO_PROXY"] = "localhost,127.0.0.1,::1"
	}
	b, err := json.MarshalIndent(map[string]any{
		"allowedProviders": []string{"customEndpoint"},
		"env":              env,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// CodexManagedRequirements is the content of CodexRequirements:
// model_provider enforces the provider ID over local and session
// configuration, and the managed model_providers entry replaces any user
// definition with the same ID.
func CodexManagedRequirements(o ManagedOptions) []byte {
	return []byte("# Written by `scrim install --managed-settings`; `scrim uninstall --managed-settings` removes it.\n" +
		"model_provider = \"scrim\"\n\n" +
		"[model_providers.scrim]\n" +
		"name = \"OpenAI through scrim\"\n" +
		"base_url = " + tomlString(o.OpenAIBaseURL) + "\n" +
		"requires_openai_auth = true\n")
}

func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// HookCommand is the shell command an agent runs for event: the scrim
// binary, quoted for sh, then HookMarker.
func HookCommand(scrim, agent, event string) string {
	return shellQuote(scrim) + " hooks run --agent " + agent + " --event " + event + " " + HookMarker
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// hookGroup is the matcher group scrim adds for event.
func hookGroup(scrim, agent, event string) map[string]any {
	h := map[string]any{"type": "command", "command": HookCommand(scrim, agent, event), "timeout": HookTimeout}
	if agent == AgentClaude && event == "UserPromptSubmit" {
		// A prompt check that cannot run blocks the prompt (Claude Code
		// v2.1.295 or later; older versions ignore the field).
		h["onFailure"] = "block"
	}
	g := map[string]any{"hooks": []any{h}}
	if event == "PostToolUse" {
		g["matcher"] = "*"
	}
	return g
}

// object is a JSON object that keeps its key order, so editing one key of
// a user's settings file leaves the rest as it was.
type object struct {
	keys []string
	vals map[string]json.RawMessage
}

func parseObject(b []byte) (*object, error) {
	o := &object{vals: map[string]json.RawMessage{}}
	if len(bytes.TrimSpace(b)) == 0 {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := o.vals[k]; !dup {
			o.keys = append(o.keys, k)
		}
		o.vals[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("trailing data after the JSON object")
	}
	return o, nil
}

func (o *object) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *object) del(k string) {
	delete(o.vals, k)
	o.keys = slices.DeleteFunc(o.keys, func(x string) bool { return x == k })
}

func (o *object) marshal() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("{")
	for i, k := range o.keys {
		if i > 0 {
			b.WriteString(",")
		}
		kb, _ := json.Marshal(k)
		b.WriteString("\n")
		b.Write(kb)
		b.WriteString(": ")
		b.Write(o.vals[k])
	}
	if len(o.keys) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("}")
	var out bytes.Buffer
	if err := json.Indent(&out, b.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// isOurs reports whether a hook handler is one scrim installed.
func isOurs(h any) bool {
	m, ok := h.(map[string]any)
	if !ok {
		return false
	}
	c, _ := m["command"].(string)
	return strings.HasSuffix(strings.TrimSpace(c), HookMarker)
}

// withoutOurs removes scrim's handlers from the groups of one event, and
// groups left with no handler. It reports whether anything changed.
func withoutOurs(groups []any) ([]any, bool) {
	changed := false
	var out []any
	for _, g := range groups {
		gm, ok := g.(map[string]any)
		hs, hok := gm["hooks"].([]any)
		if !ok || !hok {
			out = append(out, g)
			continue
		}
		kept := slices.DeleteFunc(slices.Clone(hs), isOurs)
		if len(kept) == len(hs) {
			out = append(out, g)
			continue
		}
		changed = true
		if len(kept) > 0 {
			gm["hooks"] = kept
			out = append(out, gm)
		}
	}
	return out, changed
}

// MergeHooks returns doc (an agent's hooks file, Claude Code's
// settings.json or Codex's hooks.json; both keep hooks under a top-level
// "hooks" object) with scrim's hooks for agent installed: any handler of
// scrim's already there is replaced, everything else is kept in order.
func MergeHooks(doc []byte, scrim, agent string) ([]byte, error) {
	o, err := parseObject(doc)
	if err != nil {
		return nil, err
	}
	hooks, err := parseObject(o.vals["hooks"])
	if err != nil {
		return nil, fmt.Errorf("hooks: %w", err)
	}
	for _, ev := range HookEvents {
		var groups []any
		if raw, ok := hooks.vals[ev]; ok {
			if err := json.Unmarshal(raw, &groups); err != nil {
				return nil, fmt.Errorf("hooks.%s is not a list: %w", ev, err)
			}
		}
		groups, _ = withoutOurs(groups)
		groups = append(groups, hookGroup(scrim, agent, ev))
		raw, err := json.Marshal(groups)
		if err != nil {
			return nil, err
		}
		hooks.set(ev, raw)
	}
	raw, err := hooks.marshal()
	if err != nil {
		return nil, err
	}
	o.set("hooks", raw)
	return o.marshal()
}

// RemoveHooks returns doc without scrim's handlers, dropping events and a
// hooks object left empty. empty reports a document left with no keys.
func RemoveHooks(doc []byte) (out []byte, changed, empty bool, err error) {
	o, err := parseObject(doc)
	if err != nil {
		return nil, false, false, err
	}
	raw, ok := o.vals["hooks"]
	if !ok {
		return doc, false, len(o.keys) == 0, nil
	}
	hooks, err := parseObject(raw)
	if err != nil {
		return nil, false, false, fmt.Errorf("hooks: %w", err)
	}
	for _, ev := range slices.Clone(hooks.keys) {
		var groups []any
		if json.Unmarshal(hooks.vals[ev], &groups) != nil {
			continue
		}
		kept, ch := withoutOurs(groups)
		if !ch {
			continue
		}
		changed = true
		if len(kept) == 0 {
			hooks.del(ev)
			continue
		}
		b, err := json.Marshal(kept)
		if err != nil {
			return nil, false, false, err
		}
		hooks.set(ev, b)
	}
	if !changed {
		return doc, false, len(o.keys) == 0, nil
	}
	if len(hooks.keys) == 0 {
		o.del("hooks")
	} else {
		b, err := hooks.marshal()
		if err != nil {
			return nil, false, false, err
		}
		o.set("hooks", b)
	}
	out, err = o.marshal()
	return out, true, len(o.keys) == 0, err
}

// HasHooks reports whether doc holds a hook handler scrim installed for
// each of HookEvents.
func HasHooks(doc []byte) bool {
	o, err := parseObject(doc)
	if err != nil {
		return false
	}
	hooks, err := parseObject(o.vals["hooks"])
	if err != nil {
		return false
	}
	for _, ev := range HookEvents {
		var groups []any
		if json.Unmarshal(hooks.vals[ev], &groups) != nil {
			return false
		}
		_, ours := withoutOurs(groups)
		if !ours {
			return false
		}
	}
	return true
}

// HooksFile is the file an agent's user hooks live in.
func (in *Installer) HooksFile(agent string) string {
	if agent == AgentCodex {
		return filepath.Join(in.CodexHome, "hooks.json")
	}
	return filepath.Join(in.ClaudeConfigDir, "settings.json")
}

func (in *Installer) installHooks() error {
	if in.HookExecutable == "" {
		return errors.New("install: the scrim binary the hooks run is unknown")
	}
	if err := in.ensureDir(filepath.Dir(in.mpath), 0o700); err != nil {
		return err
	}
	for _, a := range in.Agents {
		path := in.HooksFile(a)
		if err := in.ensureDir(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := in.hooksFile(path, a); err != nil {
			return err
		}
	}
	return nil
}

// hooksFile adds scrim's hooks to path, keeping everything else in it.
func (in *Installer) hooksFile(path, agent string) error {
	cur, err := os.ReadFile(path) // #nosec G304 -- the agent's own settings file
	created := errors.Is(err, fs.ErrNotExist)
	if err != nil && !created {
		return fmt.Errorf("install: %w", err)
	}
	next, err := MergeHooks(cur, in.HookExecutable, agent)
	if err != nil {
		return fmt.Errorf("install: %s: %w; fix the file and run install again", path, err)
	}
	e := Entry{Kind: KindHooks, Target: path, Group: agent}
	if i := in.mf.find(e); i >= 0 {
		e.Created = in.mf.Entries[i].Created
	} else {
		e.Created = created
	}
	if bytes.Equal(cur, next) && in.recorded(e) {
		return nil
	}
	desc := fmt.Sprintf("add scrim's %s hooks for %s to %s", strings.Join(HookEvents, " and "), agent, path)
	if created {
		desc = fmt.Sprintf("write %s with scrim's %s hooks for %s", path, strings.Join(HookEvents, " and "), agent)
	}
	return in.change(desc, e, func() error {
		mode := fs.FileMode(0o600)
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
		return writeAtomic(path, next, mode)
	})
}

// revertHooks removes scrim's handlers from the file of e.
func (in *Installer) revertHooks(e Entry) result {
	cur, err := os.ReadFile(e.Target) // #nosec G304 -- a path install recorded
	if errors.Is(err, fs.ErrNotExist) {
		return ok()
	}
	manual := "remove the hooks whose command ends with " + HookMarker + " from " + e.Target
	if err != nil {
		return fail(err, manual)
	}
	next, changed, empty, err := RemoveHooks(cur)
	if err != nil {
		return fail(fmt.Errorf("%s: %w", e.Target, err), manual)
	}
	switch {
	case e.Created && empty:
		if err := os.Remove(e.Target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(err, "rm "+e.Target)
		}
	case changed:
		st, err := os.Stat(e.Target)
		if err != nil {
			return fail(err, manual)
		}
		if err := writeAtomic(e.Target, next, st.Mode().Perm()); err != nil {
			return fail(err, manual)
		}
	}
	return ok()
}

func (in *Installer) installManaged() error {
	if err := in.ensureDir(filepath.Dir(in.mpath), 0o755); err != nil {
		return err
	}
	for _, a := range in.Agents {
		var err error
		switch a {
		case AgentClaude:
			err = in.managedClaude()
		case AgentCodex:
			err = in.managedCodex()
		default:
			err = fmt.Errorf("install: no managed settings for agent %q", a)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (in *Installer) managedClaude() error {
	content, err := ClaudeManagedSettings(in.Managed)
	if err != nil {
		return err
	}
	in.warnClaudeManaged()
	path := in.path(ClaudeManagedDropIn)
	if err := in.ensureDir(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_, err = in.file(fileSpec{path: path, content: content, mode: 0o644,
		what: "Claude Code managed settings: allowedProviders customEndpoint, ANTHROPIC_BASE_URL pinned to scrim"})
	return err
}

// warnClaudeManaged points out managed settings of the administrator's own
// that widen scrim's: lists such as allowedProviders combine across the
// managed files, so another provider listed there stays allowed.
func (in *Installer) warnClaudeManaged() {
	files := []string{in.path(ClaudeManagedFile)}
	if more, err := filepath.Glob(filepath.Join(in.path(filepath.Dir(ClaudeManagedDropIn)), "*.json")); err == nil {
		files = append(files, more...)
	}
	for _, f := range files {
		if f == in.path(ClaudeManagedDropIn) {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- managed settings files
		if err != nil {
			continue
		}
		var doc struct {
			AllowedProviders []string          `json:"allowedProviders"`
			Env              map[string]string `json:"env"`
		}
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		for _, p := range doc.AllowedProviders {
			if p != "customEndpoint" {
				in.printf("  warning: %s allows the provider %q; managed lists combine, so Claude Code may still reach it directly\n", f, p)
			}
		}
		if v, ok := doc.Env["ANTHROPIC_BASE_URL"]; ok && v != in.Managed.AnthropicBaseURL && filepath.Base(f) > filepath.Base(ClaudeManagedDropIn) {
			in.printf("  warning: %s sets ANTHROPIC_BASE_URL and is merged after scrim's file, so its value wins\n", f)
		}
	}
}

func (in *Installer) managedCodex() error {
	content := CodexManagedRequirements(in.Managed)
	path := in.path(CodexRequirements)
	if exists(path) && !in.recorded(Entry{Kind: KindFile, Target: path}) {
		return fmt.Errorf("install: %s exists and was not written by scrim; Codex has no drop-in directory, so add these lines to it yourself:\n\n%s", path, content)
	}
	if err := in.ensureDir(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_, err := in.file(fileSpec{path: path, content: content, mode: 0o644,
		what: "Codex requirements: model_provider pinned to scrim's endpoint"})
	return err
}

// AgentModeState is an installed agent-side mode as its manifest and the
// files on disk show it, for `scrim status` and `scrim doctor`.
type AgentModeState struct {
	Mode   Mode
	Agents []string
	Files  []string
	// Changed are files missing or no longer holding what install wrote.
	Changed []string
}

// ReadAgentMode reads the agent-side manifest at path. root prefixes the
// managed settings paths, as Installer.Root does. A missing manifest
// returns found false.
func ReadAgentMode(path, root string) (AgentModeState, bool, error) {
	mf, found, err := ReadManifest(path)
	if err != nil || !found {
		return AgentModeState{}, found, err
	}
	st := AgentModeState{Mode: mf.Mode}
	addAgent := func(a string) {
		if a != "" && !slices.Contains(st.Agents, a) {
			st.Agents = append(st.Agents, a)
		}
	}
	join := func(p string) string {
		if root == "" {
			return p
		}
		return filepath.Join(root, p)
	}
	for _, e := range mf.Entries {
		switch e.Kind {
		case KindHooks:
			addAgent(e.Group)
			st.Files = append(st.Files, e.Target)
			b, err := os.ReadFile(e.Target) // #nosec G304 -- a path install recorded
			if err != nil || !HasHooks(b) {
				st.Changed = append(st.Changed, e.Target)
			}
		case KindFile:
			switch e.Target {
			case join(ClaudeManagedDropIn):
				addAgent(AgentClaude)
			case join(CodexRequirements):
				addAgent(AgentCodex)
			default:
				continue
			}
			st.Files = append(st.Files, e.Target)
			if cur, err := fileSum(e.Target); err != nil || cur != e.SHA256 {
				st.Changed = append(st.Changed, e.Target)
			}
		}
	}
	return st, true, nil
}
