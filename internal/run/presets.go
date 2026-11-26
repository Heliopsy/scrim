// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/localapi"
)

// Preset adds what one agent CLI needs beyond the common environment.
type Preset struct {
	// Name is what --agent takes.
	Name string
	// Commands are the executable names that select the preset.
	Commands []string
	// Check refuses an inherited environment the preset cannot make safe.
	Check func(env map[string]string) error
	// Apply adds the agent's own variables, arguments and files.
	Apply func(b *builder) error
}

// Presets are the built-in agent presets, generic last.
var Presets = []*Preset{ClaudePreset, CodexPreset, OpenCodePreset, GenericPreset}

// GenericPreset sets the common environment only.
var GenericPreset = &Preset{Name: "generic"}

// ClaudePreset is Claude Code.
var ClaudePreset = &Preset{
	Name:     "claude",
	Commands: []string{"claude"},
	Check: func(env map[string]string) error {
		for _, v := range []string{"CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD"} {
			if truthy(env[v]) {
				return fmt.Errorf("%s is set: scrim does not serve this provider yet, and the agent would reach it directly; unset it to use the Anthropic API or a provider scrim serves", v)
			}
		}
		return nil
	},
	Apply: func(b *builder) error {
		if err := cloudMode(b); err != nil {
			return err
		}
		if b.identified() {
			// Claude Code adds ANTHROPIC_CUSTOM_HEADERS (one "Name: value"
			// per line) to every API request: the session header identifies
			// it on the base-URL listener, which strips it. Inherited
			// headers are kept, minus any session header of their own.
			var keep []string
			for line := range strings.SplitSeq(b.env["ANTHROPIC_CUSTOM_HEADERS"], "\n") {
				name, _, _ := strings.Cut(line, ":")
				if strings.TrimSpace(line) != "" && !strings.EqualFold(strings.TrimSpace(name), SessionHeader) {
					keep = append(keep, line)
				}
			}
			hdr := SessionHeader + ": " + TokenMarker
			display := hdr
			if len(keep) > 0 {
				display = "<inherited headers>\n" + hdr
			}
			b.setWithToken("ANTHROPIC_CUSTOM_HEADERS", strings.Join(append(keep, hdr), "\n"), display,
				"identifies the session to scrim's LLM proxy (stripped before the provider)")
		}
		if !b.in.MCP {
			return nil
		}
		cfg, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
			"scrim": map[string]any{"command": b.in.ScrimPath, "args": []string{"mcp"}},
		}})
		if err != nil {
			return err
		}
		b.plan.Files[FileMCP] = cfg
		// --mcp-config takes several values; the = form keeps it from
		// swallowing the prompt that follows. Claude Code starts MCP
		// servers with its own environment, so the token reaches them.
		b.insertArgs("--mcp-config=" + b.file(FileMCP))
		return nil
	},
}

// claudeCloud is one of Claude Code's cloud provider modes.
type claudeCloud struct {
	// Use turns the mode on; Kind is the scrim provider kind that serves it.
	Use, Kind string
	// BaseURL is Claude Code's base URL variable for the mode, pointed at
	// scrim's route plus Suffix.
	BaseURL, Suffix string
	// SkipAuth turns Claude Code's own signing or key off: scrim
	// authenticates the redacted request.
	SkipAuth string
	// Unset are credential variables that would take precedence over
	// SkipAuth.
	Unset []string
}

// claudeClouds are the modes scrim serves (docs/providers).
var claudeClouds = []claudeCloud{
	{Use: "CLAUDE_CODE_USE_BEDROCK", Kind: "bedrock", BaseURL: "ANTHROPIC_BEDROCK_BASE_URL",
		SkipAuth: "CLAUDE_CODE_SKIP_BEDROCK_AUTH", Unset: []string{"AWS_BEARER_TOKEN_BEDROCK"}},
	{Use: "CLAUDE_CODE_USE_MANTLE", Kind: "bedrock-mantle", BaseURL: "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
		SkipAuth: "CLAUDE_CODE_SKIP_MANTLE_AUTH", Unset: []string{"AWS_BEARER_TOKEN_BEDROCK"}},
	{Use: "CLAUDE_CODE_USE_ANTHROPIC_AWS", Kind: "anthropic-aws", BaseURL: "ANTHROPIC_AWS_BASE_URL",
		SkipAuth: "CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH", Unset: []string{"ANTHROPIC_AWS_API_KEY"}},
	{Use: "CLAUDE_CODE_USE_FOUNDRY", Kind: "foundry", BaseURL: "ANTHROPIC_FOUNDRY_BASE_URL", Suffix: "/anthropic",
		SkipAuth: "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
		Unset:    []string{"ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_AUTH_TOKEN", "ANTHROPIC_FOUNDRY_RESOURCE"}},
	// Claude Code appends /projects/... to the base URL, which ends in the
	// API version.
	{Use: "CLAUDE_CODE_USE_VERTEX", Kind: "vertex", BaseURL: "ANTHROPIC_VERTEX_BASE_URL", Suffix: "/v1",
		SkipAuth: "CLAUDE_CODE_SKIP_VERTEX_AUTH"},
}

// cloudMode points each cloud provider mode the inherited environment turns
// on at scrim's route for it, with Claude Code's own authentication off, or
// refuses when scrim has no such route: the agent would reach the provider
// directly.
func cloudMode(b *builder) error {
	for _, c := range claudeClouds {
		if !truthy(b.env[c.Use]) {
			continue
		}
		prefix := b.in.Endpoints.route(c.Kind)
		if prefix == "" {
			return fmt.Errorf("%s is set but scrim has no %s provider route, and the agent would reach the provider directly; "+
				"configure providers.<name> with kind %s (docs/providers/README.md) or unset %s", c.Use, c.Kind, c.Kind, c.Use)
		}
		base := strings.TrimRight(b.in.Endpoints.LLMBaseURL, "/")
		b.override(c.BaseURL, base+prefix+c.Suffix, "Claude Code's "+c.Kind+" requests through scrim's LLM proxy")
		b.setVar(c.SkipAuth, "1", "scrim authenticates the redacted request with credentials it holds")
		for _, v := range c.Unset {
			b.unsetVar(v)
		}
	}
	return nil
}

// CodexPreset is the OpenAI Codex CLI.
var CodexPreset = &Preset{
	Name:     "codex",
	Commands: []string{"codex"},
	Apply: func(b *builder) error {
		bundle := ""
		for _, v := range b.plan.Set {
			if v.Name == "SSL_CERT_FILE" {
				bundle = v.Value
			}
		}
		if bundle != "" {
			b.setVar("CODEX_CA_CERTIFICATE", bundle, "Codex's own CA override, ahead of SSL_CERT_FILE")
		}
		// Codex reads the OpenAI base URL from its configuration
		// (openai_base_url) and ignores OPENAI_BASE_URL (checked with 0.171);
		// -c sets it for this run only without touching
		// ~/.codex/config.toml. A project's .codex/config.toml cannot set it.
		if p := codexProvider(b.env, b.plan.Args[1:]); p != "" && p != "openai" {
			b.warn("Codex is configured with model_provider %q: its model requests go to that provider's base_url, not through scrim's LLM proxy "+
				"(unless that base_url is scrim's); remove model_provider to use the built-in openai provider (docs/run.md#codex-codex)", p)
		}
		args := []string{"-c", "openai_base_url=" + tomlString(b.valueOf("OPENAI_BASE_URL"))}
		// No session header here: the built-in openai provider takes no
		// extra headers and its id is reserved, and a provider of scrim's own
		// would change where a ChatGPT sign-in sends its requests. Codex's
		// base-URL requests are therefore unidentified; its ChatGPT traffic
		// goes through the forward proxy, which carries the session
		// (docs/run.md, "Codex").
		if b.in.MCP {
			// Codex starts MCP servers with a reduced environment; env_vars
			// passes the socket and token through by name, so the token
			// never appears on a command line.
			args = append(args,
				"-c", "mcp_servers.scrim.command="+tomlString(b.in.ScrimPath),
				"-c", `mcp_servers.scrim.args=["mcp"]`,
				"-c", "mcp_servers.scrim.env_vars="+tomlList(localapi.EnvSocket, localapi.EnvToken, EnvSessionID),
			)
		}
		b.insertArgs(args...)
		return nil
	},
}

// codexProvider returns the model provider Codex is set to use, from a
// `-c model_provider=...` argument or the top level of
// $CODEX_HOME/config.toml (default ~/.codex), or "" when neither sets one.
// Profiles are not read: a profile's provider is not reported.
func codexProvider(env map[string]string, args []string) string {
	for i, a := range args {
		v := ""
		switch {
		case (a == "-c" || a == "--config") && i+1 < len(args):
			v = args[i+1]
		case strings.HasPrefix(a, "--config="):
			v = strings.TrimPrefix(a, "--config=")
		}
		if k, val, ok := strings.Cut(v, "="); ok && strings.TrimSpace(k) == "model_provider" {
			return strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}
	home := env["CODEX_HOME"]
	if home == "" {
		for _, v := range []string{"HOME", "USERPROFILE"} {
			if h := envGet(env, v); h != "" {
				home = filepath.Join(h, ".codex")
				break
			}
		}
	}
	if home == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, "config.toml")) // #nosec G304 -- the user's own Codex configuration, read for a warning
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			break
		}
		if m := codexProviderLine.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

var codexProviderLine = regexp.MustCompile(`^model_provider\s*=\s*["']([^"']*)["']`)

// PresetFor picks the preset for an executable by its base name.
func PresetFor(command string) *Preset {
	base := filepath.Base(command)
	for _, p := range Presets {
		if slices.Contains(p.Commands, base) {
			return p
		}
	}
	return GenericPreset
}

// PresetNamed returns the preset called name.
func PresetNamed(name string) (*Preset, error) {
	var names []string
	for _, p := range Presets {
		if p.Name == name {
			return p, nil
		}
		names = append(names, p.Name)
	}
	return nil, fmt.Errorf("unknown agent preset %q (%s)", name, strings.Join(names, ", "))
}

// ErrWrapperFirst is returned for a command that would put another proxy
// between the agent and scrim.
var ErrWrapperFirst = errors.New("caveman would sit between the agent and scrim and receive requests before they are redacted; run the agent directly under scrim run and chain caveman behind scrim instead (docs/run.md#chained-proxies)")

// checkCommand refuses commands that defeat the wrapper.
func checkCommand(cmd []string) error {
	if filepath.Base(cmd[0]) == "caveman" {
		return ErrWrapperFirst
	}
	return nil
}

func (b *builder) insertArgs(args ...string) {
	b.plan.Args = slices.Insert(b.plan.Args, 1, args...)
}

func (b *builder) valueOf(name string) string {
	if i, ok := b.set[name]; ok {
		return b.plan.Set[i].Value
	}
	return ""
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}

// tomlString quotes s as a TOML basic string.
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

func tomlList(items ...string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = tomlString(s)
	}
	return "[" + strings.Join(q, ",") + "]"
}
