// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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
var Presets = []*Preset{ClaudePreset, CodexPreset, GenericPreset}

// GenericPreset sets the common environment only.
var GenericPreset = &Preset{Name: "generic"}

// ClaudePreset is Claude Code.
var ClaudePreset = &Preset{
	Name:     "claude",
	Commands: []string{"claude"},
	Check: func(env map[string]string) error {
		// These route Claude Code to cloud providers by their own base URL
		// variables, which scrim does not serve yet (tasks.md 11.4).
		for _, v := range []string{"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"} {
			if truthy(env[v]) {
				return fmt.Errorf("%s is set: Bedrock, Vertex and Foundry are not served by scrim yet, and the agent would reach them directly; unset it to use the Anthropic API through scrim", v)
			}
		}
		return nil
	},
	Apply: func(b *builder) error {
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
		// Current Codex reads the OpenAI base URL from its configuration
		// (openai_base_url), older releases from OPENAI_BASE_URL; -c sets it
		// for this run only without touching ~/.codex/config.toml.
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
