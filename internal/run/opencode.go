// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/localapi"
)

// EnvOpenCodeConfig is OpenCode's inline configuration. OpenCode merges it
// over its global, OPENCODE_CONFIG and project configuration files, so the
// base URLs it sets hold whatever the user's files say (only OpenCode's
// managed configuration in /etc/opencode ranks higher).
const EnvOpenCodeConfig = "OPENCODE_CONFIG_CONTENT"

// openCodeProviders are OpenCode's built-in providers scrim serves: its
// provider id, scrim's provider route, and the API version path its AI SDK
// package expects at the end of the base URL.
var openCodeProviders = []struct{ id, route, suffix string }{
	{"anthropic", ProviderAnthropic, "/v1"},
	{"openai", ProviderOpenAI, "/v1"},
	{"google", ProviderGemini, "/v1beta"},
}

// OpenCodePreset is OpenCode (sst/opencode).
var OpenCodePreset = &Preset{
	Name:     "opencode",
	Commands: []string{"opencode"},
	Apply: func(b *builder) error {
		var served []string
		for _, p := range openCodeProviders {
			served = append(served, p.id)
		}
		if err := openCodeModelServed(b.plan.Args[1:], served); err != nil {
			return err
		}
		base := strings.TrimRight(b.in.Endpoints.LLMBaseURL, "/")
		providers := map[string]any{}
		for _, p := range openCodeProviders {
			opts := map[string]any{"baseURL": base + b.in.Endpoints.route(p.route) + p.suffix}
			if b.identified() {
				// OpenCode substitutes {env:...} when it loads the
				// configuration, so the token is read from the environment
				// and never written into the configuration itself.
				opts["headers"] = map[string]any{SessionHeader: "{env:" + localapi.EnvToken + "}"}
			}
			providers[p.id] = map[string]any{"options": opts}
		}
		// Only the providers scrim serves: any other would reach its own
		// endpoint, with requests scrim's LLM proxy never sees. A list the
		// user set is narrowed, never widened.
		enabled := served
		if user, from, err := openCodeUserProviders(b.env); err != nil {
			return err
		} else if user != nil {
			enabled = nil
			for _, p := range served {
				if slices.Contains(user, p) {
					enabled = append(enabled, p)
				}
			}
			if len(enabled) == 0 {
				return fmt.Errorf("enabled_providers in %s allows none of the providers scrim serves for OpenCode (%s); "+
					"add one of them to it to run OpenCode under scrim", from, strings.Join(served, ", "))
			}
		}
		cfg := map[string]any{
			"enabled_providers": enabled,
			"provider":          providers,
		}
		if b.in.MCP {
			env := map[string]any{}
			for _, name := range []string{localapi.EnvSocket, localapi.EnvToken, EnvSessionID} {
				if _, set := b.set[name]; set {
					env[name] = "{env:" + name + "}"
				}
			}
			cfg["mcp"] = map[string]any{"scrim": map[string]any{
				"type": "local", "command": []string{b.in.ScrimPath, "mcp"}, "enabled": true, "environment": env,
			}}
		}
		ours, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		why := "OpenCode's " + strings.Join(enabled, ", ") + " providers through scrim's LLM proxy, other providers off"
		if b.identified() {
			why += ", the session header on each request"
		}
		if b.in.MCP {
			why += ", scrim mcp registered"
		}
		old, ok := b.env[EnvOpenCodeConfig]
		if !ok || strings.TrimSpace(old) == "" {
			b.setVar(EnvOpenCodeConfig, string(ours), why)
			return nil
		}
		// An inherited inline configuration is kept, with scrim's settings
		// merged over it. It may hold the user's own keys, so --print-env
		// does not show it.
		var inherited map[string]any
		if err := json.Unmarshal([]byte(old), &inherited); err != nil || inherited == nil {
			return fmt.Errorf("%s from your environment is not a JSON object, so scrim's provider settings cannot be merged into it; "+
				"move it to a file and name it with OPENCODE_CONFIG", EnvOpenCodeConfig)
		}
		merged, err := json.Marshal(mergeJSON(inherited, cfg))
		if err != nil {
			return err
		}
		b.setDisplayed(EnvOpenCodeConfig, string(merged), "<inherited "+EnvOpenCodeConfig+"> merged with "+string(ours),
			why+"; the inherited configuration is kept beneath")
		return nil
	},
}

// openCodeUserProviders returns the enabled_providers list the user set,
// and where, or nil when none is set. It reads what OpenCode reads before
// OPENCODE_CONFIG_CONTENT that scrim run can see: the global configuration
// ($XDG_CONFIG_HOME/opencode/config.json, opencode.json, opencode.jsonc),
// the file OPENCODE_CONFIG names, then an inherited OPENCODE_CONFIG_CONTENT;
// the last one that sets the list wins, as in OpenCode. Project files are not
// read. A file that exists but cannot be parsed is an error: its list cannot
// be honoured.
func openCodeUserProviders(env map[string]string) ([]string, string, error) {
	var files []string
	dir := envGet(env, "XDG_CONFIG_HOME")
	if dir == "" {
		if h := envGet(env, "HOME"); h != "" {
			dir = filepath.Join(h, ".config")
		}
	}
	if dir != "" {
		for _, n := range []string{"config.json", "opencode.json", "opencode.jsonc"} {
			files = append(files, filepath.Join(dir, "opencode", n))
		}
	}
	if f := env["OPENCODE_CONFIG"]; f != "" {
		files = append(files, f)
	}
	var list []string
	from := ""
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- the user's own OpenCode configuration, read for its provider list
		if err != nil {
			continue
		}
		l, set, err := enabledProviders(b)
		if err != nil {
			return nil, "", fmt.Errorf("%s: cannot read its enabled_providers to keep them: %w", f, err)
		}
		if set {
			list, from = l, f
		}
	}
	if c := env[EnvOpenCodeConfig]; strings.TrimSpace(c) != "" {
		if l, set, err := enabledProviders([]byte(c)); err == nil && set {
			list, from = l, EnvOpenCodeConfig
		}
	}
	return list, from, nil
}

// enabledProviders reads enabled_providers from an OpenCode configuration
// (JSON with comments and trailing commas allowed).
func enabledProviders(b []byte) ([]string, bool, error) {
	var cfg struct {
		Enabled *[]string `json:"enabled_providers"`
	}
	if err := json.Unmarshal(stripJSONC(b), &cfg); err != nil {
		return nil, false, err
	}
	if cfg.Enabled == nil {
		return nil, false, nil
	}
	return *cfg.Enabled, true, nil
}

// stripJSONC removes // and /* */ comments outside strings and commas
// before a closing bracket, turning JSONC into JSON.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inStr:
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			i--
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := bytes.Index(b[i+2:], []byte("*/"))
			if end < 0 {
				return out
			}
			i += end + 3
		default:
			out = append(out, c)
		}
	}
	return trailingComma.ReplaceAll(out, []byte("$1"))
}

// trailingComma matches a comma before a closing bracket. It runs after
// comments are gone; a string holding ",}" would be changed too, which is
// harmless for reading enabled_providers.
var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// openCodeModelServed refuses a --model (-m) whose provider OpenCode would
// not send through scrim. The model is provider/model.
func openCodeModelServed(args, served []string) error {
	for i, a := range args {
		var model string
		switch {
		case a == "-m" || a == "--model":
			if i+1 < len(args) {
				model = args[i+1]
			}
		case strings.HasPrefix(a, "--model="):
			model = strings.TrimPrefix(a, "--model=")
		case strings.HasPrefix(a, "-m="):
			model = strings.TrimPrefix(a, "-m=")
		default:
			continue
		}
		provider, _, ok := strings.Cut(model, "/")
		if ok && !slices.Contains(served, provider) {
			return fmt.Errorf("model %q: scrim does not serve OpenCode's %s provider, and OpenCode would reach it directly; "+
				"use a model of %s (docs/run.md#opencode-opencode)", model, provider, strings.Join(served, ", "))
		}
	}
	return nil
}

// mergeJSON merges src over dst the way OpenCode merges configuration
// files: objects key by key, anything else replaced.
func mergeJSON(dst, src map[string]any) map[string]any {
	for k, v := range src {
		if sv, ok := v.(map[string]any); ok {
			if dv, ok := dst[k].(map[string]any); ok {
				dst[k] = mergeJSON(dv, sv)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}
