// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/profiles"
	"github.com/heliopsy/scrim/internal/secret"
)

// Environment variables scrim run sets besides the clients' own
// (localapi.EnvSocket, localapi.EnvToken).
const (
	EnvSessionID = "SCRIM_SESSION_ID"
)

// SessionHeader is the header that identifies the session on scrim's
// base-URL listener. Its value is the session token; the data plane keeps
// only a proof of it and never forwards the header (design D14).
const SessionHeader = "x-scrim-session"

// TokenMarker stands for the session token in the displayed value of a
// variable that embeds it (`scrim run --print-env`).
const TokenMarker = "<session-token>"

// Files written into the session directory.
const (
	FileCA     = "scrim-ca.pem"
	FileBundle = "ca-bundle.pem"
	FileMCP    = "mcp.json"
	// ProfilesDir holds what tool profiles generate.
	ProfilesDir = "profiles"
)

// proxyVars are set to the forward proxy, in both spellings clients read.
var proxyVars = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}

// removedProxyVars would send traffic somewhere other than the forward
// proxy, so they are dropped when it is set.
var removedProxyVars = []string{"ALL_PROXY", "all_proxy"}

var noProxyVars = []string{"NO_PROXY", "no_proxy"}

// bundleVars point runtimes that replace their trust store at the session
// bundle (system roots plus the scrim CA).
var bundleVars = []string{
	"SSL_CERT_FILE",      // OpenSSL, Go, Python ssl, rustls-native-certs, Codex
	"REQUESTS_CA_BUNDLE", // Python requests
	"CURL_CA_BUNDLE",     // curl
	"GIT_SSL_CAINFO",     // git over HTTPS
	"AWS_CA_BUNDLE",      // AWS CLI and SDKs
	"PIP_CERT",           // pip
	"NPM_CONFIG_CAFILE",  // npm
	"CARGO_HTTP_CAINFO",  // cargo
	"DENO_CERT",          // Deno
}

// loopback is always excluded from the proxy: the LLM base URL, the local
// API and local services live there.
var loopback = []string{"localhost", "127.0.0.1", "::1"}

// Var is one environment variable scrim run sets for the agent.
type Var struct {
	Name string `json:"name"`
	// Value is the value, or for a secret variable what is shown instead:
	// empty for the bare session token, else the value with [TokenMarker]
	// where the token goes (and inherited parts that may hold secrets
	// elided).
	Value string `json:"value,omitempty"`
	// Secret marks a value that is never printed: it holds the session token.
	Secret bool `json:"secret,omitempty"`
	// Why is a short note for --print-env.
	Why string `json:"why"`

	// template is the value with TokenMarker for the token, when it is not
	// the bare token. Never printed.
	template string
}

// Plan is everything scrim run changes for the agent process. It holds no
// secret: the session token is added when the agent starts.
type Plan struct {
	Preset string `json:"preset"`
	// Set lists the variables set, in a stable order.
	Set []Var `json:"set"`
	// Unset lists inherited variables removed.
	Unset []string `json:"unset,omitempty"`
	// Args is the agent's command line after the preset's additions.
	Args []string `json:"args"`
	// Files are written into the session directory before the agent
	// starts, keyed by slash-separated path relative to it.
	Files map[string][]byte `json:"-"`
	// Dirs are created in the session directory, mode 0700.
	Dirs []string `json:"-"`
	// Profiles are the tool profiles applied (docs/cli-tools.md).
	Profiles []string `json:"profiles,omitempty"`
	// Warnings are shown before the agent starts.
	Warnings []string `json:"warnings,omitempty"`
}

// Input is what a plan is built from.
type Input struct {
	// Command is the agent and its arguments.
	Command []string
	// Preset is the agent preset; nil picks one from Command.
	Preset *Preset
	// Environ is the environment scrim run inherited.
	Environ []string
	// Endpoints are where scrim listens.
	Endpoints Endpoints
	// SessionDir is the per-session directory for generated files.
	SessionDir string
	// SessionID is the minted session's public ID; empty without a session.
	SessionID string
	// Token says a session token will be passed.
	Token bool
	// MCP registers `scrim mcp` with agents whose preset supports it.
	MCP bool
	// ScrimPath is the scrim executable the agent starts for MCP.
	ScrimPath string
	// Placeholders are the declared catalog placeholders to export.
	Placeholders []string
	// Reserved reports names that must not be exported as placeholders
	// (scrim's own settings). Optional.
	Reserved func(name string) bool
	// Profiles is what the session's tool profiles set, rendered under
	// SessionDir/profiles. Optional.
	Profiles *profiles.Rendered
	// SystemRoots is the PEM of the trust store the session bundle starts
	// from. NodeExtra is the PEM of an inherited NODE_EXTRA_CA_CERTS file.
	SystemRoots, NodeExtra []byte
}

type builder struct {
	in    Input
	plan  *Plan
	env   map[string]string
	set   map[string]int
	unset map[string]bool
}

func (b *builder) setVar(name, value, why string) {
	if i, ok := b.set[name]; ok {
		b.plan.Set[i] = Var{Name: name, Value: value, Why: why}
		return
	}
	b.set[name] = len(b.plan.Set)
	b.plan.Set = append(b.plan.Set, Var{Name: name, Value: value, Why: why})
	delete(b.unset, name)
}

func (b *builder) setSecret(name, why string) {
	b.set[name] = len(b.plan.Set)
	b.plan.Set = append(b.plan.Set, Var{Name: name, Secret: true, Why: why})
}

// setWithToken sets name to template, with TokenMarker replaced by the
// session token when the agent starts; display is what --print-env shows.
func (b *builder) setWithToken(name, template, display, why string) {
	v := Var{Name: name, Value: display, Secret: true, Why: why, template: template}
	if i, ok := b.set[name]; ok {
		b.plan.Set[i] = v
		return
	}
	b.set[name] = len(b.plan.Set)
	b.plan.Set = append(b.plan.Set, v)
	delete(b.unset, name)
}

// identified reports whether the agent gets a session token to identify
// itself with on scrim's listeners.
func (b *builder) identified() bool { return b.in.Token && b.in.SessionID != "" }

// sessionProxyURL is the forward proxy URL with the session as proxy
// credentials (`Proxy-Authorization: Basic <session-id>:<token>`), so policy
// and grants apply to this agent on the forward proxy and the tool proxy.
func (b *builder) sessionProxyURL() (string, bool) {
	u, err := url.Parse(b.in.Endpoints.ForwardProxy)
	if err != nil || u.Scheme != "http" || u.Host == "" || !b.identified() {
		return "", false
	}
	return u.Scheme + "://" + b.in.SessionID + ":" + TokenMarker + "@" + u.Host, true
}

func (b *builder) unsetVar(name string) {
	if _, ok := b.env[name]; ok {
		if _, set := b.set[name]; !set {
			b.unset[name] = true
		}
	}
}

func (b *builder) warn(format string, a ...any) {
	b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(format, a...))
}

func (b *builder) file(name string) string { return filepath.Join(b.in.SessionDir, name) }

// Build computes the plan for in. It fails when the endpoints cannot serve
// the agent safely or the preset refuses the inherited environment.
func Build(in Input) (*Plan, error) {
	if len(in.Command) == 0 {
		return nil, errors.New("no agent command")
	}
	ep := in.Endpoints
	if ep.LLMBaseURL == "" {
		return nil, errors.New("scrim has no LLM base URL listener")
	}
	if ep.ForwardProxy != "" && len(ep.CACertPEM) == 0 {
		return nil, errors.New("scrim's forward proxy has no CA certificate to trust")
	}
	if in.SessionDir == "" {
		return nil, errors.New("no session directory")
	}
	p := in.Preset
	if p == nil {
		p = PresetFor(in.Command[0])
	}
	b := &builder{in: in, plan: &Plan{Preset: p.Name, Args: slices.Clone(in.Command), Files: map[string][]byte{}},
		env: envMap(in.Environ), set: map[string]int{}, unset: map[string]bool{}}
	if p.Check != nil {
		if err := p.Check(b.env); err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name, err)
		}
	}

	base := strings.TrimRight(ep.LLMBaseURL, "/")
	b.override("ANTHROPIC_BASE_URL", base+ep.route(ProviderAnthropic), "Anthropic API through scrim's LLM proxy")
	b.override("OPENAI_BASE_URL", base+ep.route(ProviderOpenAI)+"/v1", "OpenAI API through scrim's LLM proxy")

	if ep.APISocket != "" {
		b.setVar(localapi.EnvSocket, ep.APISocket, "local agent API for scrim mcp and scrim secret")
	}
	if in.Token {
		b.setSecret(localapi.EnvToken, "session token, bound to this process tree")
	} else {
		b.unsetVar(localapi.EnvToken)
	}
	if in.SessionID != "" {
		b.setVar(EnvSessionID, in.SessionID, "session ID (public)")
	}

	b.proxy()

	if p.Apply != nil {
		if err := p.Apply(b); err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name, err)
		}
	}
	b.placeholders()
	b.profiles()

	for n := range b.unset {
		b.plan.Unset = append(b.plan.Unset, n)
	}
	sort.Strings(b.plan.Unset)
	return b.plan, nil
}

// override sets name, warning when the inherited environment pointed it
// somewhere else (often a local proxy that should be chained instead).
func (b *builder) override(name, value, why string) {
	if old, ok := b.env[name]; ok && old != "" && old != value {
		b.warn("%s from your environment is replaced for this session; to keep a local proxy such as caveman in the path, chain it behind scrim (docs/run.md#chained-proxies)", name)
	}
	b.setVar(name, value, why)
}

func (b *builder) proxy() {
	ep := b.in.Endpoints
	noProxy := slices.Clone(loopback)
	for _, h := range ep.Bypass {
		noProxy = appendHost(noProxy, h)
	}
	if ep.ForwardProxy == "" {
		// No forward proxy: keep the user's proxy settings for tool
		// traffic, but never send the loopback LLM base URL through them.
		for _, v := range noProxyVars {
			if old := b.env[v]; old != "" {
				for _, h := range strings.Split(old, ",") {
					if h = strings.TrimSpace(h); h != "" {
						noProxy = appendHost(noProxy, h)
					}
				}
			}
		}
		for _, v := range noProxyVars {
			b.setVar(v, strings.Join(noProxy, ","), "loopback (LLM base URL) is reached directly")
		}
		return
	}
	for _, v := range proxyVars {
		if old := b.env[v]; old != "" && old != ep.ForwardProxy {
			b.warn("%s from your environment is replaced by scrim's forward proxy; scrim does not chain to another forward proxy yet", v)
			break
		}
	}
	if tmpl, ok := b.sessionProxyURL(); ok {
		for _, v := range proxyVars {
			b.setWithToken(v, tmpl, tmpl, "tool traffic through scrim's forward proxy, identified by the session")
		}
		// git asks libcurl for any proxy authentication method, so it sends
		// the session credentials only after a 407 challenge, which scrim's
		// forward proxy never sends: its tunnels would be unidentified and
		// injection refused. Basic sends them with the CONNECT.
		b.setVar("GIT_HTTP_PROXY_AUTHMETHOD", "basic", "git sends the session's proxy credentials with every CONNECT")
	} else {
		for _, v := range proxyVars {
			b.setVar(v, ep.ForwardProxy, "tool traffic through scrim's forward proxy")
		}
	}
	for _, v := range removedProxyVars {
		b.unsetVar(v)
	}
	for _, v := range noProxyVars {
		if old := b.env[v]; old != "" && old != strings.Join(noProxy, ",") {
			b.warn("%s from your environment is replaced: only loopback and chained local upstreams skip scrim's forward proxy", v)
			break
		}
	}
	for _, v := range noProxyVars {
		b.setVar(v, strings.Join(noProxy, ","), "only loopback and chained local upstreams skip the proxy")
	}

	ca := slices.Clone(ep.CACertPEM)
	if len(b.in.NodeExtra) > 0 {
		ca = appendPEM(ca, b.in.NodeExtra)
	}
	b.plan.Files[FileCA] = ca
	bundle := appendPEM(slices.Clone(b.in.SystemRoots), ep.CACertPEM)
	b.plan.Files[FileBundle] = bundle
	if len(b.in.SystemRoots) == 0 {
		b.warn("no system trust store found; the session bundle holds only scrim's CA, so hosts excluded from the proxy fail TLS")
	}
	b.setVar("NODE_EXTRA_CA_CERTS", b.file(FileCA), "Node.js adds scrim's CA to its roots")
	for _, v := range bundleVars {
		b.setVar(v, b.file(FileBundle), "system roots plus scrim's CA")
	}
}

func (b *builder) placeholders() {
	for _, ph := range b.in.Placeholders {
		if _, taken := b.set[ph]; taken || (b.in.Reserved != nil && b.in.Reserved(ph)) {
			b.warn("declared placeholder %s is not exported: the name is used by scrim itself", ph)
			continue
		}
		if old, ok := b.env[ph]; ok && old != ph {
			b.warn("%s from your environment is replaced by its declared placeholder", ph)
		}
		b.setVar(ph, ph, "declared placeholder, swapped for the value toward its bound hosts")
	}
}

// profiles applies the rendered tool profiles: their variables (never over
// one scrim run sets itself), the inherited variables they remove and their
// generated files.
func (b *builder) profiles() {
	r := b.in.Profiles
	if r == nil {
		return
	}
	b.plan.Profiles = slices.Clone(r.Profiles)
	b.plan.Warnings = append(b.plan.Warnings, r.Warnings...)
	for _, e := range r.Env {
		if _, taken := b.set[e.Name]; taken {
			b.warn("tool profile %s does not set %s: scrim run sets it itself", e.Profile, e.Name)
			continue
		}
		b.setVar(e.Name, e.Value, "tool profile "+e.Profile)
	}
	for name := range b.env {
		if _, set := b.set[name]; !set && profiles.Unsets(r.Unset, name) {
			b.unsetVar(name)
		}
	}
	for _, f := range r.Files {
		b.plan.Files[ProfilesDir+"/"+f.Path] = f.Data
	}
	for _, d := range r.Dirs {
		b.plan.Dirs = append(b.plan.Dirs, ProfilesDir+"/"+d)
	}
}

func appendHost(list []string, h string) []string {
	if !slices.Contains(list, h) {
		list = append(list, h)
	}
	return list
}

func appendPEM(dst, src []byte) []byte {
	if len(dst) > 0 && dst[len(dst)-1] != '\n' {
		dst = append(dst, '\n')
	}
	return append(dst, src...)
}

func envMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			m[k] = v
		}
	}
	return m
}

// Environ returns the agent's environment: inherited minus what the plan
// unsets or overrides, plus what it sets. token is the session token; it is
// required when the plan sets one. The returned slice holds the token, so
// it must go straight to the process start.
func (p *Plan) Environ(inherited []string, token secret.Value) ([]string, error) {
	drop := map[string]bool{}
	for _, n := range p.Unset {
		drop[n] = true
	}
	for _, v := range p.Set {
		drop[v.Name] = true
	}
	out := make([]string, 0, len(inherited)+len(p.Set))
	for _, kv := range inherited {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	for _, v := range p.Set {
		if !v.Secret {
			out = append(out, v.Name+"="+v.Value)
			continue
		}
		if token.IsZero() {
			return nil, fmt.Errorf("%s: no session token", v.Name)
		}
		// The process start needs the token as a string; this is the only
		// conversion, and it goes straight into the child's environment.
		_ = token.Expose(func(t []byte) error {
			if v.template == "" {
				out = append(out, v.Name+"="+string(t))
			} else {
				out = append(out, v.Name+"="+strings.ReplaceAll(v.template, TokenMarker, string(t)))
			}
			return nil
		})
	}
	return out, nil
}
