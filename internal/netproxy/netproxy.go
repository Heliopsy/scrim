// SPDX-License-Identifier: AGPL-3.0-only

// Package netproxy is scrim's upstream proxy: the HTTP proxy its own
// outbound connections go through on networks that only reach out through
// one (specs/interception "Outbound connections through an upstream
// proxy").
//
// One configuration serves both planes. The control plane's HTTP clients
// (stores, notifiers, audit sinks, identity and token endpoints, the admin
// client) use [Func], which this package installs as the Proxy of
// http.DefaultTransport at init, so every transport cloned from it and every
// client that uses it follows the proxy the daemon installed with [Install].
// The data plane receives the same proxy in its snapshot ([Proxy.Proto]) and
// tunnels provider, chain, tool-host and pass-through connections through
// it. TLS to the destination runs inside the CONNECT tunnel on both planes.
//
// The proxy comes from network.upstream-proxy.url, or when that is empty
// from the HTTPS_PROXY, https_proxy, HTTP_PROXY or http_proxy scrim itself
// was started with, with NO_PROXY added to network.upstream-proxy.no-proxy.
// network.upstream-proxy.url "direct" turns it off. Loopback is always
// reached directly. Credentials come from network.upstream-proxy.username
// and the secret reference network.upstream-proxy.password, or from the
// user info of the environment's proxy URL; the password is one of scrim's
// own credentials and is redacted from provider traffic (daemon package,
// scrimCredentials).
package netproxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/secret"
)

// Direct is the network.upstream-proxy.url value that turns the upstream
// proxy off, whatever scrim's environment says.
const Direct = "direct"

// Sources of the proxy in force.
const (
	SourceConfig      = "config"
	SourceEnvironment = "environment"
)

// EnvProxyVars are read, in order, for the proxy when
// network.upstream-proxy.url is empty.
var EnvProxyVars = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}

// EnvNoProxyVars are read, in order, for NO_PROXY entries with an
// environment proxy.
var EnvNoProxyVars = []string{"NO_PROXY", "no_proxy"}

// Loopback is always reached directly, on both planes.
var Loopback = []string{"localhost", "127.0.0.0/8", "::1"}

// Settings.
var (
	URL = config.Register(config.Spec[string]{
		Key: "network.upstream-proxy.url",
		Description: "HTTP proxy scrim's own outbound connections go through (providers, chained upstreams, tool hosts, stores, notifiers, audit sinks, identity endpoints): " +
			"http://host:port or https://host:port, as an HTTP CONNECT tunnel with TLS to the destination inside it. Empty takes HTTPS_PROXY (then https_proxy, HTTP_PROXY, http_proxy) " +
			"from scrim's own environment, with its NO_PROXY; `direct` connects directly whatever the environment says. Credentials go in username and password, never in the URL.",
		Validate: validURL,
	})
	NoProxy = config.Register(config.Spec[[]string]{
		Key:     "network.upstream-proxy.no-proxy",
		Default: []string{},
		Description: "Destinations reached directly rather than through the upstream proxy: a host name (also matching its subdomains), .domain (subdomains only), an IP address or CIDR range, " +
			"each optionally with :port, or * for all. Loopback is always direct. With the proxy from the environment, NO_PROXY is added.",
		Validate: validNoProxy,
	})
	Username = config.Register(config.Spec[string]{
		Key:         "network.upstream-proxy.username",
		Description: "User name sent to the upstream proxy (Basic Proxy-Authorization on every CONNECT), with network.upstream-proxy.password. Overrides the user info of an environment proxy URL.",
		Validate: func(s string) error {
			if strings.ContainsAny(s, ":\r\n") {
				return errors.New("must not contain ':' or a line break")
			}
			return nil
		},
	})
	Password = config.Register(config.Spec[config.SecretRef]{
		Key: "network.upstream-proxy.password",
		Description: "Reference to the upstream proxy password (env:, file:, cred: or a store reference; a store reference needs that store reachable without the proxy). " +
			"Redacted from provider traffic like scrim's other credentials.",
	})
)

func validURL(s string) error {
	if s == "" || s == Direct {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("must be http://host:port, https://host:port or direct")
	}
	if u.User != nil {
		return errors.New("must not hold credentials: set network.upstream-proxy.username and network.upstream-proxy.password")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not have a path, query or fragment")
	}
	if p := u.Port(); p != "" {
		if _, err := strconv.ParseUint(p, 10, 16); err != nil {
			return errors.New("port must be a number up to 65535")
		}
	}
	return nil
}

func validNoProxy(list []string) error {
	for _, e := range list {
		for part := range strings.SplitSeq(e, ",") {
			if err := ValidNoProxyEntry(part); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidNoProxyEntry checks one NO_PROXY entry with the rules the data plane
// applies (dataplane/crates/scrim-upstream-proxy, noproxy.rs): `*`, an IP
// address or CIDR range, or a host name of letters, digits, `.`, `-` and
// `_` with an optional leading `.` or `*.`, each optionally with `:port`
// (not a range). Empty entries are allowed and skipped.
func ValidNoProxyEntry(e string) error {
	e = strings.ToLower(strings.TrimSpace(e))
	if e == "" || e == "*" {
		return nil
	}
	bad := fmt.Errorf("no-proxy entry %q is not a host, address or CIDR range", e)
	if strings.Contains(e, "/") {
		ip, bits, ok := strings.Cut(e, "/")
		n, err := strconv.ParseUint(bits, 10, 8)
		addr := net.ParseIP(ip)
		if !ok || err != nil || addr == nil || (addr.To4() != nil && n > 32) || n > 128 {
			return bad
		}
		return nil
	}
	host := e
	if strings.HasPrefix(e, "[") {
		h, rest, ok := strings.Cut(e[1:], "]")
		if !ok || net.ParseIP(h) == nil {
			return bad
		}
		if rest != "" {
			p, ok := strings.CutPrefix(rest, ":")
			if _, err := strconv.ParseUint(p, 10, 16); !ok || err != nil {
				return bad
			}
		}
		return nil
	}
	if strings.Count(e, ":") > 1 {
		if net.ParseIP(e) == nil {
			return bad
		}
		return nil
	}
	if h, p, ok := strings.Cut(e, ":"); ok {
		if _, err := strconv.ParseUint(p, 10, 16); err != nil {
			return bad
		}
		host = h
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	host = strings.TrimPrefix(host, "*")
	if host == "" || host == "." {
		return bad
	}
	for _, c := range host {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' {
			return bad
		}
	}
	return nil
}

// Proxy is the upstream proxy configuration in effect. The zero value and
// nil connect directly.
type Proxy struct {
	// URL is scheme://host:port without user info; nil means direct.
	URL *url.URL
	// NoProxy is the effective list, loopback first.
	NoProxy []string
	// Username is the user name sent with every CONNECT, if any.
	Username string
	// Source is SourceConfig or SourceEnvironment.
	Source string
	// Skipped names environment NO_PROXY entries left out because the data
	// plane could not apply them (for example <local>).
	Skipped []string

	password secret.Value
	match    func(*url.URL) (*url.URL, error)
}

// Resolve reads the upstream proxy from cfg: network.upstream-proxy.* and,
// when the URL setting is empty, the environment cfg was built from. The
// Proxy owns a copy of the password; call Wipe when done with it.
func Resolve(cfg *config.Config) (*Proxy, error) {
	raw := URL.Get(cfg)
	p := &Proxy{Source: SourceConfig}
	noProxy := slices.Clone(NoProxy.Get(cfg))
	var envUser string
	var envPass secret.Value
	switch {
	case raw == Direct:
		return p, nil
	case raw != "":
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", URL.Name(), err)
		}
		p.URL = &url.URL{Scheme: u.Scheme, Host: u.Host}
	default:
		name, val := firstEnv(cfg, EnvProxyVars)
		if val == "" {
			return p, nil
		}
		p.Source = SourceEnvironment
		u, user, pass, err := parseEnvProxy(val)
		if err != nil {
			return nil, fmt.Errorf("%s in scrim's environment: %w; set %s to a supported proxy or to %s", name, err, URL.Name(), Direct)
		}
		p.URL, envUser, envPass = u, user, pass
		if _, np := firstEnv(cfg, EnvNoProxyVars); np != "" {
			for e := range strings.SplitSeq(np, ",") {
				if e = strings.TrimSpace(e); e == "" {
					continue
				}
				if ValidNoProxyEntry(e) != nil {
					p.Skipped = append(p.Skipped, e)
					continue
				}
				noProxy = append(noProxy, e)
			}
		}
	}
	if p.URL.Port() == "" {
		port := "80"
		if p.URL.Scheme == "https" {
			port = "443"
		}
		p.URL.Host = net.JoinHostPort(p.URL.Hostname(), port)
	}
	p.Username = envUser
	p.password = envPass
	if u := Username.Get(cfg); u != "" {
		p.Username = u
	}
	if v, ok := cfg.Secret(Password); ok {
		p.password.Wipe()
		_ = v.Expose(func(b []byte) error { p.password = secret.New(b); return nil })
	}
	if p.Username == "" && !p.password.IsZero() {
		p.Wipe()
		return nil, fmt.Errorf("%s is set without %s", Password.Name(), Username.Name())
	}
	p.NoProxy = append(slices.Clone(Loopback), noProxy...)
	p.compile()
	return p, nil
}

func firstEnv(cfg *config.Config, names []string) (string, string) {
	for _, n := range names {
		if v := strings.TrimSpace(cfg.Getenv(n)); v != "" {
			return n, v
		}
	}
	return "", ""
}

// parseEnvProxy accepts what curl and Go accept in HTTPS_PROXY: a URL with
// an http or https scheme, or host:port alone (http). User info becomes the
// credentials; a path is ignored.
func parseEnvProxy(v string) (*url.URL, string, secret.Value, error) {
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil || u.Hostname() == "" {
		return nil, "", secret.Value{}, errors.New("not a proxy URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", secret.Value{}, fmt.Errorf("scheme %s is not supported (http and https proxies are)", u.Scheme)
	}
	var user string
	var pass secret.Value
	if u.User != nil {
		user = u.User.Username()
		if pw, ok := u.User.Password(); ok && pw != "" {
			pass = secret.New([]byte(pw))
		}
	}
	if strings.Contains(user, ":") {
		pass.Wipe()
		return nil, "", secret.Value{}, errors.New("user name must not contain ':'")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, user, pass, nil
}

func (p *Proxy) compile() {
	if p.URL == nil {
		return
	}
	c := httpproxy.Config{HTTPProxy: p.URL.String(), HTTPSProxy: p.URL.String(), NoProxy: strings.Join(p.NoProxy, ",")}
	p.match = c.ProxyFunc()
}

// Enabled reports whether connections go through a proxy at all.
func (p *Proxy) Enabled() bool { return p != nil && p.URL != nil }

// String is the proxy URL without credentials, or "direct".
func (p *Proxy) String() string {
	if !p.Enabled() {
		return Direct
	}
	return p.URL.String()
}

// HasCredentials reports whether CONNECT carries a user name.
func (p *Proxy) HasCredentials() bool { return p.Enabled() && p.Username != "" }

// Password returns the proxy password; the Proxy owns it. Zero without one.
func (p *Proxy) Password() secret.Value {
	if p == nil {
		return secret.Value{}
	}
	return p.password
}

// ProxyURL returns the proxy for a request to target, nil for a direct
// connection. The URL carries the credentials as user info: Go's transport
// takes them from there for the Proxy-Authorization header, so they are
// copied into strings for the connection (docs/limitations.md).
func (p *Proxy) ProxyURL(target *url.URL) (*url.URL, error) {
	if !p.Enabled() || p.match == nil {
		return nil, nil
	}
	pu, err := p.match(target)
	if err != nil || pu == nil {
		return pu, err
	}
	out := *pu
	if p.Username != "" {
		pw := ""
		_ = p.password.Expose(func(b []byte) error { pw = string(b); return nil })
		out.User = url.UserPassword(p.Username, pw)
	}
	return &out, nil
}

// Proto is the proxy for the data plane snapshot, nil for direct. The
// password is a fresh copy: the snapshot's sender wipes it.
func (p *Proxy) Proto() *pb.UpstreamProxy {
	if !p.Enabled() {
		return nil
	}
	out := &pb.UpstreamProxy{Url: p.URL.String(), NoProxy: slices.Clone(p.NoProxy), Username: p.Username}
	_ = p.password.Expose(func(b []byte) error {
		if len(b) > 0 {
			out.Password = slices.Clone(b)
		}
		return nil
	})
	return out
}

// Wipe clears the Proxy's copy of the password.
func (p *Proxy) Wipe() {
	if p != nil {
		p.password.Wipe()
	}
}

var current atomic.Pointer[Proxy]

// retireAfter is how long a replaced Proxy keeps its password, for requests
// that read it just before the replacement.
var retireAfter = time.Minute

func init() {
	// Every transport cloned from the default one, and every client that
	// uses it, asks Func. Done at init, before any request, so the field is
	// never written while a request reads it.
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.Proxy = Func
	}
}

// Func is the Proxy function of scrim's HTTP transports: the proxy
// installed with Install, or before any, Go's ProxyFromEnvironment (what a
// command that starts no daemon has always used).
func Func(req *http.Request) (*url.URL, error) {
	p := current.Load()
	if p == nil {
		return http.ProxyFromEnvironment(req)
	}
	return p.ProxyURL(req.URL)
}

// Install makes p the proxy Func uses; nil returns to ProxyFromEnvironment.
// The previous Proxy's password is wiped a minute later. The returned
// function uninstalls p if it is still installed.
func Install(p *Proxy) (uninstall func()) {
	old := current.Swap(p)
	retire(old, p)
	return func() {
		if current.CompareAndSwap(p, nil) {
			retire(p, nil)
		}
	}
}

func retire(old, cur *Proxy) {
	if old == nil || old == cur {
		return
	}
	time.AfterFunc(retireAfter, old.Wipe)
}

// Current is the installed Proxy, nil before Install.
func Current() *Proxy { return current.Load() }
