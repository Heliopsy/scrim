// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores"
)

// Settings the daemon reads. Listener addresses need a restart; the data
// plane routes, chaining, capture and capture rules follow a reload.
var (
	// ProxyListen is the LLM proxy's base URL listener.
	ProxyListen = config.Register(config.Spec[string]{
		Key:             "proxy.listen",
		Default:         "127.0.0.1:9790",
		Description:     "TCP address of the LLM proxy base URL (agents use http://<address>/anthropic and http://<address>/openai/v1). Empty disables it; keep it on loopback.",
		Flag:            true,
		RestartRequired: true,
		Validate:        optionalHostPort,
	})
	// ProxySocket is the LLM proxy's base URL on a Unix socket.
	ProxySocket = config.Register(config.Spec[string]{
		Key:             "proxy.socket",
		Description:     "Unix socket path for the LLM proxy base URL, for agents that can connect to one. Empty disables it.",
		Flag:            true,
		RestartRequired: true,
	})
	// ForwardListen is the forward proxy (CONNECT with TLS interception).
	ForwardListen = config.Register(config.Spec[string]{
		Key:             "proxy.forward-listen",
		Description:     "TCP address of the forward proxy for agents with HTTPS_PROXY set: provider hosts go to the LLM proxy, every other host to the tool proxy. Empty disables it.",
		Flag:            true,
		RestartRequired: true,
		Validate:        optionalHostPort,
	})
	// ToolProxyListen is the HTTPS tool proxy alone.
	ToolProxyListen = config.Register(config.Spec[string]{
		Key:             "tool-proxy.listen",
		Description:     "TCP address of the HTTPS tool proxy (credential injection and response redaction) for tools pointed at it directly. Empty disables it.",
		Flag:            true,
		RestartRequired: true,
		Validate:        optionalHostPort,
	})
	// UpstreamAnthropic is where Anthropic requests are forwarded.
	UpstreamAnthropic = config.Register(config.Spec[string]{
		Key:         "proxy.upstream.anthropic",
		Default:     "https://api.anthropic.com",
		Description: "Base URL Anthropic Messages requests are forwarded to after redaction.",
		Validate:    httpURL,
	})
	// UpstreamOpenAI is where OpenAI requests are forwarded.
	UpstreamOpenAI = config.Register(config.Spec[string]{
		Key:         "proxy.upstream.openai",
		Default:     "https://api.openai.com",
		Description: "Base URL OpenAI Chat Completions and Responses requests are forwarded to after redaction.",
		Validate:    httpURL,
	})
	// ChainURL is an optional chained upstream for every route.
	ChainURL = config.Register(config.Spec[string]{
		Key:         "proxy.chain.url",
		Description: "Base URL of a chained upstream (for example a context compression proxy) that receives every redacted provider request in place of the provider. Empty means no chain.",
		Validate: func(s string) error {
			if s == "" {
				return nil
			}
			return httpURL(s)
		},
	})
	// ChainOnUnavailable decides what happens when the chain is down.
	ChainOnUnavailable = config.Register(config.Spec[string]{
		Key:         "proxy.chain.on-unavailable",
		Default:     "fail",
		Enum:        []string{"fail", "direct"},
		Description: "When the chained upstream cannot be reached: fail refuses the request, direct sends the already redacted request to the provider and audits the skip.",
	})
	// CaptureDir turns on capture mode.
	CaptureDir = config.Register(config.Spec[string]{
		Key:         "proxy.capture.dir",
		Description: "Capture mode: write every provider request exactly as it left, and the response as received, to this directory (mode 0700; refused if group or others can access it). Empty disables capture. `scrim proxy --capture DIR` sets it.",
		Flag:        true,
	})
	// CaptureRetention bounds how long captures are kept.
	CaptureRetention = config.Register(config.Spec[time.Duration]{
		Key:         "proxy.capture.retention",
		Default:     7 * 24 * time.Hour,
		Description: "Captured files older than this are deleted.",
		Validate: func(d time.Duration) error {
			if d < time.Minute {
				return errors.New("must be at least 1m")
			}
			return nil
		},
	})
	// MinValueLength is the matcher's minimum length for free-text matches.
	MinValueLength = config.Register(config.Spec[int]{
		Key:         "redaction.min-value-length",
		Default:     8,
		Description: "Shortest value matched in free text; shorter values are matched only in exact and encoded forms.",
		Validate: func(n int) error {
			if n < 1 || n > 1024 {
				return errors.New("must be between 1 and 1024")
			}
			return nil
		},
	})
	// PushDebounce batches snapshot pushes.
	PushDebounce = config.Register(config.Spec[time.Duration]{
		Key:         "dataplane.push-debounce",
		Default:     200 * time.Millisecond,
		Description: "How long the control plane waits after a store, catalog, configuration or policy change before it pushes a new snapshot, so bursts of changes become one push.",
		Validate: func(d time.Duration) error {
			if d < 0 || d > time.Minute {
				return errors.New("must be between 0 and 1m")
			}
			return nil
		},
	})
	// AdminToken authenticates operators on a TCP admin listener.
	AdminToken = config.Register(config.Spec[config.SecretRef]{
		Key:         "admin.token",
		Description: "Reference to the bearer token operators present on a TCP admin listener (admin.url http://host:port). Required for TCP; the Unix socket uses peer credentials instead. scrim approve and friends send it.",
	})
	// DecisionListen serves the decision links approvers open.
	DecisionListen = config.Register(config.Spec[string]{
		Key:             "approvals.listen",
		Description:     "TCP address that serves only the decision-link endpoint, for approvals.public-url to point at (usually through a TLS reverse proxy). Empty means decision links are served on the admin listener only.",
		Flag:            true,
		RestartRequired: true,
		Validate:        optionalHostPort,
	})
	// CaptureRules store values tool-proxy responses return.
	CaptureRules = config.RegisterCollection(config.CollectionSpec{
		Key: captureRulesKey,
		Description: "Response capture rules by name: `hosts`, optional `methods`, `path` glob and `status` codes select the response; " +
			"exactly one of `json-pointer` and `header` selects the field; `store-ref` is the store reference the value is written to. " +
			"The agent receives the reference's placeholder instead.",
		RequiredFields: []string{"hosts", "store-ref"},
		Validate: func(inst config.Instance) error {
			_, err := captureRuleOf(inst)
			return err
		},
	})
)

const captureRulesKey = "tool-proxy.capture-rules"

func optionalHostPort(s string) error {
	if s == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("must be host:port")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil || host == "" {
		return errors.New("must be host:port")
	}
	return nil
}

func httpURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("must be an absolute http or https URL")
	}
	return nil
}

// CaptureRule is one tool-proxy capture rule from configuration.
type CaptureRule struct {
	Name        string
	Hosts       []string
	Methods     []string
	Path        string
	Status      []uint32
	JSONPointer string
	Header      string
	StoreRef    stores.Ref
}

func captureRuleOf(inst config.Instance) (CaptureRule, error) {
	r := CaptureRule{Name: inst.Name, Path: inst.String("path"), JSONPointer: inst.String("json-pointer"), Header: inst.String("header")}
	where := func(f string) string { return inst.Key(captureRulesKey, f) }
	var err error
	if r.Hosts, err = stringList(inst, "hosts"); err != nil || len(r.Hosts) == 0 {
		return r, fmt.Errorf("%s: must list at least one host", where("hosts"))
	}
	if r.Methods, err = stringList(inst, "methods"); err != nil {
		return r, fmt.Errorf("%s: %w", where("methods"), err)
	}
	for i, m := range r.Methods {
		r.Methods[i] = strings.ToUpper(m)
	}
	if raw, ok := inst.Field("status"); ok {
		list, ok := raw.([]any)
		if !ok {
			return r, fmt.Errorf("%s: must be a list of status codes", where("status"))
		}
		for _, v := range list {
			n, ok := asInt(v)
			if !ok || n < 100 || n > 599 {
				return r, fmt.Errorf("%s: %v is not an HTTP status", where("status"), v)
			}
			r.Status = append(r.Status, uint32(n)) //nolint:gosec // checked above
		}
	}
	if (r.JSONPointer == "") == (r.Header == "") {
		return r, fmt.Errorf("tool-proxy.capture-rules.%s: set exactly one of json-pointer and header", inst.Name)
	}
	if r.JSONPointer != "" && !strings.HasPrefix(r.JSONPointer, "/") {
		return r, fmt.Errorf("%s: must be an RFC 6901 pointer starting with /", where("json-pointer"))
	}
	ref, err := stores.ParseRef(inst.String("store-ref"))
	if err != nil {
		return r, fmt.Errorf("%s: %w", where("store-ref"), err)
	}
	r.StoreRef = ref
	known := map[string]bool{"hosts": true, "methods": true, "path": true, "status": true, "json-pointer": true, "header": true, "store-ref": true}
	for k := range inst.Fields {
		if !known[k] {
			return r, fmt.Errorf("tool-proxy.capture-rules.%s: unknown field %s", inst.Name, k)
		}
	}
	return r, nil
}

func stringList(inst config.Instance, field string) ([]string, error) {
	raw, ok := inst.Field(field)
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		var out []string
		for s := range strings.SplitSeq(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, errors.New("must be a list of strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, errors.New("must be a list of strings")
}

func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case float64:
		return int(x), float64(int(x)) == x
	case string:
		n, err := strconv.Atoi(x)
		return n, err == nil
	}
	return 0, false
}

// captureRules returns the configured rules. The collection validated each
// at load, so errors here mean a programming mistake; such a rule is skipped.
func captureRules(cfg *config.Config) []CaptureRule {
	var out []CaptureRule
	for _, inst := range CaptureRules.Get(cfg) {
		if r, err := captureRuleOf(inst); err == nil {
			out = append(out, r)
		}
	}
	return out
}
