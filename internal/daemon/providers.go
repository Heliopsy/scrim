// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/stores"
)

// Cloud provider kinds (llm-proxy spec, "Cloud provider routes").
const (
	// ProviderBedrock is Amazon Bedrock's runtime API: InvokeModel and
	// Converse, streaming over Amazon's event stream.
	ProviderBedrock = "bedrock"
	// ProviderBedrockMantle is Bedrock's Mantle endpoint, which serves the
	// Anthropic Messages API.
	ProviderBedrockMantle = "bedrock-mantle"
	// ProviderAnthropicAWS is Claude Platform on AWS, the Anthropic API with
	// AWS authentication.
	ProviderAnthropicAWS = "anthropic-aws"
	// ProviderFoundry is Microsoft Foundry's Anthropic endpoint.
	ProviderFoundry = "foundry"
)

// ProviderKinds lists the kinds a providers instance can name.
var ProviderKinds = []string{ProviderAnthropicAWS, ProviderBedrock, ProviderBedrockMantle, ProviderFoundry}

const providersKey = "providers"

// Fields of a providers instance.
const (
	pfKind            = "kind"
	pfRegion          = "region"
	pfResource        = "resource"
	pfUpstream        = "upstream"
	pfAccessKeyID     = "access-key-id"
	pfSecretAccessKey = "secret-access-key"
	pfSessionToken    = "session-token"
	pfAPIKey          = "api-key"
)

var providerFields = []string{pfKind, pfRegion, pfResource, pfUpstream, pfAccessKeyID, pfSecretAccessKey, pfSessionToken, pfAPIKey}

// Providers are the cloud provider routes.
var Providers = config.RegisterCollection(config.CollectionSpec{
	Key: providersKey,
	Description: "Cloud provider routes by name, each served at `/<name>` on the LLM base URL and for its provider host through the forward proxy. " +
		"`kind` is `bedrock` (Amazon Bedrock runtime), `bedrock-mantle`, `anthropic-aws` (Claude Platform on AWS) or `foundry` (Microsoft Foundry). " +
		"`region` (AWS kinds) or `resource` (foundry) selects the endpoint, `upstream` overrides it. " +
		"scrim authenticates every request itself after redaction and drops what the agent sent: " +
		"`access-key-id`, `secret-access-key` and optional `session-token` sign with AWS SigV4 (AWS kinds), or `api-key` sends a key " +
		"(Bedrock and Claude Platform on AWS as a bearer token, Foundry as `api-key`). Credential fields are store references, never values. " +
		"Provider routes are never chained.",
	RequiredFields: []string{pfKind},
	Validate: func(inst config.Instance) error {
		_, err := providerOf(inst)
		return err
	},
	FieldSchemas: map[string]map[string]any{
		pfKind:            {"type": "string", "enum": ProviderKinds},
		pfRegion:          {"type": "string", "pattern": `^[a-z0-9-]+$`},
		pfResource:        {"type": "string", "pattern": `^[a-z0-9][a-z0-9-]*$`},
		pfUpstream:        {"type": "string", "format": "uri"},
		pfAccessKeyID:     {"type": "string", "description": "Store reference to the AWS access key id."},
		pfSecretAccessKey: {"type": "string", "description": "Store reference to the AWS secret access key."},
		pfSessionToken:    {"type": "string", "description": "Store reference to the AWS session token."},
		pfAPIKey:          {"type": "string", "description": "Store reference to the provider API key."},
	},
})

// CloudProvider is one configured cloud provider route.
type CloudProvider struct {
	Name     string
	Kind     string
	Region   string
	Resource string
	// Upstream is the provider origin requests go to.
	Upstream string
	// SigV4 credentials (AWS kinds), or APIKey.
	AccessKeyID, SecretAccessKey, SessionToken stores.Ref
	APIKey                                     stores.Ref
}

var (
	regionPattern   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	resourcePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	reservedRoutes  = []string{"anthropic", "openai", "gemini", "chatgpt", "chatgpt-ab"}
)

func providerOf(inst config.Instance) (CloudProvider, error) {
	p := CloudProvider{Name: inst.Name, Kind: inst.String(pfKind), Region: inst.String(pfRegion),
		Resource: inst.String(pfResource), Upstream: inst.String(pfUpstream)}
	where := func(f string) string { return inst.Key(providersKey, f) }
	for k := range inst.Fields {
		if !slices.Contains(providerFields, k) {
			return p, fmt.Errorf("%s.%s: unknown field %s", providersKey, inst.Name, k)
		}
	}
	if slices.Contains(reservedRoutes, inst.Name) {
		return p, fmt.Errorf("%s.%s: the name is taken by a built-in route", providersKey, inst.Name)
	}
	if !slices.Contains(ProviderKinds, p.Kind) {
		return p, fmt.Errorf("%s: must be one of %s", where(pfKind), strings.Join(ProviderKinds, ", "))
	}
	aws := p.Kind != ProviderFoundry
	switch {
	case aws && p.Resource != "":
		return p, fmt.Errorf("%s: only for kind foundry", where(pfResource))
	case !aws && p.Region != "":
		return p, fmt.Errorf("%s: only for AWS kinds", where(pfRegion))
	case p.Region != "" && !regionPattern.MatchString(p.Region):
		return p, fmt.Errorf("%s: %q is not an AWS region", where(pfRegion), p.Region)
	case p.Resource != "" && !resourcePattern.MatchString(p.Resource):
		return p, fmt.Errorf("%s: must be the Foundry resource name alone, not a URL or host", where(pfResource))
	case aws && p.Region == "":
		return p, fmt.Errorf("%s: required for kind %s (it is part of the signature)", where(pfRegion), p.Kind)
	}
	if p.Upstream != "" {
		u, err := url.Parse(p.Upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || strings.Trim(u.Path, "/") != "" {
			return p, fmt.Errorf("%s: must be an http or https origin without a path", where(pfUpstream))
		}
		p.Upstream = strings.TrimRight(p.Upstream, "/")
	} else {
		switch p.Kind {
		case ProviderBedrock:
			p.Upstream = "https://bedrock-runtime." + p.Region + ".amazonaws.com"
		case ProviderBedrockMantle:
			p.Upstream = "https://bedrock-mantle." + p.Region + ".api.aws"
		case ProviderAnthropicAWS:
			p.Upstream = "https://aws-external-anthropic." + p.Region + ".api.aws"
		case ProviderFoundry:
			if p.Resource == "" {
				return p, fmt.Errorf("%s: required for kind foundry without an upstream", where(pfResource))
			}
			p.Upstream = "https://" + p.Resource + ".services.ai.azure.com"
		}
	}
	ref := func(f string) (stores.Ref, error) {
		s := inst.String(f)
		if s == "" {
			return stores.Ref{}, nil
		}
		r, err := stores.ParseRef(s)
		if err != nil {
			return r, fmt.Errorf("%s: must be a store reference: %w", where(f), err)
		}
		return r, nil
	}
	var err error
	if p.AccessKeyID, err = ref(pfAccessKeyID); err != nil {
		return p, err
	}
	if p.SecretAccessKey, err = ref(pfSecretAccessKey); err != nil {
		return p, err
	}
	if p.SessionToken, err = ref(pfSessionToken); err != nil {
		return p, err
	}
	if p.APIKey, err = ref(pfAPIKey); err != nil {
		return p, err
	}
	sig := !p.AccessKeyID.IsZero() || !p.SecretAccessKey.IsZero() || !p.SessionToken.IsZero()
	switch {
	case sig && !aws:
		return p, fmt.Errorf("%s.%s: AWS keys only sign for AWS kinds; foundry takes api-key", providersKey, inst.Name)
	case sig && (p.AccessKeyID.IsZero() || p.SecretAccessKey.IsZero()):
		return p, fmt.Errorf("%s.%s: access-key-id and secret-access-key go together", providersKey, inst.Name)
	case sig && !p.APIKey.IsZero():
		return p, fmt.Errorf("%s.%s: set either the AWS keys or api-key, not both", providersKey, inst.Name)
	case !sig && p.APIKey.IsZero():
		return p, errors.New(providersKey + "." + inst.Name + ": needs credentials: access-key-id and secret-access-key, or api-key")
	}
	return p, nil
}

// CloudProviders returns the configured provider routes, by name. The
// collection validated each at load; one that fails here is skipped.
func CloudProviders(cfg *config.Config) []CloudProvider {
	var out []CloudProvider
	for _, inst := range Providers.Get(cfg) {
		if p, err := providerOf(inst); err == nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sigv4Service is the signing name of an AWS kind.
func sigv4Service(kind string) string {
	switch kind {
	case ProviderBedrock:
		return "bedrock"
	case ProviderBedrockMantle:
		return "bedrock-mantle"
	case ProviderAnthropicAWS:
		return "aws-external-anthropic"
	}
	return ""
}

// Route is the data plane route of the provider: the request codec, its
// prefix and host, and the authentication scrim adds after redaction.
func (p CloudProvider) Route() *pb.Route {
	provider := "anthropic"
	if p.Kind == ProviderBedrock {
		provider = "bedrock"
	}
	r := &pb.Route{Name: p.Name, Provider: provider, Upstream: p.Upstream, PathPrefix: "/" + p.Name, Auth: &pb.RouteAuth{}}
	if u, err := url.Parse(p.Upstream); err == nil && u.Hostname() != "" {
		r.Hosts = []string{u.Hostname()}
	}
	switch {
	case !p.APIKey.IsZero() && p.Kind == ProviderFoundry:
		r.Auth.Kind = &pb.RouteAuth_Header{Header: &pb.HeaderAuth{Name: "api-key", ValueRef: p.APIKey.String()}}
	case !p.APIKey.IsZero():
		r.Auth.Kind = &pb.RouteAuth_Header{Header: &pb.HeaderAuth{Name: "authorization", Prefix: "Bearer ", ValueRef: p.APIKey.String()}}
	default:
		s := &pb.AwsSigV4Auth{Region: p.Region, Service: sigv4Service(p.Kind),
			AccessKeyIdRef: p.AccessKeyID.String(), SecretAccessKeyRef: p.SecretAccessKey.String()}
		if !p.SessionToken.IsZero() {
			s.SessionTokenRef = p.SessionToken.String()
		}
		r.Auth.Kind = &pb.RouteAuth_AwsSigv4{AwsSigv4: s}
	}
	return r
}

// Refs are the store references the provider authenticates with.
func (p CloudProvider) Refs() []stores.Ref {
	var out []stores.Ref
	for _, r := range []stores.Ref{p.AccessKeyID, p.SecretAccessKey, p.SessionToken, p.APIKey} {
		if !r.IsZero() {
			out = append(out, r)
		}
	}
	return out
}

// ProviderRoutes maps each cloud provider kind to the path prefix of its
// first route, for scrim run.
func ProviderRoutes(cfg *config.Config) map[string]string {
	out := map[string]string{}
	for _, p := range CloudProviders(cfg) {
		if _, ok := out[p.Kind]; !ok {
			out[p.Kind] = "/" + p.Name
		}
	}
	return out
}
