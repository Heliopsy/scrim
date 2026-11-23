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

	"github.com/heliopsy/scrim/internal/app"
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
	// ProviderVertex is Google Vertex AI: Claude through rawPredict and
	// streamRawPredict, Gemini through generateContent.
	ProviderVertex = "vertex"
)

// ProviderKinds lists the kinds a providers instance can name.
var ProviderKinds = []string{ProviderAnthropicAWS, ProviderBedrock, ProviderBedrockMantle, ProviderFoundry, ProviderVertex}

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
	pfServiceAccount  = "service-account"
	pfMetadataServer  = "metadata-server"
	pfTenantID        = "tenant-id"
	pfClientID        = "client-id"
	pfClientSecret    = "client-secret"
	pfTokenURL        = "token-url"
)

var providerFields = []string{pfKind, pfRegion, pfResource, pfUpstream, pfAccessKeyID, pfSecretAccessKey, pfSessionToken, pfAPIKey,
	pfServiceAccount, pfMetadataServer, pfTenantID, pfClientID, pfClientSecret, pfTokenURL}

// Providers are the cloud provider routes.
var Providers = config.RegisterCollection(config.CollectionSpec{
	Key: providersKey,
	Description: "Cloud provider routes by name, each served at `/<name>` on the LLM base URL and for its provider host through the forward proxy. " +
		"`kind` is `bedrock` (Amazon Bedrock runtime), `bedrock-mantle`, `anthropic-aws` (Claude Platform on AWS), `foundry` (Microsoft Foundry) or `vertex` (Google Vertex AI). " +
		"`region` (AWS kinds, and the Vertex location) or `resource` (foundry) selects the endpoint, `upstream` overrides it. " +
		"scrim authenticates every request itself after redaction and drops what the agent sent: " +
		"`access-key-id`, `secret-access-key` and optional `session-token` sign with AWS SigV4 (AWS kinds); `api-key` sends a key " +
		"(Bedrock and Claude Platform on AWS as a bearer token, Foundry as `api-key`); `service-account` (a JSON key file) or `metadata-server: true` " +
		"mints Google access tokens (vertex); `tenant-id`, `client-id` and `client-secret` mint Entra ID tokens (foundry). `token-url` overrides the token endpoint. " +
		"Credential fields are store references, never values. " +
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
		pfServiceAccount:  {"type": "string", "description": "Store reference to a Google service account key (the JSON key file)."},
		pfMetadataServer:  {"type": "boolean", "description": "Take Google access tokens from the metadata server (workload identity)."},
		pfTenantID:        {"type": "string", "description": "Entra ID tenant (directory) id."},
		pfClientID:        {"type": "string", "description": "Entra ID application (client) id."},
		pfClientSecret:    {"type": "string", "description": "Store reference to the Entra ID client secret."},
		pfTokenURL:        {"type": "string", "format": "uri", "description": "Token endpoint replacing the default (Google, Entra ID, or the metadata server)."},
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
	// ServiceAccount or MetadataServer mint Google tokens (vertex).
	ServiceAccount stores.Ref
	MetadataServer bool
	// TenantID, ClientID and ClientSecret mint Entra ID tokens (foundry).
	TenantID, ClientID string
	ClientSecret       stores.Ref
	// TokenURL replaces the default token endpoint.
	TokenURL string
}

var (
	regionPattern   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	locationPattern = regexp.MustCompile(`^(global|us|eu|[a-z]+-[a-z]+[0-9]+)$`)
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)
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
	if err := p.endpoint(where); err != nil {
		return p, err
	}
	if err := p.credentials(inst, where); err != nil {
		return p, err
	}
	return p, nil
}

func (p *CloudProvider) aws() bool {
	return p.Kind == ProviderBedrock || p.Kind == ProviderBedrockMantle || p.Kind == ProviderAnthropicAWS
}

// endpoint checks region, resource and upstream and fills the default
// upstream.
func (p *CloudProvider) endpoint(where func(string) string) error {
	switch {
	case p.Kind != ProviderFoundry && p.Resource != "":
		return fmt.Errorf("%s: only for kind foundry", where(pfResource))
	case p.Kind == ProviderFoundry && p.Region != "":
		return fmt.Errorf("%s: not for kind foundry", where(pfRegion))
	case p.aws() && p.Region != "" && !regionPattern.MatchString(p.Region):
		return fmt.Errorf("%s: %q is not an AWS region", where(pfRegion), p.Region)
	case p.Kind == ProviderVertex && p.Region != "" && !locationPattern.MatchString(p.Region):
		return fmt.Errorf("%s: %q is not a Vertex AI location (global, us, eu or a region such as us-east5)", where(pfRegion), p.Region)
	case p.Resource != "" && !resourcePattern.MatchString(p.Resource):
		return fmt.Errorf("%s: must be the Foundry resource name alone, not a URL or host", where(pfResource))
	case p.aws() && p.Region == "":
		return fmt.Errorf("%s: required for kind %s (it is part of the signature)", where(pfRegion), p.Kind)
	}
	if p.Upstream != "" {
		u, err := url.Parse(p.Upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || strings.Trim(u.Path, "/") != "" {
			return fmt.Errorf("%s: must be an http or https origin without a path", where(pfUpstream))
		}
		p.Upstream = strings.TrimRight(p.Upstream, "/")
		return nil
	}
	switch p.Kind {
	case ProviderBedrock:
		p.Upstream = "https://bedrock-runtime." + p.Region + ".amazonaws.com"
	case ProviderBedrockMantle:
		p.Upstream = "https://bedrock-mantle." + p.Region + ".api.aws"
	case ProviderAnthropicAWS:
		p.Upstream = "https://aws-external-anthropic." + p.Region + ".api.aws"
	case ProviderVertex:
		switch p.Region {
		case "":
			return fmt.Errorf("%s: required for kind vertex without an upstream", where(pfRegion))
		case "global":
			p.Upstream = "https://aiplatform.googleapis.com"
		case "us", "eu":
			p.Upstream = "https://aiplatform." + p.Region + ".rep.googleapis.com"
		default:
			p.Upstream = "https://" + p.Region + "-aiplatform.googleapis.com"
		}
	case ProviderFoundry:
		if p.Resource == "" {
			return fmt.Errorf("%s: required for kind foundry without an upstream", where(pfResource))
		}
		p.Upstream = "https://" + p.Resource + ".services.ai.azure.com"
	}
	return nil
}

// credentials reads the credential fields: exactly one way to authenticate
// that the kind supports.
func (p *CloudProvider) credentials(inst config.Instance, where func(string) string) error {
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
	for f, dst := range map[string]*stores.Ref{pfAccessKeyID: &p.AccessKeyID, pfSecretAccessKey: &p.SecretAccessKey,
		pfSessionToken: &p.SessionToken, pfAPIKey: &p.APIKey, pfServiceAccount: &p.ServiceAccount, pfClientSecret: &p.ClientSecret} {
		r, err := ref(f)
		if err != nil {
			return err
		}
		*dst = r
	}
	if raw, ok := inst.Field(pfMetadataServer); ok {
		b, isBool := raw.(bool)
		if !isBool {
			return fmt.Errorf("%s: must be true or false", where(pfMetadataServer))
		}
		p.MetadataServer = b
	}
	p.TenantID, p.ClientID, p.TokenURL = inst.String(pfTenantID), inst.String(pfClientID), inst.String(pfTokenURL)
	if p.TokenURL != "" {
		if u, err := url.Parse(p.TokenURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s: must be an absolute http or https URL", where(pfTokenURL))
		}
	}
	name := providersKey + "." + inst.Name
	sig := !p.AccessKeyID.IsZero() || !p.SecretAccessKey.IsZero() || !p.SessionToken.IsZero()
	google := !p.ServiceAccount.IsZero() || p.MetadataServer
	entra := p.TenantID != "" || p.ClientID != "" || !p.ClientSecret.IsZero()
	ways := 0
	for _, b := range []bool{sig, !p.APIKey.IsZero(), google, entra} {
		if b {
			ways++
		}
	}
	switch {
	case ways > 1 || (!p.ServiceAccount.IsZero() && p.MetadataServer):
		return fmt.Errorf("%s: set one way to authenticate", name)
	case sig && !p.aws():
		return fmt.Errorf("%s: AWS keys only sign for AWS kinds", name)
	case sig && (p.AccessKeyID.IsZero() || p.SecretAccessKey.IsZero()):
		return fmt.Errorf("%s: access-key-id and secret-access-key go together", name)
	case google && p.Kind != ProviderVertex:
		return fmt.Errorf("%s: service-account and metadata-server are for kind vertex", name)
	case entra && p.Kind != ProviderFoundry:
		return fmt.Errorf("%s: tenant-id, client-id and client-secret are for kind foundry", name)
	case entra && (p.ClientID == "" || p.ClientSecret.IsZero() || (p.TenantID == "" && p.TokenURL == "")):
		return fmt.Errorf("%s: Entra ID needs tenant-id, client-id and client-secret", name)
	case p.TenantID != "" && !idPattern.MatchString(p.TenantID):
		return fmt.Errorf("%s: not a tenant id", where(pfTenantID))
	case p.ClientID != "" && !idPattern.MatchString(p.ClientID):
		return fmt.Errorf("%s: not a client id", where(pfClientID))
	case !p.APIKey.IsZero() && p.Kind == ProviderVertex:
		return fmt.Errorf("%s: vertex takes service-account or metadata-server", name)
	case p.TokenURL != "" && !google && !entra:
		return fmt.Errorf("%s: only with service-account, metadata-server or Entra ID", where(pfTokenURL))
	case ways == 0 && p.Kind == ProviderVertex:
		return errors.New(name + ": needs credentials: service-account or metadata-server: true")
	case ways == 0 && p.Kind == ProviderFoundry:
		return errors.New(name + ": needs credentials: api-key, or tenant-id, client-id and client-secret")
	case ways == 0:
		return errors.New(name + ": needs credentials: access-key-id and secret-access-key, or api-key")
	}
	return nil
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
	switch p.Kind {
	case ProviderBedrock:
		provider = "bedrock"
	case ProviderVertex:
		provider = "vertex"
	}
	r := &pb.Route{Name: p.Name, Provider: provider, Upstream: p.Upstream, PathPrefix: "/" + p.Name, Auth: &pb.RouteAuth{}}
	if u, err := url.Parse(p.Upstream); err == nil && u.Hostname() != "" {
		r.Hosts = []string{u.Hostname()}
	}
	switch {
	case !p.ServiceAccount.IsZero():
		r.Auth.Kind = &pb.RouteAuth_GoogleServiceAccount{GoogleServiceAccount: &pb.GoogleServiceAccountAuth{
			KeyRef: p.ServiceAccount.String(), TokenUrl: p.TokenURL}}
	case p.MetadataServer:
		r.Auth.Kind = &pb.RouteAuth_GoogleMetadata{GoogleMetadata: &pb.GoogleMetadataAuth{Url: p.TokenURL}}
	case !p.ClientSecret.IsZero():
		tok := p.TokenURL
		if tok == "" {
			tok = "https://login.microsoftonline.com/" + p.TenantID + "/oauth2/v2.0/token"
		}
		r.Auth.Kind = &pb.RouteAuth_EntraClientSecret{EntraClientSecret: &pb.EntraClientSecretAuth{
			TokenUrl: tok, ClientId: p.ClientID, ClientSecretRef: p.ClientSecret.String()}}
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

func init() { app.AddRedactRefs(providerStoreRefs) }

// providerStoreRefs lists the credential references of every cloud
// provider. Each is a redact target of its store, so the value is loaded
// with the store, refreshed with it and in the snapshot for the route.
func providerStoreRefs(cfg *config.Config) []string {
	var out []string
	for _, p := range CloudProviders(cfg) {
		for _, r := range p.Refs() {
			out = append(out, r.String())
		}
	}
	return out
}

// refFields are the provider's credential references by field name.
func (p CloudProvider) refFields() map[string]stores.Ref {
	out := map[string]stores.Ref{}
	for f, r := range map[string]stores.Ref{pfAccessKeyID: p.AccessKeyID, pfSecretAccessKey: p.SecretAccessKey,
		pfSessionToken: p.SessionToken, pfAPIKey: p.APIKey, pfServiceAccount: p.ServiceAccount, pfClientSecret: p.ClientSecret} {
		if !r.IsZero() {
			out[f] = r
		}
	}
	return out
}

// Refs are the store references the provider authenticates with.
func (p CloudProvider) Refs() []stores.Ref {
	var out []stores.Ref
	for _, r := range []stores.Ref{p.AccessKeyID, p.SecretAccessKey, p.SessionToken, p.APIKey, p.ServiceAccount, p.ClientSecret} {
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
