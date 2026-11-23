// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// API is the leak suite API a provider's requests are written in.
func (p Provider) API() fp.API {
	switch p {
	case ProviderOpenAIChat:
		return fp.OpenAIChat
	case ProviderOpenAIResponses:
		return fp.OpenAIResponses
	case ProviderGemini:
		return fp.Gemini
	}
	return fp.Anthropic
}

// Cloud reports whether p is a cloud provider route rather than a built-in
// route.
func (p Provider) Cloud() bool { return p.Kind() != "" }

// Kind is the providers.<name>.kind of a cloud provider route.
func (p Provider) Kind() fp.CloudKind {
	switch p {
	case ProviderBedrock:
		return fp.Bedrock
	case ProviderBedrockMantle:
		return fp.BedrockMantle
	case ProviderAnthropicAWS:
		return fp.AnthropicAWS
	case ProviderFoundry, ProviderFoundryEntra:
		return fp.Foundry
	case ProviderVertex:
		return fp.Vertex
	}
	return ""
}

// Route is the route prefix of p on the LLM base URL (the provider instance
// name for a cloud route).
func (p Provider) Route() string {
	switch p {
	case ProviderAnthropic:
		return "anthropic"
	case ProviderOpenAIChat, ProviderOpenAIResponses:
		return "openai"
	case ProviderGemini:
		return "gemini"
	}
	return string(p)
}

// Host is the host name the agent connects to when it bypasses the base URL
// (forward proxy, transparent): the provider's own for a built-in route, and
// for a cloud route the host of its upstream, which the sandbox resolves to
// loopback where the fake listens.
func (p Provider) Host() string {
	switch p {
	case ProviderAnthropic:
		return "api.anthropic.com"
	case ProviderOpenAIChat, ProviderOpenAIResponses:
		return "api.openai.com"
	case ProviderGemini:
		return "generativelanguage.googleapis.com"
	}
	return string(p) + ".cloud.scrim.test"
}

// SandboxHosts are the /etc/hosts lines the matrix adds to the sandbox.
func SandboxHosts() string {
	var b strings.Builder
	for _, p := range Providers {
		if p == ProviderOpenAIResponses {
			continue
		}
		fmt.Fprintf(&b, "127.0.0.1 %s\n", p.Host())
	}
	return b.String()
}

const (
	vertexProject = "scrim-matrix"
	vertexRegion  = "us-east5"
	awsRegion     = "us-east-1"
	workspaceID   = "wrkspc_01ScrimMatrix"
	entraTenant   = "scrim-matrix-tenant"
	entraClient   = "scrim-matrix-app"
	saEmail       = "scrim-matrix@scrim-matrix.iam.gserviceaccount.com"
)

// cloudSetup is a cloud provider route of one cell: its credentials (written
// to the store under test), its configuration and the fake's options.
type cloudSetup struct {
	Values map[string]string // store secret name to value
	Seeds  []leak.Seed       // the credentials, for checking scrim's own outputs
	Opts   fp.CloudOptions
	Issuer *fp.TokenIssuer // vertex and Entra ID
	auth   string          // credential lines of the providers block
}

// newCloudSetup generates the credentials for p. ref names a secret in the
// store under test.
func newCloudSetup(p Provider, ref func(name string) string) (*cloudSetup, error) {
	c := &cloudSetup{Values: map[string]string{}, Opts: fp.CloudOptions{Kind: p.Kind(), Region: awsRegion}}
	add := func(name, field string, k leak.Kind) string {
		v := leak.Generate(k)
		c.Seeds = append(c.Seeds, v)
		c.Values[name] = v.Value()
		c.auth += fmt.Sprintf("    %s: %s\n", field, ref(name))
		return v.Value()
	}
	switch p {
	case ProviderBedrock:
		c.Opts.AccessKeyID = add("cloud-akid", "access-key-id", leak.KindAWSAccessKey)
		c.Opts.SecretAccessKey = add("cloud-secret", "secret-access-key", leak.KindAWSSecret)
		c.Opts.SessionToken = add("cloud-token", "session-token", leak.KindAPIKey)
	case ProviderAnthropicAWS:
		c.Opts.AccessKeyID = add("cloud-akid", "access-key-id", leak.KindAWSAccessKey)
		c.Opts.SecretAccessKey = add("cloud-secret", "secret-access-key", leak.KindAWSSecret)
	case ProviderBedrockMantle, ProviderFoundry:
		c.Opts.APIKey = add("cloud-key", "api-key", leak.KindAPIKey)
	case ProviderFoundryEntra:
		c.Issuer = &fp.TokenIssuer{ClientID: entraClient}
		c.Issuer.ClientSecret = add("cloud-client-secret", "client-secret", leak.KindAPIKey)
		c.auth += fmt.Sprintf("    tenant-id: %s\n    client-id: %s\n", entraTenant, entraClient)
		c.Opts.Tokens = c.Issuer
	case ProviderVertex:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		sa, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": vertexProject, "private_key_id": "matrix-key-1",
			"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
			"client_email": saEmail, "token_uri": "https://oauth2.googleapis.com/token"})
		c.Values["cloud-sa"] = string(sa)
		c.Seeds = append(c.Seeds, leak.NewSeed("cloud-sa", leak.KindPrivateKey, string(sa)))
		c.auth = "    service-account: " + ref("cloud-sa") + "\n"
		c.Issuer = &fp.TokenIssuer{ServiceAccount: saEmail, PublicKey: &k.PublicKey}
		c.Opts.Tokens = c.Issuer
	default:
		return nil, fmt.Errorf("%s is not a cloud provider", p)
	}
	return c, nil
}

// Config is the providers block for p with its upstream at upstream (an
// origin) and, for token-minting routes, the token service at issuerURL.
func (c *cloudSetup) Config(p Provider, upstream, issuerURL string) string {
	var where string
	switch p.Kind() {
	case fp.Vertex:
		where = "    region: " + vertexRegion + "\n"
	case fp.Foundry:
	default:
		where = "    region: " + awsRegion + "\n"
	}
	auth := c.auth
	switch p {
	case ProviderVertex:
		auth += "    token-url: " + issuerURL + "/token\n"
	case ProviderFoundryEntra:
		auth += "    token-url: " + issuerURL + "/" + entraTenant + "/oauth2/v2.0/token\n"
	}
	return fmt.Sprintf("  %s:\n    kind: %s\n%s    upstream: %s\n%s", p.Route(), p.Kind(), where, upstream, auth)
}

// cloudRequest rewrites an Anthropic Messages request (path and body) into
// the wire format the agent uses toward the cloud provider p, the way Claude
// Code does in that provider mode: Bedrock InvokeModel and Vertex rawPredict
// carry the model in the path and anthropic_version in the body, Foundry
// serves the API under /anthropic. The body is rewritten as text, so every
// other member keeps the exact bytes (and escaping) the matrix row chose.
func cloudRequest(p Provider, path string, body []byte) (string, []byte) {
	switch p {
	case ProviderFoundry, ProviderFoundryEntra:
		return "/anthropic" + path, body
	case ProviderBedrock, ProviderVertex:
	default:
		return path, body
	}
	if path != "/v1/messages" {
		return path, body
	}
	members, ok := topLevel(body)
	if !ok {
		return path, body
	}
	model, stream := "claude-sonnet-4-5", false
	var kept [][]byte
	for _, m := range members {
		switch m.key {
		case "model":
			_ = json.Unmarshal(m.value, &model)
			continue
		case "stream":
			_ = json.Unmarshal(m.value, &stream)
			if p == ProviderBedrock {
				continue
			}
		case "anthropic_version":
			continue
		}
		kept = append(kept, m.text)
	}
	version := `"anthropic_version":"bedrock-2023-05-31"`
	if p == ProviderVertex {
		version = `"anthropic_version":"vertex-2023-10-16"`
	}
	out := append([]byte("{"+version), byte(','))
	out = append(out, bytes.Join(kept, []byte(","))...)
	out = bytes.TrimSuffix(out, []byte(","))
	out = append(out, '}')
	if p == ProviderBedrock {
		action := "invoke"
		if stream {
			action = "invoke-with-response-stream"
		}
		return "/model/" + url.PathEscape(model) + "/" + action, out
	}
	action := "rawPredict"
	if stream {
		action = "streamRawPredict"
	}
	return fmt.Sprintf("/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:%s", vertexProject, vertexRegion, model, action), out
}

type member struct {
	key   string
	value json.RawMessage
	text  []byte // the member as written: key, colon and value
}

// topLevel splits a JSON object into its members without re-encoding them.
func topLevel(b []byte) ([]member, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	var out []member
	for dec.More() {
		start := dec.InputOffset()
		t, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := t.(string)
		if !ok {
			return nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		text := bytes.TrimLeft(b[start:dec.InputOffset()], " \t\r\n,")
		out = append(out, member{key: key, value: v, text: text})
	}
	return out, true
}
