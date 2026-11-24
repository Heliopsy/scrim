// SPDX-License-Identifier: AGPL-3.0-only

// Used by the Linux-only matrix tests (user and network namespaces).

package matrix

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
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
