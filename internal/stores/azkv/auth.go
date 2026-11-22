// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// credentials is what a login needs, resolved at first use: the azidentity
// credential, or a static access token, and copies of the credentials scrim
// itself holds, for stores.CredentialHolder.
type credentials struct {
	cred   azcore.TokenCredential
	static secret.Value
	held   []secret.Value
}

func (c *credentials) wipe() {
	c.static.Wipe()
	for _, v := range c.held {
		v.Wipe()
	}
}

// buildCredential resolves the credential options and builds the
// azidentity credential auth.method names. Building contacts nothing.
func buildCredential(ctx context.Context, s *settings, httpc *http.Client) (*credentials, error) {
	co := azcore.ClientOptions{
		Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: s.authority},
		Transport: httpc,
		// azidentity retries token requests itself; one retry is enough
		// to ride out a blip without holding a request for long.
		Retry: policy.RetryOptions{MaxRetries: 1},
	}
	clientID, err := s.resolveString(ctx, optClientID, s.clientIDRef)
	if err != nil {
		return nil, err
	}
	out := &credentials{}
	switch s.method {
	case methodToken:
		v, err := s.resolveRef(ctx, optToken, s.tokenRef)
		if err != nil {
			return nil, err
		}
		out.static = v
		out.held = append(out.held, copyValue(v))
		return out, nil
	case methodDefault:
		out.cred, err = azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
			ClientOptions: co, TenantID: s.tenantID, DisableInstanceDiscovery: s.custom,
		})
	case methodWorkload:
		out.cred, err = azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			ClientOptions: co, TenantID: s.tenantID, ClientID: clientID, TokenFilePath: s.tokenFile,
			DisableInstanceDiscovery: s.custom,
		})
	case methodManaged:
		o := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: co}
		if clientID != "" {
			o.ID = azidentity.ClientID(clientID)
		}
		out.cred, err = azidentity.NewManagedIdentityCredential(o)
	case methodSecret:
		v, rerr := s.resolveRef(ctx, optClientSecret, s.secretRef)
		if rerr != nil {
			return nil, rerr
		}
		var cs string
		// azidentity takes the client secret as a string; it lives in
		// the credential for the adapter's lifetime (see the package
		// documentation).
		_ = v.Expose(func(b []byte) error { cs = string(b); return nil })
		out.held = append(out.held, v)
		out.cred, err = azidentity.NewClientSecretCredential(s.tenantID, clientID, cs, &azidentity.ClientSecretCredentialOptions{
			ClientOptions: co, DisableInstanceDiscovery: s.custom,
		})
	case methodCertificate:
		v, rerr := s.resolveRef(ctx, optCertificate, s.certRef)
		if rerr != nil {
			return nil, rerr
		}
		out.held = append(out.held, v)
		var pw secret.Value
		if s.passwordRef != "" {
			if pw, rerr = s.resolveRef(ctx, optPassword, s.passwordRef); rerr != nil {
				out.wipe()
				return nil, rerr
			}
			out.held = append(out.held, pw)
		}
		err = v.Expose(func(cert []byte) error {
			return pw.Expose(func(p []byte) error {
				certs, key, perr := azidentity.ParseCertificates(cert, p)
				if perr != nil {
					// ParseCertificates' errors describe the format, not
					// the data, but keep only a fixed text.
					return errors.New("option " + optCertificate + " holds no usable PEM or PKCS#12 certificate and key (check " + optPassword + ")")
				}
				var cerr error
				out.cred, cerr = azidentity.NewClientCertificateCredential(s.tenantID, clientID, certs, key,
					&azidentity.ClientCertificateCredentialOptions{ClientOptions: co, DisableInstanceDiscovery: s.custom})
				return cerr
			})
		})
	}
	if err != nil {
		out.wipe()
		return nil, fmt.Errorf("%s %s: %s", optAuthMethod, s.method, scrubCredError(err))
	}
	return out, nil
}

func copyValue(v secret.Value) secret.Value {
	var c secret.Value
	_ = v.Expose(func(b []byte) error { c = secret.New(b); return nil })
	return c
}

// scrubCredError keeps the first line of an azidentity error: later lines
// hold troubleshooting links and the raw Entra response.
func scrubCredError(err error) string {
	msg, _, _ := strings.Cut(err.Error(), "\n")
	return strings.TrimSpace(msg)
}

// tokenKind classifies a failed token request: Entra answered and refused
// (a permission problem), or it answered with an outage, could not be
// reached, or the credential found nothing to work with (unavailable, with
// the reason in the detail).
func tokenKind(err error) error {
	var af *azidentity.AuthenticationFailedError
	if errors.As(err, &af) {
		if af.RawResponse != nil && (af.RawResponse.StatusCode == http.StatusTooManyRequests || af.RawResponse.StatusCode >= 500) {
			return stores.ErrUnavailable
		}
		if af.RawResponse != nil {
			return stores.ErrPermission
		}
		return stores.ErrUnavailable
	}
	return stores.ErrUnavailable
}
