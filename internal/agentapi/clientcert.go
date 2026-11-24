// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
)

// Client certificate identity (specs/agent-identity "Optional mutual TLS
// identity"). Read when the daemon starts; the trust anchors and CRLs are
// read again every identity.client-certificates.refresh.
var (
	CertEnabled = config.Register(config.Spec[bool]{
		Key: "identity.client-certificates.enabled",
		Description: "Identify callers by the client certificate they present on scrim's TLS listeners (proxy.tls-listen, " +
			"proxy.forward-tls-listen, tool-proxy.tls-listen and edge.listen). Needs identity.client-certificates.ca.",
		RestartRequired: true,
	})
	CertCA = config.Register(config.Spec[string]{
		Key: "identity.client-certificates.ca",
		Description: "Trust anchors client certificates must chain to: a PEM bundle of CA certificates, as a reference " +
			"(file:/path, env:NAME, cred:NAME or a store reference such as bao://kv/pki#ca). No system roots are used.",
		RestartRequired: true,
		Validate: func(s string) error {
			if s == "" {
				return nil
			}
			switch config.SecretRef(s).Kind() {
			case config.RefFile, config.RefEnv, config.RefCredential, config.RefStore:
				return nil
			default:
				return errors.New("must be a reference: file:/path, env:NAME, cred:NAME or a store reference")
			}
		},
	})
	CertCRLFiles = config.Register(config.Spec[[]string]{
		Key: "identity.client-certificates.crl-files",
		Description: "Certificate revocation lists (PEM or DER files) checked for every client certificate. With any set, a " +
			"certificate whose issuer has no current CRL among them is refused, and so is every certificate of an issuer " +
			"whose CRL is past its next update. Empty checks no revocation: use short-lived certificates.",
		Default:         []string{},
		RestartRequired: true,
	})
	CertRefresh = config.Register(config.Spec[time.Duration]{
		Key:             "identity.client-certificates.refresh",
		Default:         time.Minute,
		Description:     "How often the trust anchors and CRL files are read again. A new CRL applies to new connections within this bound.",
		Validate:        positive,
		RestartRequired: true,
	})
	CertAgents = config.Register(config.Spec[map[string]string]{
		Key: "identity.client-certificates.agents",
		Description: "Agents by client certificate: agent name to space-separated selectors spiffe:ID, cn:NAME, dns:NAME, " +
			"uri:URI, email:ADDRESS (globs allowed, * does not cross /), scope:SCOPE, label:K=V. A certificate no rule maps " +
			"follows identity.client-certificates.unmapped.",
		RestartRequired: true,
	})
	CertUnmapped = config.Register(config.Spec[string]{
		Key:     "identity.client-certificates.unmapped",
		Default: identity.UnmappedUnknown,
		Enum:    []string{identity.UnmappedUnknown, identity.UnmappedDerive},
		Description: "What a verified client certificate no identity.client-certificates.agents rule maps becomes: unknown " +
			"treats it as an unknown caller, derive names the agent after its SPIFFE ID without the spiffe:// prefix " +
			"(a certificate without one stays unknown).",
		RestartRequired: true,
	})
	CertServerNames = config.Register(config.Spec[[]string]{
		Key: "identity.client-certificates.server-names",
		Description: "Host names and IP addresses the certificate of scrim's TLS proxy listeners carries, signed by scrim's " +
			"CA. A client that sends no server name, or one not in the list, gets the address it connected to when that is " +
			"listed, else the first name.",
		Default:         []string{"localhost", "127.0.0.1", "::1"},
		RestartRequired: true,
	})
)

// crlFileMax bounds a CRL file; large CAs publish CRLs of a few megabytes.
const crlFileMax = 32 << 20

// CertTrustSource builds the trust source of client certificate identity
// from cfg and loads it once, nil when identity.client-certificates.enabled
// is off. The trust anchors resolve through cfg's references.
func CertTrustSource(ctx context.Context, cfg *config.Config) (*identity.CertTrustSource, error) {
	if !CertEnabled.Get(cfg) {
		return nil, nil
	}
	ref := CertCA.Get(cfg)
	if ref == "" {
		return nil, fmt.Errorf("%s needs %s", CertEnabled.Name(), CertCA.Name())
	}
	files := CertCRLFiles.Get(cfg)
	src := &identity.CertTrustSource{
		ReadCA: func() ([]byte, error) {
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			v, err := cfg.ResolveRef(rctx, config.SecretRef(ref))
			if err != nil {
				return nil, err
			}
			defer v.Wipe()
			var out []byte
			// The bundle is public; it leaves the secret type here so it
			// can be parsed and sent to the data plane.
			_ = v.Expose(func(b []byte) error { out = append([]byte(nil), b...); return nil })
			return out, nil
		},
		ReadCRLs: func() ([][]byte, error) {
			out := make([][]byte, 0, len(files))
			for _, f := range files {
				b, err := readBounded(f, crlFileMax)
				if err != nil {
					return nil, err
				}
				out = append(out, b)
			}
			return out, nil
		},
	}
	if _, err := src.Reload(); err != nil {
		return nil, fmt.Errorf("%s: %w", CertCA.Name(), err)
	}
	return src, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

// CertResolver builds the client certificate resolver over src, nil when
// src is nil.
func CertResolver(cfg *config.Config, src *identity.CertTrustSource) (*identity.CertResolver, error) {
	if src == nil {
		return nil, nil
	}
	rules, err := identity.CertRulesFromMap(CertAgents.Get(cfg))
	if err != nil {
		return nil, err
	}
	return &identity.CertResolver{Trust: src.Current, Rules: rules, Unmapped: CertUnmapped.Get(cfg)}, nil
}
