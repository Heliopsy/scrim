// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
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
			"certificate whose issuer has no current CRL among them is refused unless OCSP answers for it, and so is every " +
			"certificate of an issuer whose CRL is past its next update. Empty, without OCSP, checks no revocation: use " +
			"short-lived certificates.",
		Default:         []string{},
		RestartRequired: true,
	})
	CertRevocationScope = config.Register(config.Spec[string]{
		Key:     "identity.client-certificates.revocation-scope",
		Default: identity.RevocationEndEntity,
		Enum:    []string{identity.RevocationEndEntity, identity.RevocationChain},
		Description: "Which certificates of a client's chain are checked for revocation (CRLs and OCSP): end-entity checks " +
			"the client certificate only, chain checks every certificate below the trust anchor as well, so a revoked " +
			"intermediate CA refuses the certificates it issued.",
		RestartRequired: true,
	})
	CertOCSP = config.Register(config.Spec[bool]{
		Key: "identity.client-certificates.ocsp.enabled",
		Description: "Ask the issuer's OCSP responder whether each client certificate is revoked before its connection is " +
			"served. The control plane fetches and verifies the responses, through network.upstream-proxy, and keeps each " +
			"until its next update. Off: only CRLs are checked.",
		RestartRequired: true,
	})
	CertOCSPResponder = config.Register(config.Spec[string]{
		Key: "identity.client-certificates.ocsp.responder",
		Description: "OCSP responder URL used for every certificate instead of the one in its authority information access " +
			"extension. Empty uses the certificate's own; a certificate without one is checked by CRL only. Responses must " +
			"still be signed by the issuer or a responder it delegated to.",
		RestartRequired: true,
		Validate: func(s string) error {
			if s == "" {
				return nil
			}
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return errors.New("must be an http:// or https:// URL")
			}
			if u.User != nil {
				return errors.New("must not carry credentials")
			}
			return nil
		},
	})
	CertOCSPUnreachable = config.Register(config.Spec[string]{
		Key:     "identity.client-certificates.ocsp.unreachable",
		Default: identity.OCSPFailClosed,
		Enum:    []string{identity.OCSPFailClosed, identity.OCSPSoftFail},
		Description: "What happens when no valid OCSP answer can be had (responder unreachable, error status, bad signature, " +
			"stale response): fail-closed refuses the certificate, soft-fail accepts it as if OCSP were off. A revoked or " +
			"unknown answer always refuses.",
		RestartRequired: true,
	})
	CertOCSPTimeout = config.Register(config.Spec[time.Duration]{
		Key:             "identity.client-certificates.ocsp.timeout",
		Default:         5 * time.Second,
		Description:     "How long one OCSP request may take. Requests for one chain run in parallel. At most 10s.",
		RestartRequired: true,
		Validate: func(d time.Duration) error {
			if d <= 0 || d > identity.MaxOCSPTimeout {
				return fmt.Errorf("must be positive and at most %s", identity.MaxOCSPTimeout)
			}
			return nil
		},
	})
	CertOCSPCacheSize = config.Register(config.Spec[int]{
		Key:     "identity.client-certificates.ocsp.cache-size",
		Default: 10000,
		Description: "How many OCSP responses are kept, each until its next update. When full, expired responses go first, " +
			"then the ones that expire soonest.",
		RestartRequired: true,
		Validate: func(n int) error {
			if n < 1 {
				return errors.New("must be at least 1")
			}
			return nil
		},
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
			"listed, else the first name. Not used with identity.client-certificates.listener-cert-file.",
		Default:         []string{"localhost", "127.0.0.1", "::1"},
		RestartRequired: true,
	})
	CertListenerCertFile = config.Register(config.Spec[string]{
		Key: "identity.client-certificates.listener-cert-file",
		Description: "PEM certificate (end entity first, then intermediates) scrim's TLS proxy listeners present instead of one " +
			"its CA issues, so agents need not trust scrim's CA for them. Needs identity.client-certificates.listener-key. " +
			"Read again every identity.client-certificates.refresh: a certificate renewed in place is used for new " +
			"connections; one that does not parse, does not match the key or has expired is not, and the one in force stays.",
		RestartRequired: true,
	})
	CertListenerKey = config.Register(config.Spec[config.SecretRef]{
		Key: "identity.client-certificates.listener-key",
		Description: "Reference to the PEM private key of identity.client-certificates.listener-cert-file (file:, env:, cred: " +
			"or a store reference), resolved again every identity.client-certificates.refresh. One of scrim's own " +
			"credentials: redacted from provider traffic and never logged.",
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

// listenerCertFileMax bounds the listener certificate file.
const listenerCertFileMax = 1 << 20

// ListenerCertSource builds the source of the operator's listener
// certificate and loads it once, nil when
// identity.client-certificates.listener-cert-file is not set. Both settings
// are needed, and only with client certificate identity on.
func ListenerCertSource(ctx context.Context, cfg *config.Config) (*identity.ListenerCertSource, error) {
	file := CertListenerCertFile.Get(cfg)
	ref := CertListenerKey.Get(cfg)
	switch {
	case file == "" && ref == "":
		return nil, nil
	case file == "":
		return nil, fmt.Errorf("%s needs %s", CertListenerKey.Name(), CertListenerCertFile.Name())
	case ref == "":
		return nil, fmt.Errorf("%s needs %s", CertListenerCertFile.Name(), CertListenerKey.Name())
	case !CertEnabled.Get(cfg):
		return nil, fmt.Errorf("%s needs %s: only the client certificate listeners present it", CertListenerCertFile.Name(), CertEnabled.Name())
	}
	src := &identity.ListenerCertSource{
		Read: func() ([]byte, secret.Value, error) {
			chain, err := readBounded(file, listenerCertFileMax)
			if err != nil {
				return nil, secret.Value{}, err
			}
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			key, err := cfg.ResolveRef(rctx, ref)
			if err != nil {
				return nil, secret.Value{}, fmt.Errorf("%s: %w", CertListenerKey.Name(), err)
			}
			return chain, key, nil
		},
	}
	if _, err := src.Reload(); err != nil {
		return nil, fmt.Errorf("%s: %w", CertListenerCertFile.Name(), err)
	}
	return src, nil
}

// CertResolver builds the client certificate resolver over src, nil when
// src is nil, with the OCSP checker when identity.client-certificates.ocsp
// is on. log receives the OCSP checks that got no valid answer.
func CertResolver(cfg *config.Config, src *identity.CertTrustSource, log *slog.Logger) (*identity.CertResolver, error) {
	if src == nil {
		return nil, nil
	}
	rules, err := identity.CertRulesFromMap(CertAgents.Get(cfg))
	if err != nil {
		return nil, err
	}
	r := &identity.CertResolver{Trust: src.Current, Rules: rules, Unmapped: CertUnmapped.Get(cfg),
		Chain: CertRevocationScope.Get(cfg) == identity.RevocationChain, OCSP: OCSPChecker(cfg, log)}
	return r, nil
}

// OCSPChecker is the OCSP checker of client certificate identity, nil when
// identity.client-certificates.ocsp.enabled is off. Its requests follow
// network.upstream-proxy.
func OCSPChecker(cfg *config.Config, log *slog.Logger) *identity.OCSPChecker {
	if !CertEnabled.Get(cfg) || !CertOCSP.Get(cfg) {
		return nil
	}
	return &identity.OCSPChecker{
		Responder: CertOCSPResponder.Get(cfg),
		SoftFail:  CertOCSPUnreachable.Get(cfg) == identity.OCSPSoftFail,
		Timeout:   CertOCSPTimeout.Get(cfg),
		CacheSize: CertOCSPCacheSize.Get(cfg),
		Log:       log,
	}
}
