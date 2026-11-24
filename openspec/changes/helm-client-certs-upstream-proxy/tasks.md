## 1. Client certificates

- [x] 1.1 `identity.clientCertificates` values, schema and generated docs
- [x] 1.2 identity.client-certificates and the TLS listeners in central scrim's chart.yaml
- [x] 1.3 CA bundle and CRL mounts, container ports, the `<fullname>-mtls` Service
- [x] 1.4 NetworkPolicy rule with `networkPolicy.clientCertificatesFrom`
- [x] 1.5 Refusals: no CA, CRLs without keys, ports taken, central off, set twice

## 2. Upstream proxy

- [x] 2.1 `upstreamProxy` values, schema and generated docs
- [x] 2.2 network.upstream-proxy in central and sidecar chart.yaml, in-cluster no-proxy entries
- [x] 2.3 Secret slot `upstream-proxy`: central mount, ExternalSecret, sidecar mount through Kyverno
- [x] 2.4 Refusals: password without url, credentials in the url, literal password in config, set
  twice, sidecar password without an existing Secret

## 3. Tests and docs

- [x] 3.1 helm-unittest suites and golden cases validated with `scrim config validate`
- [x] 3.2 docs/kubernetes.md, cross-links from identity.md and configuration.md, limitations.md
