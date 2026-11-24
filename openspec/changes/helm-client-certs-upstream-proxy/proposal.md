## Why

1.1.0 added client certificate identity and the upstream proxy, but the Helm chart exposes neither.
On Kubernetes an operator has to write `identity.client-certificates.*`, the TLS listeners and
`network.upstream-proxy.*` into `config` by hand and mount the CA bundle, CRLs and proxy password
with `secretMounts`, while the chart neither exposes the TLS listeners nor reaches the sidecars'
configuration (docs/limitations.md listed the client certificate gap).

## What Changes

- New: `identity.clientCertificates.*` values. Central scrim serves the LLM base URL and the forward
  proxy on TLS listeners that require a client certificate, on a Service of their own
  (`<fullname>-mtls`) so they can be exposed without exposing the plain listeners. The trust anchors
  and CRLs come from ConfigMaps; the listener certificate names the Service and `serverNames`; a
  NetworkPolicy rule opens the ports (`networkPolicy.clientCertificatesFrom` narrows it).
- New: `upstreamProxy.*` values, for central scrim and the sidecars: url, noProxy, username, and the
  password from the Secret slot `upstream-proxy`. `inClusterDirect` (on) reaches `.svc` and the
  cluster domain directly.
- The chart refuses a literal proxy password in `config`, a proxy URL with credentials, CRLs without
  keys, TLS ports taken by another listener, and settings given both in `config` and in the values.

## Impact

- Affected specs: deployment.
- Affected code: deploy/helm/scrim (values, templates, schema, tests), test/k8s/golden,
  docs/kubernetes.md, docs/helm-values.md.
- No change to scrim itself. Installs that leave the new values at their defaults render as before.
