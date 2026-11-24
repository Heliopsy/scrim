# Tasks

## 1. Edge CA

- [x] 1.1 `internal/ca`: CA profiles; `OpenEdge` with `edge.ca.dir`, `edge.ca.cert-file`, `edge.ca.key`; generated edge CA name-constrained to `edge.server-names`, `serverAuth` only, path length 0, rotated when the names change; operator edge CA checked with a trial certificate; verify: `internal/ca` edge tests (constraints refuse other names and addresses, rename rotates, operator CA refused for names its constraints do not permit, never the interception directory)
- [x] 1.2 `internal/daemon`: the edge listener issues from the edge CA, refuses an edge CA with the interception CA's key, runs its rotation; verify: `TestEdgeListenerHasItsOwnCA` (forwarder trusting the edge CA served, trusting the interception CA refused before the token is read), watched failing with the listener on the interception CA
- [x] 1.3 `internal/edge`: forwarder announces `scrim-edge-ca`, `edge-forwarder.ca-file` defaults to the edge CA; `edge.legacy-interception-certificate` serves 1.0 forwarders the interception CA's certificate; verify: `TestForwarderTrustsOnlyTheEdgeCA` and `TestEdgeLegacyInterceptionCertificate`, watched failing without the ALPN marker
- [x] 1.4 `scrim ca export --edge` and `scrim ca rotate --edge`; verify: `TestCAExportRotateEdge`

## 2. Chart

- [x] 2.1 `edge.ca.*` values; generated Ed25519 edge CA Secret kept across upgrades, or an existing Secret; mounted only into central scrim; `scrim-edge-ca.pem` in the `scrim-ca` ConfigMap; Kyverno mounts it only into the forwarder; refuse the interception CA's Secret; verify: `tests/edge_test.yaml`, `tests/refusals_*`, golden `edge` and `edge-existing-ca`
- [x] 2.2 Edge kind e2e checks the listener chains to the edge CA only; verify: CI job "Edge forwarder on kind"

## 3. Docs

- [x] 3.1 docs/edge-forwarder.md (edge CA, settings, upgrading from 1.0), docs/ca.md, docs/limitations.md entry reworded, generated configuration and values references
