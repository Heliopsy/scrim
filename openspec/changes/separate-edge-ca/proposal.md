## Why

The edge listener's certificate is issued by the TLS interception CA. One CA key therefore both
mints certificates for every host scrim intercepts and authenticates scrim to the edge forwarders
in agent pods. Whoever holds that key can impersonate central scrim to the forwarders as well as
to agents, and every forwarder trusts a CA that signs for any name (docs/limitations.md,
"The edge listener's certificate is issued by the interception CA").

## What Changes

- New: an edge CA, a key pair of its own used only to issue the edge listener's certificate.
  scrim generates it in `edge.ca.dir` (default `$XDG_STATE_HOME/scrim/edge-ca`), name-constrained
  to `edge.server-names` and limited to server certificates with path length 0, and rotates it with
  the interception CA's policy; or the operator supplies it with `edge.ca.cert-file` and
  `edge.ca.key`. scrim refuses to start when the edge CA has the interception CA's key, and a
  generated edge CA is rotated at once when the names change.
- Changed: the forwarder verifies the edge listener against the edge CA only
  (`edge-forwarder.ca-file`, default `/etc/scrim/edge-trust/scrim-edge-ca.pem`) and announces the
  ALPN protocol `scrim-edge-ca` so a listener can tell it from a 1.0 forwarder.
- New: `edge.legacy-interception-certificate`, a weakening setting for the upgrade window: a client
  that does not announce `scrim-edge-ca` (a 1.0 forwarder) gets a listener certificate from the
  interception CA. Current forwarders never accept that certificate.
- New: `scrim ca export --edge` and `scrim ca rotate --edge`.
- Chart: `edge.ca.*` values. The chart generates an Ed25519 edge CA once and keeps it (or takes an
  existing TLS Secret), mounts it only into central scrim, publishes its certificate as
  `scrim-edge-ca.pem` in the `scrim-ca` ConfigMap of every agent namespace, and the Kyverno policy
  mounts that key only into the forwarder. `edge.ca.legacyInterceptionCertificate` turns on the
  upgrade window. The chart refuses the interception CA's Secret as the edge CA.

## Impact

- Specs: credential-injection (edge channel, new edge CA requirement), deployment (edge forwarder
  mounts, new edge CA in the chart requirement).
- Code: `internal/ca` (profiles, `OpenEdge`, name constraints), `internal/edge` (certificate
  selection, forwarder ALPN, settings), `internal/daemon/edge.go`, `internal/cli/ca.go`.
- Chart: `values.yaml`, `templates/ca.yaml`, `_scrim.tpl`, `_kyverno.tpl`, `config.yaml`,
  `deployment.yaml`, `validate.yaml`, tests and golden cases.
- Upgrades: agent pods started before the upgrade run a forwarder that trusts the interception CA.
  They fail closed until restarted, or keep working while `edge.ca.legacyInterceptionCertificate`
  is on (docs/edge-forwarder.md, "Upgrading from 1.0").
