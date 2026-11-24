## Context

The edge listener (`edge.listen`) authenticates central scrim to the forwarders in agent pods. In
1.0 its certificate came from the interception CA, the CA whose key signs a certificate for every
host the tool proxy intercepts. The forwarder trusted that CA from the `scrim-ca` ConfigMap.

## Decisions

### E1. A second CA with the same machinery

The edge CA is a second `ca.Manager` with its own profile (settings, directory, common name, name
constraints). Generation, persistence, locking, rotation with overlap and operator-supplied mode are
the code the interception CA already uses, so "rotation and renewal as today" holds by
construction: the generated edge CA rotates under `tool-proxy.ca.validity`, `rotate-before` and
`overlap`, the listener certificate is issued for 24 hours, renewed at half that, and issued again
on the first handshake after the CA changes. A rotation keeps the previous edge CA in the bundle
`scrim ca export --edge` prints for the overlap. There is no cross certificate: the forwarder's CA
file is the bundle, and the listener presents a leaf from the current generation only.

Rejected: separate rotation settings for the edge CA. They would double the surface for no case
anyone has asked for.

### E2. Name constraints on the generated edge CA

A generated edge CA carries critical name constraints that permit exactly the DNS names in
`edge.server-names` (each with the names below it) and exactly its IP addresses. A kind of name the
list has none of is excluded outright (all IPv4 and IPv6, or every DNS name), so the key can sign
nothing else that a constraint-checking client accepts. It is limited to `serverAuth` and path
length 0. When `edge.server-names` changes, the CA no longer matches and is rotated on start.

An operator-supplied edge CA is used as given after a trial: a certificate for the configured
names, issued by it, must verify against it alone (constraints, key usage, path length). An
unconstrained one is accepted with an info log.

### E3. The chart's edge CA cannot be name-constrained

Helm's `genCAWithKey` cannot add extensions, and nothing in the chart can sign. The chart's
generated edge CA (Ed25519, like the interception CA) is therefore unconstrained. Its key is still
separate, mounted only into central scrim, and its certificate is published only to the forwarder
(a ConfigMap key no agent container mounts, and in neither `scrim-ca.pem` nor `ca-bundle.pem`), so
no agent runtime trusts it. An operator who wants the constraint supplies the edge CA with
`edge.ca.existingSecret` (cert-manager can issue a CA with `nameConstraints`).

Rejected for now: scrim creating the edge CA and writing its certificate into the ConfigMaps
through the Kubernetes API. It needs write access to ConfigMaps in every agent namespace, a new
permission for a process that holds every secret, to get a constraint that only matters to a
client other than the forwarder.

### E4. Distribution as a second ConfigMap key

The certificate goes into the existing `scrim-ca` ConfigMap as `scrim-edge-ca.pem`, which is
already rendered into every agent namespace, so no new object has to be kept in sync. The Kyverno
policy adds a `scrim-edge-trust` volume with only that key, mounted only into the forwarder at
`/etc/scrim/edge-trust`. The agent containers' `scrim-trust` volume keeps its explicit item list
and does not include it.

### E5. Upgrade window chosen by ALPN

A forwarder from 1.0 trusts the interception CA and offers ALPN `http/1.1` only. The new forwarder
also offers `scrim-edge-ca`; the listener never selects it, so the negotiated protocol is unchanged.
With `edge.legacy-interception-certificate` on, the listener's `GetCertificate` serves a client that
does not offer `scrim-edge-ca` a certificate from the interception CA, and every other client the
edge CA's. The separation still holds for current forwarders: they trust only the edge CA, so a
certificate from the interception CA is refused whatever the listener does. The setting is
weakening (it keeps the 1.0 exposure for old forwarders), logs a warning, and is off by default.

Rejected: forwarders that trust both CAs during the window. That would keep the interception key
able to impersonate scrim to every new forwarder for as long as the window lasts.

### E6. Refusing a shared key

`startEdge` compares the public keys of every edge CA certificate with every interception CA
generation and refuses to start on a match. `edge.ca.dir` equal to the interception CA's directory
is refused before anything is generated, and the chart refuses `edge.ca.existingSecret` naming the
interception CA's Secret.

## Risks

- Agent pods that are not restarted after an upgrade lose their edge endpoints until they are,
  unless the window is turned on. The upgrade notes say so.
- The chart default is unconstrained (E3).
