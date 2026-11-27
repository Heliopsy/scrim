## Why

docs/limitations.md says agent writes are not checked against the agent's own store identity: the
per-agent check runs before a value is used (injection, restore), while `secret_gen`,
`secret_capture`, `secret_ask_human` and `scrim secret put` write with scrim's own store identity
once scrim's rules allow them. OpenBao, Vault, Google Secret Manager, Bitwarden Secrets Manager and
Vaultwarden can already answer `AgentCan(..., OpWrite)` without writing, but nothing asks. An agent
whose own Vaultwarden account may only view a collection can still write into it through scrim.

## What Changes

- The agent tools ask the agent's own store identity after scrim's rules allow a write and before
  the value is generated, the command runs or a human is asked: `secret_gen`, `secret_capture` (and
  its pre-check), `secret_ask_human` and `scrim secret put`, over MCP, the local API and the edge
  listener. A refusal is `denied`, names the store, reference and the store's reason, and stores
  nothing. A failed check refuses the write as `unavailable`.
- Adapters declare whether they can check a write (`stores.DeclareAgentWriteCheck`): `openbao`,
  `vault`, `gcpsm`, `bws`, `vaultwarden`. For those, a governed store refuses a write the agent's
  identity may not make, and refuses an agent without an identity of its own.
- Stores that cannot check (`awssm`, `ssm`, `azkv`, `infisical`, `doppler`, `onepassword`) keep
  today's behaviour (scrim's identity, scrim's rules decide), unless the new setting
  `identity.refuse-unchecked-writes` (store names or `*`) names them, which refuses agents' writes.
- New weakening setting `identity.skip-agent-write-checks` (default off) writes without asking the
  agent's identity on stores that could check.
- Stores without per-agent identity are unchanged.
- The Kubernetes service account token a pod presents to the local API or the edge listener is kept
  for the request, so a write to a store with Kubernetes passthrough can log in as the pod.
- Write audit entries record `store_identity` and `store_write_check`. `scrim doctor` says, per
  governed store, whether agents' writes are checked, and warns where they are not.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `agent-identity`: agent writes are checked with the agent's own store identity where the store can
  check; stores that cannot are reported and can refuse agent writes.

## Impact

- `internal/agentstore` (`CheckWrite`, the two settings), `internal/stores` (write check
  declaration, declared by five adapters), `internal/agenttools` (`WriteAccess`, audit fields),
  `internal/agentapi` (the adapter and wiring), `internal/localapi` and `internal/edge` (the pod's
  token for the request), `internal/identity` (context carrier), `internal/daemon`, `internal/cli`
  (doctor), `internal/stores/storeconfig` (`Kinds`).
- docs/identity.md, docs/agent-tools.md, docs/limitations.md, docs/configuration.md,
  schema/config-v1.json.
- Two configuration keys. No boundary protocol or state change.
