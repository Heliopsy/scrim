## Why

docs/limitations.md says only `openbao`, `vault`, `awssm`, `ssm`, `gcpsm`, `azkv` and `infisical` take
per-agent store credentials: Bitwarden Secrets Manager, Doppler, 1Password and Vaultwarden have none,
so a store of those kinds configured in `identity.store-credentials` or `identity.store-login` refuses
every use. Those adapters predate per-agent identity (#119, #104, #5) and the token exchange work
(#128) covered only the stores with a federated login. Each of the four has a per-identity
credential a check can use: a machine account access token, a service token or OIDC service account
identity, a Connect access token, and a member account's API key.

## What Changes

- `doppler`: a static Doppler token per agent, or the new `identity.store-login` method
  `doppler-oidc identity:<template> audience:<aud>`, which presents an identity token scrim signs
  for the agent at a service account identity's OIDC authentication (`POST /v3/auth/oidc`) and caches
  the short-lived token it returns. The read check reads the secret with the agent's token and wipes
  the value; a withheld value refuses the use. Writes are not checkable.
- `onepassword`: a Connect access token per agent from the same Connect server. The read check lists
  the item's vault with the agent's token (summaries, no value) and requires the item. Writes are not
  checkable. Service account tokens stay unsupported (SDK only).
- `bws`: a machine account access token per agent. scrim logs in as that machine account (cached per
  agent), refuses one of another organisation, and fetches the secret (`GET /secrets/{id}`) or, for a
  new secret, its project (`GET /projects/{id}`) as the agent: not found refuses a read, and the
  `write` flag decides a write. The ciphertext is never decrypted.
- `vaultwarden`: the agent account's personal API key per agent, as JSON. scrim logs in as that
  account (cached per agent) and fetches the item: an item the account cannot see, or whose
  collection hides passwords, is refused; `edit` (or the target collection's `readOnly`) decides a
  write. Nothing is decrypted, so the agent's master password is not needed.
- `infisical`: unchanged. Writes stay unchecked: the only permissions endpoint accepts user sessions,
  not machine identity tokens, and there is no dry run for a write.
- agentcache gains `Forget`, so a login a store stops accepting (401) is dropped and repeated once.
- Docs: identity.md lists the credential and check per store, limitations.md drops the four stores
  from the gap and states that agent writes are not yet checked against the agent's identity for any
  store (the write path never asks, a gap that predates this change).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `agent-identity`: token exchange adds `doppler-oidc`; the store checks cover Doppler, 1Password
  Connect, Bitwarden Secrets Manager and Vaultwarden; static credentials name what each of those takes;
  logins made from static credentials are cached and dropped when the store refuses them.

## Impact

- `internal/stores/{doppler,onepassword,bws,vaultwarden}` (new `agent.go` each, client changes to send
  as the agent), `internal/stores/stores.go` (`FederationDoppler`), `internal/agentstore` (the
  `doppler-oidc` method), `internal/stores/internal/agentcache` (`Forget`).
- docs/identity.md, docs/limitations.md, docs/kubernetes.md, docs/stores/{doppler,onepassword,bws,
  vaultwarden,infisical}.md, docs/configuration.md and schema/config-v1.json (the `identity.store-login`
  description).
- No configuration key, boundary protocol or state change.
