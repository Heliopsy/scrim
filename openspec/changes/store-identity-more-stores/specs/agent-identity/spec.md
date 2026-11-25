## MODIFIED Requirements

### Requirement: Token exchange per store

Each adapter that supports federated login SHALL exchange an identity token scrim signs for the
agent for a short-lived store credential, as `identity.store-login` configures per store: `jwt`
(Vault and OpenBao JWT auth), `aws-web-identity` (AssumeRoleWithWebIdentity),
`gcp-workload-identity` (Google STS, optionally impersonating a service account), `azure-federated`
(Entra ID client assertion), `infisical-oidc` (Infisical OIDC identities) or `doppler-oidc`
(Doppler service account identities).

#### Scenario: AWS role per agent

- **WHEN** the IAM role `agent-claude-laptop` trusts scrim's identity provider for that agent's claims
- **THEN** scrim assumes that role for the agent with the session name `claude-laptop.<session>` and
  AWS CloudTrail shows the agent's session name

#### Scenario: OpenBao role per agent

- **WHEN** OpenBao's JWT auth trusts scrim's issuer, the role for `claude-laptop` may read
  `kv/agents/shared/*` and the role for `intruder` may not, and scrim's rules allow both to use
  `bao://kv/agents/shared/db`
- **THEN** the use by `claude-laptop` passes and the use by `intruder` is refused with OpenBao's denial

#### Scenario: Doppler identity per agent

- **WHEN** a Doppler service account identity trusts scrim's issuer for agent `agent-a` and its
  service account may read config `billing/prd`, and another agent's identity may read `billing/dev`
  only
- **THEN** a use of `dop://billing/prd/DB_PASSWORD` by `agent-a` passes and the same use by the other
  agent is refused with Doppler's denial

### Requirement: Store checks as the agent

After scrim's rules allow a use of a governed store's secret, the control plane SHALL check it with
the agent's own store identity. Where the store can say what an identity may do (Vault and OpenBao
`sys/capabilities-self`, Google `testIamPermissions`, the access flags of Bitwarden Secrets Manager
and Vaultwarden, 1Password Connect's vault listing) the value SHALL NOT be read or decrypted as the
agent; elsewhere (AWS, Azure Key Vault, Infisical, Doppler) the check SHALL read it and wipe it.

#### Scenario: AWS role without access

- **WHEN** the role an agent assumes may not read the secret
- **THEN** the use is refused with the store's denial, although scrim's rules allow it

#### Scenario: Google principal without access

- **WHEN** the federated principal of an agent lacks `secretmanager.versions.access` on the secret
- **THEN** the use is refused without the value being read

#### Scenario: Machine account without the project

- **WHEN** an agent's Bitwarden Secrets Manager machine account has no access to the project of
  `bws://prod/DB_PASSWORD` and scrim's own machine account has
- **THEN** the use is refused and the secret's ciphertext is not decrypted for the check

#### Scenario: Collection hides passwords from the agent

- **WHEN** an agent's Vaultwarden account may view the collection holding an item except its
  passwords
- **THEN** a use of any field of that item is refused without anything decrypted with the agent's
  account

#### Scenario: Connect token without the vault

- **WHEN** an agent's 1Password Connect token is not scoped to the vault of `op://Prod/db#password`
- **THEN** the use is refused and no item with fields is fetched with the agent's token

### Requirement: Static per-agent store credentials as fallback

For stores without federated login, the system SHALL support a separate store credential per agent,
held by scrim and given by reference in `identity.store-credentials`, and SHALL report in `scrim doctor`,
per store and agent, which identity applies: passthrough, federated (token exchange), static,
shared (a store without per-agent identity) or none. An agent with no usable identity for a store that has per-agent identity SHALL be
refused for it.

#### Scenario: Vaultwarden per agent

- **WHEN** each agent has its own Vaultwarden account in the organisation, with collection access of
  its own, and its personal API key is configured for it
- **THEN** each use is checked with that agent's account and refused where its collection access
  does not allow it

#### Scenario: Doctor lists the identity sources

- **WHEN** store `bao` has Kubernetes passthrough, store `vw` a static credential for agent `laptop`
  only, and store `env` neither
- **THEN** `scrim doctor` reports `bao` as passthrough for service accounts, `vw` as static for
  `laptop` and refused for other agents, and `env` as using scrim's own identity

#### Scenario: Credential of the wrong kind

- **WHEN** the static credential held for an agent is not one the store takes (a malformed machine
  account access token, an API key that is not the expected JSON, a token the store does not accept)
- **THEN** the agent's use is refused and the error names the store and agent, not the credential

## ADDED Requirements

### Requirement: Logins from static agent credentials are cached

Where a static agent credential has to be traded for a session (Bitwarden Secrets Manager machine
accounts, Vaultwarden API keys), the session SHALL be cached per agent and credential until two thirds
of its lifetime has passed, keyed by a hash of the credential, never the credential. A cached session
the store refuses SHALL be dropped and the login repeated once.

#### Scenario: Revoked agent session

- **WHEN** Bitwarden stops accepting an agent's cached bearer token
- **THEN** scrim drops it, logs in once more with the agent's access token, and refuses the use if
  that login fails

#### Scenario: Rotated agent credential

- **WHEN** the reference for an agent's access token resolves to a new token
- **THEN** the next check logs in with the new token instead of using the cached session

### Requirement: Write checks only where the store can answer them

An adapter SHALL answer a write check as the agent only from what the store reports without
writing (Vault and OpenBao capabilities, Google `versions.add`, Bitwarden Secrets Manager `write`,
Vaultwarden `edit` and `readOnly`), and SHALL refuse the check as unsupported where the store
cannot (AWS, Azure Key Vault, Infisical, Doppler, 1Password Connect). A write SHALL never be made to
check a write.

#### Scenario: Read-only machine account

- **WHEN** an agent's machine account may read but not write the project of an existing secret
- **THEN** a write check for that agent is refused and a read check passes

#### Scenario: Store without a write check

- **WHEN** a write check is made for an agent of a Doppler store
- **THEN** it is refused as unsupported and nothing is sent to Doppler
