# Tasks

## 1. Adapters

- [x] 1.1 Doppler: static token and `doppler-oidc` login, read check by reading, writes unsupported; verify: `TestAgentCanStaticToken` and `TestAgentCanOIDC` against the fake (service token outside its config refused, restricted value withheld, login cached, 401 relogs once, session end drops it)
- [x] 1.2 1Password Connect: static Connect token, read check by the vault's item listing; verify: `TestAgentCanRead`, `TestAgentCanMatchesByID`, `TestAgentCanRefusesUnchecked` against the fake (no full item fetched as the agent)
- [x] 1.3 Bitwarden Secrets Manager: machine account login per agent, read and write checks from the server's access flags; verify: `go test ./internal/stores/bws/` (read-only, no-access and other-organisation agents, new secret checked on its project, cached login, 401 relog)
- [ ] 1.4 Vaultwarden: API key login per agent, read and write checks from `viewPassword`, `edit` and `readOnly`; verify: Vaultwarden in podman with two member accounts on one collection
- [x] 1.5 `agentcache.Forget`; verify: `TestForget`

## 2. Wiring and docs

- [x] 2.1 `doppler-oidc` in `identity.store-login` with `identity` templated; verify: `TestTokenExchangeSettings`
- [x] 2.2 docs/identity.md, docs/limitations.md, docs/stores/*.md, `just config-docs`

## 3. Live checks (need real accounts)

- [ ] 3.1 Doppler: a service account identity trusting scrim's issuer, and the status of a refused OIDC login
- [ ] 3.2 1Password Connect: the status of an item listing for a vault outside a token, and a write-only token
- [ ] 3.3 Bitwarden Secrets Manager: read and write flags of a read-only machine account, and the event log entries
- [ ] 3.4 Infisical: recheck for a permissions endpoint that accepts machine identity tokens
