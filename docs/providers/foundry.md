# Microsoft Foundry

The `foundry` kind serves Claude in Microsoft Foundry at
`https://<resource>.services.ai.azure.com/anthropic`. Requests and responses are the Anthropic
Messages API, redacted and restored exactly as on the Anthropic API.

```yaml
providers:
  azure:
    kind: foundry
    resource: my-foundry-resource
    api-key: openbao://kv/azure/foundry#key
```

scrim sends the key in the `api-key` header of each redacted request and drops the agent's
`Authorization`, `api-key` and `x-api-key`.

## Microsoft Entra ID

With an Entra ID application instead of a key, scrim mints access tokens with the client
credentials grant (scope `https://ai.azure.com/.default`) and sends them as `Authorization: Bearer`:

```yaml
providers:
  azure:
    kind: foundry
    resource: my-foundry-resource
    tenant-id: 00000000-0000-0000-0000-000000000000
    client-id: 11111111-1111-1111-1111-111111111111
    client-secret: openbao://kv/azure/foundry#client_secret
```

The application needs the `Foundry User` or `Cognitive Services User` role on the resource.
Tokens come from `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token`; `token-url`
replaces it. Managed identities and workload identity federation are not supported yet.

The route forwards the whole path to the resource origin, so the agent's base URL is the route
plus `/anthropic`: `http://127.0.0.1:9790/azure/anthropic`.

## Claude Code

<!-- docs-test: skip: needs a configured Foundry route and Claude Code -->
```sh
CLAUDE_CODE_USE_FOUNDRY=1 scrim run -- claude
```

`scrim run` sets `ANTHROPIC_FOUNDRY_BASE_URL` to the route plus `/anthropic` and
`CLAUDE_CODE_SKIP_FOUNDRY_AUTH=1`, and removes `ANTHROPIC_FOUNDRY_API_KEY`,
`ANTHROPIC_FOUNDRY_AUTH_TOKEN` and `ANTHROPIC_FOUNDRY_RESOURCE`. Claude Code then sends
`Authorization: Bearer skip-foundry-auth`, which scrim drops.
