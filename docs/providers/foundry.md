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
`Authorization`, `api-key` and `x-api-key`. Microsoft Entra ID tokens are not minted by scrim yet.

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
