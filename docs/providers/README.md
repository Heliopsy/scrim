# Cloud provider routes

Claude is served by Anthropic's API and by several clouds. scrim redacts requests to all of them.
For the Anthropic API the agent's own key passes through (see [run.md](../run.md)). The clouds
authenticate differently, and two things rule out passing the agent's credentials:

- Redaction changes the request body, and AWS signatures (SigV4) cover the body. A signature the
  agent made over its own body is invalid once scrim has replaced a secret in it.
- The agent should not hold cloud credentials at all. With them it could reach the provider
  without scrim.

So a cloud provider route authenticates every request itself, after redaction, with credentials
scrim reads from a store. Whatever authentication the agent sent (`Authorization`, `x-api-key`,
`api-key`, `x-amz-*` headers) is dropped before the request is redacted and never reaches the
provider.

| Kind | Provider | Wire format | Authentication | Page |
| --- | --- | --- | --- | --- |
| `bedrock` | Amazon Bedrock runtime | InvokeModel (Anthropic body), Converse, event stream | SigV4 (`bedrock`) or Bedrock API key | [bedrock.md](bedrock.md) |
| `bedrock-mantle` | Bedrock Mantle endpoint | Anthropic Messages | SigV4 (`bedrock-mantle`) or Bedrock API key | [bedrock.md](bedrock.md#mantle) |
| `anthropic-aws` | Claude Platform on AWS | Anthropic Messages | SigV4 (`aws-external-anthropic`) or workspace API key | [claude-platform-aws.md](claude-platform-aws.md) |
| `foundry` | Microsoft Foundry | Anthropic Messages under `/anthropic` | `api-key` header | [foundry.md](foundry.md) |

Google Vertex AI is not served yet; `scrim run` refuses Claude Code with `CLAUDE_CODE_USE_VERTEX`.

## Configuration

Each route is an instance of the `providers` collection. The instance name is the route: it is
served at `/<name>` on the LLM base URL, and the provider's host is routed to it when traffic
arrives through the forward proxy or a transparent listener.

```yaml
providers:
  bedrock:
    kind: bedrock
    region: us-east-1
    access-key-id: openbao://kv/aws/bedrock#access_key_id
    secret-access-key: openbao://kv/aws/bedrock#secret_access_key
    session-token: openbao://kv/aws/bedrock#session_token   # temporary credentials only
```

| Field | Meaning |
| --- | --- |
| `kind` | `bedrock`, `bedrock-mantle`, `anthropic-aws` or `foundry` |
| `region` | AWS kinds: the region of the endpoint and of the signature |
| `resource` | `foundry`: the Foundry resource name alone, not a URL |
| `upstream` | An origin (`https://host[:port]`, no path) that replaces the default endpoint, for a VPC endpoint or a test |
| `access-key-id`, `secret-access-key`, `session-token` | AWS kinds: store references to the keys scrim signs with |
| `api-key` | Store reference to an API key (Bedrock API key and Claude Platform on AWS key as a bearer token, Foundry key as `api-key`) |

Credential fields are store references, never values; a literal is rejected when the
configuration loads. The values must be in the store's redaction set (they are when the store
loads every secret, the default). A route whose credentials are not loaded refuses every request
with `503` and the code `credential_unavailable`, naming the missing reference, and sends nothing.

The credentials are used toward the route's upstream only. A provider route is never chained
(`proxy.chain.url` applies to the built-in routes only), because the chained proxy would receive
the signed request or the key.

The values are also ordinary store values: if one shows up in a prompt or a tool result it is
redacted like any other secret, and as a credential it is never restored into a response.

## Who may use a route

The request gate decides as for any provider request: `op == "llm.forward"` with `provider` set
to `bedrock` for Bedrock routes and `anthropic` for the others. A deployment that serves several
teams should allow cloud routes only to the sessions that need them, since scrim's credentials,
not the agent's, pay for the request.

## Claude Code under scrim run

`scrim run -- claude` keeps Claude Code's provider mode. When the inherited environment turns one
on and scrim has a route of the matching kind, it points Claude Code at the route, turns Claude
Code's own authentication off and removes inherited keys that would take precedence:

| Claude Code mode | Base URL variable set | Turned off | Removed |
| --- | --- | --- | --- |
| `CLAUDE_CODE_USE_BEDROCK` | `ANTHROPIC_BEDROCK_BASE_URL` | `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1` | `AWS_BEARER_TOKEN_BEDROCK` |
| `CLAUDE_CODE_USE_MANTLE` | `ANTHROPIC_BEDROCK_MANTLE_BASE_URL` | `CLAUDE_CODE_SKIP_MANTLE_AUTH=1` | `AWS_BEARER_TOKEN_BEDROCK` |
| `CLAUDE_CODE_USE_ANTHROPIC_AWS` | `ANTHROPIC_AWS_BASE_URL` | `CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH=1` | `ANTHROPIC_AWS_API_KEY` |
| `CLAUDE_CODE_USE_FOUNDRY` | `ANTHROPIC_FOUNDRY_BASE_URL` (route + `/anthropic`) | `CLAUDE_CODE_SKIP_FOUNDRY_AUTH=1` | `ANTHROPIC_FOUNDRY_API_KEY`, `ANTHROPIC_FOUNDRY_AUTH_TOKEN`, `ANTHROPIC_FOUNDRY_RESOURCE` |

When the mode is on and no route of that kind is configured, `scrim run` refuses to start the
agent, because Claude Code would reach the provider directly. The first route of each kind is
used. `scrim run` reads the routes from its own configuration; with a system service, keep the
two configurations in step.

Other agents point their SDK's base URL at `http://127.0.0.1:9790/<name>` (plus `/anthropic` for
Foundry) and turn their own signing off.
