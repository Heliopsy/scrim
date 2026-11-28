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
| `foundry` | Microsoft Foundry | Anthropic Messages under `/anthropic`, Voice Live (Realtime) over WebSocket | `api-key` header or Entra ID token | [foundry.md](foundry.md) |
| `vertex` | Google Vertex AI | Anthropic Messages on `rawPredict`/`streamRawPredict`, Gemini `generateContent`, Gemini Live over WebSocket | Google access token (service account key or metadata server) | [vertex.md](vertex.md) |

Claude on Google Cloud operated by Anthropic (`CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD`) is not
served; `scrim run` refuses Claude Code in that mode.

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
| `kind` | `bedrock`, `bedrock-mantle`, `anthropic-aws`, `foundry` or `vertex` |
| `region` | AWS kinds: the region of the endpoint and of the signature; `vertex`: the location (`global`, `us`, `eu` or a region) |
| `resource` | `foundry`: the Foundry resource name alone, not a URL |
| `upstream` | An origin (`https://host[:port]`, no path) that replaces the default endpoint, for a VPC endpoint or a test |
| `access-key-id`, `secret-access-key`, `session-token` | AWS kinds: store references to the keys scrim signs with |
| `api-key` | Store reference to an API key (Bedrock API key and Claude Platform on AWS key as a bearer token, Foundry key as `api-key`) |
| `service-account` | `vertex`: store reference to a service account key (the JSON key file) |
| `metadata-server` | `vertex`: `true` takes tokens from the metadata server (GKE workload identity, Compute Engine) |
| `tenant-id`, `client-id`, `client-secret` | `foundry`: Entra ID application; the secret is a store reference |
| `token-url` | Replaces the token endpoint (Google, Entra ID or the metadata server), for private endpoints and tests |

Credential fields are store references, never values; a literal is rejected when the
configuration loads. A reference without a field names the secret's default field. Each
credential is loaded with its store at start-up and refreshed with it, and is in the redaction set,
whether or not the store's `redact` list or a catalog entry covers it. A credential a reload adds is
loaded after the next restart; scrim logs a warning naming it until then. A route whose credentials
are not loaded refuses every request with `503` and the code `credential_unavailable`, naming the
missing reference, and sends nothing.

The credentials are used toward the route's upstream only. A provider route is never chained
(`proxy.chain.url` applies to the built-in routes only), because the chained proxy would receive
the signed request or the key.

The values are also ordinary store values: if one shows up in a prompt or a tool result it is
redacted like any other secret, and as a credential it is never restored into a response.

## Routes

Every provider request goes through a route, served at `/<name>` on the LLM base URL
(`http://127.0.0.1:9790/<name>` by default). Through the forward proxy or a transparent listener,
a request is matched to a route by its host. The built-in routes are always there; a cloud
provider route adds one per `providers` instance, and a host goes to the first route that names it.

<!-- BEGIN GENERATED PROVIDER ROUTES: run `go test ./internal/daemon -run TestProviderRouteDocs -update` -->

Built-in routes, served without configuration:

| Route | Gate `provider` | Hosts (forward proxy, transparent) | Upstream setting | Default upstream |
| --- | --- | --- | --- | --- |
| `/anthropic` | `anthropic` | `api.anthropic.com` | `proxy.upstream.anthropic` | `https://api.anthropic.com` |
| `/openai` | `openai` | `api.openai.com` | `proxy.upstream.openai` | `https://api.openai.com` |
| `/gemini` | `gemini` | `generativelanguage.googleapis.com` | `proxy.upstream.gemini` | `https://generativelanguage.googleapis.com` |
| `/chatgpt` | `openai` | `chatgpt.com` | `proxy.upstream.chatgpt` | `https://chatgpt.com` |
| `/chatgpt-ab` | `openai` | `ab.chatgpt.com` | `proxy.upstream.chatgpt-ab` | `https://ab.chatgpt.com` |

Cloud provider kinds:

| Kind | Gate `provider` |
| --- | --- |
| `anthropic-aws` | `anthropic` |
| `bedrock` | `bedrock` |
| `bedrock-mantle` | `anthropic` |
| `foundry` | `anthropic` |
| `vertex` | `vertex` |

<!-- END GENERATED PROVIDER ROUTES -->

`chatgpt` and `chatgpt-ab` carry Codex signed in with ChatGPT, reached through the forward proxy.
Nothing on `ab.chatgpt.com` is a documented API, so every body there is redacted as generic JSON.

## Who may use a route

The request gate decides as for any provider request: `op == "llm.forward"`, with `provider` set
as in the tables above. Among the cloud routes that means `bedrock` for Bedrock, `vertex` for
Vertex AI, and `anthropic` for Bedrock Mantle, Claude Platform on AWS and Foundry, the same name
the built-in `/anthropic` route has. The gate sees the provider name and the caller, not the route,
so a rule cannot allow the Anthropic API while denying those three. A cloud route's requests are
paid with scrim's credentials, not the agent's: on a deployment that serves several teams, deny
`bedrock` and `vertex` to the sessions that do not need them, and configure a Mantle, Claude
Platform on AWS or Foundry route only where every agent allowed the Anthropic API may use it too.

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
| `CLAUDE_CODE_USE_VERTEX` | `ANTHROPIC_VERTEX_BASE_URL` (route + `/v1`) | `CLAUDE_CODE_SKIP_VERTEX_AUTH=1` | |

When the mode is on and no route of that kind is configured, `scrim run` refuses to start the
agent, because Claude Code would reach the provider directly. The first route of each kind is
used. `scrim run` reads the routes from its own configuration; with a system service, keep the
two configurations in step.

Other agents point their SDK's base URL at `http://127.0.0.1:9790/<name>` (plus `/anthropic` for
Foundry, `/v1` for Vertex) and turn their own signing off.

### Managed settings

`scrim install --managed-settings` pins Claude Code to the built-in `/anthropic` route: its managed
settings allow only `customEndpoint` and set `ANTHROPIC_BASE_URL`
([interception.md](../interception.md#claude-code)). Claude Code then refuses to start in its
Bedrock, Mantle, Claude Platform on AWS, Foundry and Vertex modes, so on that machine the cloud
routes cannot serve Claude Code, under `scrim run` or not. Other agents can still use them. To run
Claude Code through a cloud route, leave out `--managed-settings` and start it with `scrim run`.

## Minted tokens

Vertex and Foundry with Entra ID authenticate with short-lived OAuth 2.0 access tokens. The data
plane mints them from the stored credential when a request needs one, caches each until five
minutes before it expires (shared across snapshot updates), and sends it as
`Authorization: Bearer`. A token endpoint that refuses, times out or answers without a token
makes the request fail with `credential_unavailable`, naming the endpoint's host and the status;
the response body is never shown. Token requests go out through the same upstream client as
provider requests, with the same trust roots.
