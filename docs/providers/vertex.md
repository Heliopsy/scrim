# Google Vertex AI

The `vertex` kind serves Vertex AI (Google Cloud's Agent Platform) in one location:
`https://<region>-aiplatform.googleapis.com`, `https://aiplatform.googleapis.com` for `global`,
or `https://aiplatform.<us|eu>.rep.googleapis.com` for the multi-region locations.

```yaml
providers:
  gcp:
    kind: vertex
    region: us-east5
    service-account: openbao://kv/gcp/vertex#key_json
```

`service-account` names the whole JSON key file of a service account with `roles/aiplatform.user`.
On GKE with workload identity, or on Compute Engine, use the attached service account instead:

```yaml
providers:
  gcp:
    kind: vertex
    region: global
    metadata-server: true
```

## Tokens

scrim signs a JWT with the key (RS256, scope `https://www.googleapis.com/auth/cloud-platform`,
audience the token endpoint) and exchanges it at `https://oauth2.googleapis.com/token`; with
`metadata-server` it asks the metadata server. The token is cached until shortly before it
expires and sent as `Authorization: Bearer`. The `token_uri` inside the key file is ignored, so a
key cannot send its assertion elsewhere; `token-url` in the configuration replaces the endpoint.
See [README.md](README.md#minted-tokens).

## What is redacted

| Path | Body |
| --- | --- |
| `.../publishers/anthropic/models/{model}:rawPredict`, `:streamRawPredict` | Anthropic Messages (`anthropic_version` stays byte-identical); the stream is SSE, restored as on the Anthropic API |
| `.../publishers/anthropic/models/count-tokens:rawPredict` | Anthropic Messages |
| `.../publishers/google/models/{model}:generateContent`, `:streamGenerateContent`, `:countTokens` | Gemini, with the Gemini codec |
| `/ws/google.cloud.aiplatform.v1.LlmBidiService/BidiGenerateContent` (WebSocket) | Gemini Live API, with the Live codec: each client message redacted, model text, transcriptions and tool call arguments restored |
| anything else | Redacted as generic JSON, response passed through |

The project, location and model in the path are redacted and guarded like the rest of the
request target. The route serves one location: an agent that sends a request for another
location in the path reaches the configured host, which refuses it. Configure one route per
location.

The Live API handshake gets the route's access token like any request. The client's `setup`
message names the model as `projects/{project}/locations/{location}/publishers/google/models/{model}`;
the `model` stays byte-identical, the system instruction and every turn are redacted. Audio the
client sends is a binary part. Placeholders the model speaks stay in the audio; the transcripts are
restored ([limitations](../limitations.md#how-traffic-reaches-scrim)).

## Claude Code

<!-- docs-test: skip: needs a configured Vertex route and Claude Code -->
```sh
CLAUDE_CODE_USE_VERTEX=1 CLOUD_ML_REGION=us-east5 ANTHROPIC_VERTEX_PROJECT_ID=my-project scrim run -- claude
```

`scrim run` sets `ANTHROPIC_VERTEX_BASE_URL` to the route plus `/v1` and
`CLAUDE_CODE_SKIP_VERTEX_AUTH=1`. `CLOUD_ML_REGION` must match the route's `region`, and so must
any `VERTEX_REGION_CLAUDE_*` override.
