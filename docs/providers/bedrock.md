# Amazon Bedrock

The `bedrock` kind serves the Bedrock runtime API at `https://bedrock-runtime.<region>.amazonaws.com`.

```yaml
providers:
  bedrock:
    kind: bedrock
    region: us-east-1
    access-key-id: openbao://kv/aws/bedrock#access_key_id
    secret-access-key: openbao://kv/aws/bedrock#secret_access_key
```

With a [Bedrock API key](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
instead of IAM keys, set `api-key: <reference>`; scrim sends it as `Authorization: Bearer`.

## What is redacted

| Path | Body |
| --- | --- |
| `POST /model/{modelId}/invoke`, `/invoke-with-response-stream` | Anthropic Messages (`anthropic_version` and the other configuration stay byte-identical, as for the Anthropic API) |
| `POST /model/{modelId}/converse`, `/converse-stream` | Converse: `inferenceConfig`, `guardrailConfig`, `performanceConfig`, the tool choice and signed reasoning stay byte-identical; messages, system prompts, tool specifications and tool results are redacted; image, document and video bytes are binary parts, scanned under `redaction.binary` ([limitations](../limitations.md#redaction)) |
| `POST /model/{modelId}/count-tokens` | The base64 Anthropic body in `input.invokeModel.body` is decoded, redacted and encoded again; the `converse` form is redacted as JSON |
| anything else | Redacted as generic JSON, response passed through |

The model id in the path is redacted and guarded like the rest of the request target.

## Signing

scrim signs with SigV4 (service `bedrock`, the configured region) after redaction, over the
exact bytes that leave: `host`, `x-amz-date`, `x-amz-security-token` with temporary credentials,
`content-type` and any other `x-amz-*` header, and the SHA-256 of the body. The agent's own
signature and headers are dropped first.

## Responses

Streaming responses come back in Amazon's binary event stream
(`application/vnd.amazon.eventstream`). scrim decodes each message, checks both CRCs, and
restores placeholders inside it:

- InvokeModelWithResponseStream: each `chunk` event carries an Anthropic stream event base64-encoded
  in `bytes`. The events go through the same restorer as the Anthropic API and come back as
  `chunk` events, one per event.
- ConverseStream: `contentBlockDelta` text and tool input deltas are restored, with held text
  released before `contentBlockStop`, `messageStop` and `metadata`.

A message scrim changes gets new CRCs; every other message is forwarded byte for byte. A stream
with a bad CRC or impossible lengths is forwarded untouched from that point, so placeholders stay
placeholders. Non-streaming responses are restored as JSON.

## Claude Code

<!-- docs-test: skip: needs a configured Bedrock route and Claude Code -->
```sh
CLAUDE_CODE_USE_BEDROCK=1 AWS_REGION=us-east-1 scrim run -- claude
```

`scrim run` sets `ANTHROPIC_BEDROCK_BASE_URL` to the route and `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1`
([README.md](README.md#claude-code-under-scrim-run)). Claude Code also asks for the account's
inference profiles at start (`GET /inference-profiles`); that request goes to the runtime host
through the route, which does not serve it, and Claude Code carries on with its built-in model
ids. Pin models with `ANTHROPIC_MODEL` and the `ANTHROPIC_DEFAULT_*_MODEL` variables.

## Mantle

The `bedrock-mantle` kind serves `https://bedrock-mantle.<region>.api.aws`, which speaks the
Anthropic Messages API. It signs with SigV4 service `bedrock-mantle` or sends a Bedrock API key
as a bearer token. Claude Code uses it with `CLAUDE_CODE_USE_MANTLE`; `scrim run` sets
`ANTHROPIC_BEDROCK_MANTLE_BASE_URL` and `CLAUDE_CODE_SKIP_MANTLE_AUTH=1`.
