# Claude Platform on AWS

The `anthropic-aws` kind serves Claude Platform on AWS, the Anthropic API with AWS
authentication, at `https://aws-external-anthropic.<region>.api.aws`. Requests and responses are
the Anthropic Messages API, redacted and restored exactly as on the Anthropic API.

```yaml
providers:
  claude-aws:
    kind: anthropic-aws
    region: us-west-2
    access-key-id: openbao://kv/aws/claude#access_key_id
    secret-access-key: openbao://kv/aws/claude#secret_access_key
```

scrim signs each redacted request with SigV4, service `aws-external-anthropic` in the configured
region. With a workspace API key from the AWS console instead, set `api-key: <reference>`; scrim
sends it as `Authorization: Bearer`. The IAM principal needs `aws-external-anthropic:CreateInference`
(and `aws-external-anthropic:CallWithBearerToken` for a key).

Every request needs the `anthropic-workspace-id` header. It is not a secret and scrim forwards
the agent's: with Claude Code, set `ANTHROPIC_AWS_WORKSPACE_ID`.

## Claude Code

<!-- docs-test: skip: needs a configured Claude Platform on AWS route and Claude Code -->
```sh
CLAUDE_CODE_USE_ANTHROPIC_AWS=1 AWS_REGION=us-west-2 ANTHROPIC_AWS_WORKSPACE_ID=wrkspc_01AbCdEf23GhIj scrim run -- claude
```

`scrim run` sets `ANTHROPIC_AWS_BASE_URL` to the route and
`CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH=1`, and removes `ANTHROPIC_AWS_API_KEY`.
