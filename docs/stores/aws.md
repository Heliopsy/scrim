# AWS Secrets Manager and SSM Parameter Store

Two adapters share one package and one way to authenticate:

- `awssm` reads, lists, watches and writes secrets in AWS Secrets Manager: string secrets, JSON
  secrets with one field per key, and binary secrets, by version ID or staging label.
- `ssm` reads, lists, watches and writes parameters in AWS Systems Manager Parameter Store:
  `String`, `StringList` and `SecureString` (decrypted), along the parameter hierarchy, by version
  or label.

scrim signs in with the identity it runs under (an EC2 instance profile, an ECS task role, EKS Pod
Identity, IRSA, or a profile on a workstation) and needs no access key in its configuration. Agents
never call AWS: they ask scrim, which enforces write-only toward agents itself.

## Capabilities

| Kind    | read | list | watch | write | generate | dynamic |
|---------|------|------|-------|-------|----------|---------|
| `awssm` | yes  | yes  | yes   | yes   | no       | no      |
| `ssm`   | yes  | yes  | yes   | yes   | no       | no      |

Both also match names by a trailing `*` (`aws-sm://app/db-*`), which AWS filters on its side. Watch
polls; see [Watch and refresh](#watch-and-refresh).

## References

### Secrets Manager

```text
<scheme>://<secret-name>[?version=<version-id>][?stage=<staging-label>][#<field>]
```

- `<scheme>` is the store instance name or one of its aliases, for example `aws-sm://`.
- The path is the secret's name as Secrets Manager shows it, slashes included:
  `aws-sm://prod/payments/db` is the secret named `prod/payments/db`. A secret's full ARN works as
  well.
- A secret whose string is a JSON object has one field per key: `aws-sm://prod/payments/db#password`.
  A key whose value is not a JSON string (a number, an object) reads as its JSON text. Any other
  string, and a binary secret, is the single field `value`.
- `?stage=AWSPREVIOUS` reads the version that holds a staging label: `AWSCURRENT` (the default),
  `AWSPREVIOUS`, `AWSPENDING` or a label of your own. `?version=<id>` reads a version by its version
  ID. Both together must agree. A stage no version holds is not found; scrim never falls back to the
  current version. Any other selector is refused.

### Parameter Store

```text
<scheme>://<parameter/path>[?version=<n>|?label=<label>][#value]
<scheme>://<parameter/path>:<n>
<scheme>://<parameter/path>:<label>
```

- The path is the parameter's hierarchical name without its leading slash: `aws-ssm://app/prod/db`
  is `/app/prod/db`. Parameters whose name does not start with `/` cannot be addressed.
- A parameter holds one value, the field `value`. A `StringList` reads as its comma-joined text, a
  `SecureString` is decrypted (`WithDecryption`).
- `?version=3` or `?label=stable` selects a version, and so does the native suffix
  (`aws-ssm://app/prod/db:3`, `aws-ssm://app/prod/db:stable`). Use one or the other, not both.
- Public parameters under `aws/` (`aws-ssm://aws/service/...`) can be read; names under `aws` or
  `ssm` cannot be written, as AWS reserves them.

A listing prefix is a folder: `aws-sm://prod` lists every secret whose name starts with `prod/`,
`aws-ssm://app/prod` every parameter under `/app/prod/`, recursively. `prod/*` is the same, and
`prod/db-*` matches by name. Listing never asks AWS for a value.

## Authentication

With no credential options scrim uses the AWS SDK for Go's default chain, in its order:

1. Environment: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`.
2. The shared config and credentials files (`~/.aws/config`, `~/.aws/credentials`, or
   `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`), with the `profile` option or `AWS_PROFILE`,
   including SSO, `credential_process` and role profiles.
3. A web identity token (`AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`), as IRSA sets up.
4. Container credentials (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `_FULL_URI`), as ECS task roles
  and EKS Pod Identity set up.
5. EC2 instance metadata (IMDSv2), for an instance profile.

`assume-role.arn` assumes a role on top of whatever the chain found, for example to reach another
account. Access keys can be given as `access-key-id` and `secret-access-key`, by reference only in
practice (`file:`, `env:`, a systemd credential or another store); a literal works but logs a
warning. Prefer the ambient identity.

scrim never logs credentials. The secret access key and session token it signs with, static or
temporary, are added to the redaction set, so an agent that finds them cannot send them to a model
provider. No credential appears in an error.

### EKS Pod Identity or IRSA

Give scrim's service account a role and set only the region:

```yaml
stores:
  aws-sm:
    kind: awssm
    region: eu-west-1
    redact:
      - aws-sm://agents/*
```

The pod's identity is picked up from the environment the EKS webhook or the Pod Identity agent
injects. `aws-sm://agents/github#token` then resolves with no access key anywhere in configuration.

## Least privilege

Scope the identity to the names scrim serves. Secrets Manager:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Read",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:agents/*"
    },
    {
      "Sid": "List",
      "Effect": "Allow",
      "Action": "secretsmanager:ListSecrets",
      "Resource": "*"
    },
    {
      "Sid": "WriteInbox",
      "Effect": "Allow",
      "Action": ["secretsmanager:PutSecretValue", "secretsmanager:CreateSecret", "secretsmanager:TagResource"],
      "Resource": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:agents/inbox/*"
    }
  ]
}
```

Parameter Store needs `ssm:GetParameter`, `ssm:DescribeParameters` and `ssm:ListTagsForResource`
to read and list, `ssm:PutParameter` and `ssm:AddTagsToResource` to write, and `kms:Decrypt` (and
`kms:Encrypt` to write) on the KMS key of `SecureString` parameters. A read needs the describe and
tag permissions as well, since policy labels come from them; a read whose labels cannot be fetched
fails rather than go on without them.

`ListSecrets` and `DescribeParameters` cannot be scoped to a resource. Without them, name every
secret in `redact` instead of a folder; listing and watch then fail with permission denied, and the
refresh reads each named secret on `refresh.interval`.

An identity allowed to write but not to read a path works: scrim keeps the value it wrote in the
redaction set and never needs to read it back.

## Configuration

Each instance lives under `stores.<instance>`. The generic keys (`kind`, `aliases`, `redact`,
`refresh.*`, `labels`) are described in [README.md](README.md); the keys below are the adapter's
own. Every key can also be set as an environment variable: `SCRIM_` followed by the full key
upper-cased, with dots and dashes as `_`. Unknown keys fail validation and name the closest known
key.

```yaml
stores:
  aws-sm:
    kind: awssm
    region: eu-west-1
    assume-role:
      arn: arn:aws:iam::111122223333:role/scrim-secrets
      external-id: scrim
    redact:
      - aws-sm://agents/*
  aws-ssm:
    kind: ssm
    region: eu-west-1
    parameter-type: SecureString
    kms-key-id: alias/scrim
    redact:
      - aws-ssm://app/prod/*
```

| Key | Kinds | Type | Default | Meaning |
| --- | --- | --- | --- | --- |
| `stores.<name>.region` | both | string | from the chain | AWS region. Without it the region comes from `AWS_REGION`, `AWS_DEFAULT_REGION` or the profile; with none, every call fails naming the option. |
| `stores.<name>.profile` | both | string | `AWS_PROFILE` or `default` | Shared config profile. |
| `stores.<name>.endpoint` | both | URL | AWS's regional endpoint | Another endpoint: a VPC interface endpoint, or an emulator. `AWS_ENDPOINT_URL` applies when unset. |
| `stores.<name>.fips` | both | bool | `false` | Use the FIPS endpoint (`secretsmanager-fips`, `ssm-fips`). |
| `stores.<name>.access-key-id` | both | secret reference | none | Static access key ID. Goes with `secret-access-key`; excludes `profile`. |
| `stores.<name>.secret-access-key` | both | secret reference | none | Static secret access key, by reference. |
| `stores.<name>.assume-role.arn` | both | string | none | IAM role to assume with STS on top of the chain's credentials. Session credentials are refreshed before they expire. |
| `stores.<name>.assume-role.external-id` | both | string | none | External ID the role's trust policy asks for. |
| `stores.<name>.assume-role.session-name` | both | string | `scrim` | Role session name, as CloudTrail shows it. |
| `stores.<name>.assume-role.duration` | both | duration | `15m` | Session length, 15m to 12h (the role's maximum applies). |
| `stores.<name>.assume-role.sts-endpoint` | both | URL | AWS's STS endpoint | Another STS endpoint, such as a VPC endpoint. |
| `stores.<name>.timeout` | both | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.max-attempts` | both | integer | `3` | Attempts per call for throttling, 5xx answers and network errors, with jittered backoff. |
| `stores.<name>.watch.interval` | both | duration | `30s` | How often the listing is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | both | duration | `5m` | Longest wait between polls while AWS keeps failing. |
| `stores.<name>.kms-key-id` | both | string | AWS managed key | KMS key for secrets scrim creates (`CreateSecret`) or `SecureString` parameters scrim creates. Existing secrets keep theirs. |
| `stores.<name>.create-secrets` | `awssm` | bool | `true` | Create a secret that does not exist yet. With `false`, writing a missing secret fails as not found. |
| `stores.<name>.parameter-type` | `ssm` | string | `SecureString` | Type of parameters scrim creates: `SecureString` or `String`. An update keeps the parameter's type. |
| `stores.<name>.tier` | `ssm` | string | AWS default | `Standard`, `Advanced` or `Intelligent-Tiering` for parameters scrim writes. |

## Writes

`awssm` adds a version with `PutSecretValue`, so the previous one becomes `AWSPREVIOUS`, and creates
a missing secret with `CreateSecret` unless `create-secrets` is off. A write with the single field
`value` stores that value as the secret string, as any AWS client expects; a value that is not UTF-8
is stored as a binary secret, and a value that is itself a JSON object is wrapped as
`{"value": ...}` so it reads back unchanged. Several fields are stored as a JSON object. A create-only
write uses `CreateSecret` alone and fails with a conflict when the secret exists. A secret scheduled
for deletion reads as not found and refuses writes.

`ssm` creates a parameter with `PutParameter` without overwrite (type `parameter-type`, `tier`,
`kms-key-id`, tags), and on an existing one writes a new version with overwrite, keeping its type.
Parameters hold a single field, `value`, of non-empty UTF-8 text; anything else is refused before AWS
is called. Values over AWS's limits (64 KiB per secret, 4 KiB per standard parameter, 8 KiB advanced)
are refused by AWS and reported as unsupported.

Labels passed with a write (catalog bindings such as `scrim.hosts`) become resource tags. AWS tag
values cannot hold `,` and some other characters, so scrim writes `=` and each such character as `=`
followed by its UTF-8 bytes in hex (`a.example,b.example` becomes `a.example=2Cb.example`) and
decodes `scrim.*` tags on read. Write a `scrim.hosts` tag by hand the same way. Keys under `awssm.`,
`ssm.`, `store.` or `aws:` are not written.

## Policy labels

Every secret carries labels that policy rules match as `secret.labels`
([policy.md](../policy.md#labels-from-stores)). The adapters fetch them without values:
`DescribeSecret` for Secrets Manager, `DescribeParameters` and `ListTagsForResource` for Parameter
Store, which is also what `scrim catalog labels` and a write to an existing secret use.

| Label | Kind | Meaning |
| --- | --- | --- |
| `awssm.name` | `awssm` | Secret name. |
| `awssm.arn`, `awssm.account`, `awssm.region` | `awssm` | ARN and the account and region in it. |
| `awssm.stage`, `awssm.stage.<label>` = `true` | `awssm` | Staging labels of the version addressed (`AWSCURRENT`, `AWSPREVIOUS`, your own). |
| `awssm.kms-key` | `awssm` | KMS key, when the secret names one. |
| `awssm.rotation` | `awssm` | `true` or `false`; `awssm.rotation.lambda` is the rotation function when on. |
| `awssm.rotated`, `awssm.created`, `awssm.changed` | `awssm` | Last rotation, creation and change, RFC 3339 UTC. |
| `awssm.owning-service` | `awssm` | The service managing the secret (`rds`, ...), for managed secrets. |
| `awssm.primary-region` | `awssm` | Primary region of a replicated secret. |
| `ssm.name`, `ssm.path` | `ssm` | Parameter name (`/app/prod/db`) and its hierarchy (`/app/prod`, `/` at the top). |
| `ssm.type`, `ssm.tier`, `ssm.data-type` | `ssm` | `String`, `StringList` or `SecureString`; `Standard`, `Advanced`; `text` or `aws:ec2:image`. |
| `ssm.kms-key` | `ssm` | KMS key of a `SecureString`. |
| `ssm.arn`, `ssm.account`, `ssm.region` | `ssm` | ARN and the account and region in it. |
| `ssm.modified`, `ssm.modified-by` | `ssm` | Last change, RFC 3339 UTC, and who made it. |
| `ssm.policy`, `ssm.policy.<type>` = `true` | `ssm` | Parameter policies attached (`Expiration`, `ExpirationNotification`, `NoChangeNotification`). |
| `<kind>.meta.<tag-key>` | both | Every resource tag, as tagged. |
| `scrim.<key>` | both | Tags whose key starts with `scrim.` (catalog bindings), decoded as above. |

Tags are editable by anyone with `TagResource` or `AddTagsToResource`, so they never set a native
label: a tag `awssm.name` shows only as `awssm.meta.awssm.name`. Apart from `scrim.*`, no tag sets a
label outside the `meta` namespace, so a tag cannot shadow a label derived under
`stores.<name>.labels`. Derive your own from tags:

```yaml
stores:
  aws-sm:
    kind: awssm
    labels:
      env: awssm.meta.environment
      managed: {from: awssm.owning-service, value: "true"}
```

```yaml
- name: aws-previous-versions
  decision: ask
  when: '"awssm.stage.AWSPREVIOUS" in secret.labels'
  reason: Reading a superseded secret version needs a human
- name: aws-ssm-plain-writes
  decision: deny
  when: op in ["store.write", "secret.gen"] && "ssm.type" in secret.labels && secret.labels["ssm.type"] != "SecureString"
  reason: Parameters scrim writes must be SecureString
```

Labels are metadata only: no label holds a value, a description or a version's content.

## Watch and refresh

Secrets Manager has no change feed scrim can subscribe to without extra infrastructure, so both
adapters poll: `ListSecrets` (version IDs and change dates) or `DescribeParameters` (versions and
modification dates) every `watch.interval`, and report a secret whose `AWSCURRENT` version or
parameter version moved, a new one, or one that is gone (deleted or scheduled for deletion). A
rotation that moves `AWSCURRENT` is a change; scrim keeps the previous value in the redaction set
for `refresh.retention`. A changed secret is read again; one whose version is unchanged is not.

Each poll is one paginated listing call. For Parameter Store, a full list (the catalog, and refresh
of a folder target) adds one `ListTagsForResource` per parameter, so keep folder targets narrow on
large hierarchies.

## Errors

Errors name the store, the operation, the reference and AWS's error code. For reads, listing and
health AWS's own message is kept (it says which principal was denied which action); for writes it is
dropped, because AWS validation messages can quote the request, value included.

| AWS answer | scrim error |
| --- | --- |
| `ResourceNotFoundException`, `ParameterNotFound`, `ParameterVersionNotFound`, a secret scheduled for deletion | not found |
| `AccessDeniedException`, invalid or expired credentials, `DecryptionFailure`, KMS denied | permission denied |
| `ResourceExistsException`, `ParameterAlreadyExists` (create-only) | conflict |
| Throttling, 5xx, timeouts, connection errors (after `max-attempts`) | unavailable |
| Validation errors on a write (size, pattern, tag limits) | unsupported |

Health signs one listing call. An access denied answer still counts as healthy, since it proves the
endpoint answers and the credentials are valid.

## Testing against LocalStack

The conformance suite runs both adapters against LocalStack in rootless podman, the last community
image (4.14; later images need a license token):

<!-- docs-test: skip: starts a container -->
```sh
SCRIM_TEST_PODMAN=1 go test -race -run TestLocalStack ./internal/stores/aws/
```

`SCRIM_TEST_LOCALSTACK_ENDPOINT=http://127.0.0.1:4566` uses a LocalStack you started yourself; the
outage cases are skipped then. Point an instance at one with `endpoint` and any test keys:

```yaml
stores:
  aws-local:
    kind: awssm
    region: us-east-1
    endpoint: http://127.0.0.1:4566
    access-key-id: env:LOCALSTACK_KEY_ID
    secret-access-key: env:LOCALSTACK_SECRET_KEY
```
