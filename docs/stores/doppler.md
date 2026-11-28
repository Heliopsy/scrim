# Doppler

The `doppler` adapter reads, lists, watches and writes secrets in [Doppler](https://www.doppler.com)
through its v3 REST API. scrim authenticates with one Doppler token and is the only holder of it.
Agents never call Doppler: they ask scrim, which enforces write-only toward agents itself.

## Capabilities

<!-- BEGIN GENERATED STORE CAPABILITIES kinds=doppler -->

| Kind | read | list | watch | write | glob | dynamic | per-agent check | `identity.store-login` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `doppler` | yes | yes | yes | yes | yes | no | yes | `doppler-oidc` |

The columns are explained under [Capabilities](README.md#capabilities).

<!-- END GENERATED STORE CAPABILITIES -->

Listing also takes a trailing `*` glob (`dop://billing/prd/STRIPE_*`). Watch polls; see
[Watch and refresh](#watch-and-refresh). Dynamic secrets are not supported (see
[Limitations](#limitations)).

## References

```text
<scheme>://<project>/<config>/<NAME>[#value]
```

- `<scheme>` is the store instance name (or one of its aliases), for example `dop://`.
- `<project>` is the project slug, as the dashboard and `doppler setup` show it.
- `<config>` is a root config (`dev`, `stg`, `prd`) or a branch config (`prd_aws`).
- `<NAME>` is the secret name. With the workplace's Permissive secret naming a name may contain
  `/`, `:`, `.` and `-`; everything after the config is the name, so
  `dop://billing/prd/payments/stripe.key` is the secret `payments/stripe.key`. A name has at most
  200 characters.
- A Doppler secret holds one value, exposed as the field `value`. `#value` is accepted; any other
  field reads as not found, and a write with any other field name is refused.
- Doppler keeps no per-secret version a reference could pin, so every selector (`?version=`, ...) is
  refused rather than ignored.

A listing prefix stops at a config, at a name, or at part of a name followed by `*`:

| Prefix | Lists |
| --- | --- |
| `dop://billing/prd` or `dop://billing/prd/*` | every secret of the config |
| `dop://billing/prd/payments` | `payments` and every name starting with `payments/` |
| `dop://billing/prd/STRIPE_*` | every name starting with `STRIPE_` |

Listing reads names only, never values. It leaves out Doppler's managed secrets `DOPPLER_PROJECT`,
`DOPPLER_CONFIG` and `DOPPLER_ENVIRONMENT`: their values are the project, config and environment
names, and loading them into the redaction set would make scrim redact words like `dev` and `prd`
everywhere. A reference that names one explicitly still reads it.

### Computed values

Doppler resolves secret references (`${USER}`, `${prd.STRIPE_KEY}`, `${billing.prd.STRIPE_KEY}`)
when a secret is read. scrim reads the computed value, the one `doppler run`, the download endpoint
and integrations hand to applications, because that is the value an agent can come across in an
environment, a file or a log. The raw value with the `${...}` text in it is not secret on its own
and is never read separately.

## Setup

Pick the token by what scrim should reach:

- **Service token** (`dp.st.`): one config, read or read/write. Create it under the config's
  **Access** tab. Use a read token for configs scrim only redacts and injects, and a read/write
  token for the config scrim writes captured and generated secrets into. One service token cannot
  reach a second config, so a scrim that serves several configs needs one instance per config or a
  service account.
- **Service account token** (`dp.sa.`, Team and Enterprise plans): the projects and environments the
  service account's roles allow. Give it a project role with read access where scrim only reads, and
  write access only on the environment scrim writes into.
- **Personal token** (`dp.pt.`): works, but acts as you on every project you can reach and cannot read
  secrets with Restricted visibility. Use it for a trial only.

Store the token where scrim reads credentials from: a file readable only by scrim, a systemd
credential, a Kubernetes secret or an environment variable. Agents only ever get references and
metadata from scrim, never a value, whatever the token may do.

## Configuration

Each instance is configured under `stores.<instance>`. The generic keys every store takes (`kind`,
`aliases`, `redact`, `refresh.*`, `labels`) are handled by scrim; the keys below are the adapter's
own. Every key can also be set as an environment variable: `SCRIM_` followed by the full key
upper-cased, with dots and dashes as `_`. Unknown keys fail validation and name the closest known
key.

```yaml
stores:
  dop:
    kind: doppler
    token: file:/run/credentials/scrim/doppler-token
    redact:
      - dop://billing/prd/*
    watch:
      interval: 1m
```

| Key | Environment variable (instance `dop`) | Type | Default | Meaning |
| ----- | ---------------------------------------- | ------ | --------- | --------- |
| `stores.<name>.token` | `SCRIM_STORES_DOP_TOKEN` | secret reference | required | The Doppler token: `file:`, `env:`, a systemd credential or a store reference. A reference that does not resolve, or resolves to an empty value, fails the first request. A literal works but logs a warning. |
| `stores.<name>.address` | `SCRIM_STORES_DOP_ADDRESS` | URL | `https://api.doppler.com` | Base URL of the API. Change it only for a proxy in front of Doppler. |
| `stores.<name>.timeout` | `SCRIM_STORES_DOP_TIMEOUT` | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.tls.ca-file` | `SCRIM_STORES_DOP_TLS_CA_FILE` | path | system roots | PEM bundle to verify the server with, for a proxy with a private CA. |
| `stores.<name>.watch.interval` | `SCRIM_STORES_DOP_WATCH_INTERVAL` | duration | `1m` | How often a watched config is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | `SCRIM_STORES_DOP_WATCH_MAX_BACKOFF` | duration | `5m` | Longest wait between polls while Doppler keeps failing. |

Doppler tokens are static bearer tokens: there is no login and nothing to renew. scrim resolves the
token on the first request, sends it as `Authorization: Bearer`, and adds it to the redaction set. No
token appears in an error.

## Policy labels

Every secret the adapter reads or lists carries labels describing where it lives in Doppler, so
[policy rules](../policy.md) can match on project, config and environment through `secret.labels`.
Labels are metadata: they never hold a secret value.

| Key | Example | Meaning |
| --- | --- | --- |
| `doppler.workplace` | `2faa85f6610102d983522` | Workplace slug of the token, from `GET /v3/me`. |
| `doppler.workplace.name` | `Acme` | Workplace name. |
| `doppler.project` | `billing` | Project slug from the reference. |
| `doppler.config` | `prd_aws` | Config name from the reference. |
| `doppler.environment` | `prd` | Environment slug of the config. |
| `doppler.config.root` | `true` / `false` | The config is the environment's root config rather than a branch. |
| `doppler.config.locked` | `true` / `false` | The config is locked against renaming and deletion. |
| `doppler.config.inheritable` | `true` / `false` | Other configs may inherit from it (when Doppler reports it). |
| `doppler.secret` | `payments/stripe.key` | Secret name, case kept. |
| `doppler.managed` | `true` / `false` | The secret is one Doppler generates (`DOPPLER_PROJECT`, `DOPPLER_CONFIG`, `DOPPLER_ENVIRONMENT`). |
| `doppler.visibility` | `masked` | The secret's visibility: `unmasked`, `masked` or `restricted`. Read only, see below. |
| `doppler.computed-visibility` | `restricted` | The visibility of the computed value: `restricted` when the secret references a restricted one. Read only. |
| `doppler.value-type` | `string` | The value type Doppler validates the value against (`string`, `json`, `url`, ...). Read only. |

The environment and the `doppler.config.*` keys come from `GET /v3/configs/config`, asked once per
config. A token that may read secrets but not describe the config (Doppler decides that by token
type and role) gets the labels the reference itself gives, and the refused lookup is retried after
five minutes rather than at every read. Test those keys with `in`.

Visibility and value type come only with the value: Doppler's API returns them next to the raw and
computed values and nowhere else. Read sets them; listings, metadata lookups and write labels do not,
and scrim never reads a value only to label it. A rule that needs them should therefore be an ask or
deny rule: on a secret scrim has not read, indexing the missing key fails, and a failing ask or deny
rule counts as matching.

Doppler has no user-editable metadata on a secret other than its note, so there are no
`doppler.meta.*` keys and nothing a store user can type lands in a label. The note is free text that
people paste values into; scrim never decodes it.

### Example rules

Production secrets need a human; the rest of project `billing` is allowed:

<!-- policy-example -->
```yaml
default: deny
rules:
  - name: doppler-production
    decision: ask
    reason: production Doppler secrets need a human
    when: >-
      op in ["store.read", "store.write", "inject"] && secret.store == "dop" &&
      secret.labels["doppler.environment"] == "prd"
  - name: doppler-billing
    decision: allow
    when: >-
      op in ["store.read", "store.write"] && secret.store == "dop" &&
      secret.labels["doppler.project"] == "billing"
```

A config whose details the token may not read has no `doppler.environment`, so the first rule fails
on it and asks rather than allows.

More patterns:

```cel
secret.labels["doppler.config.root"] == "false"                 // branch configs only
secret.labels["doppler.secret"].startsWith("payments/")         // a name prefix
secret.labels["doppler.project"] in ["billing", "payments"]     // either project
secret.labels["doppler.computed-visibility"] == "restricted"    // read only: fails, so matches, before a read
```

For `store.write`, the adapter tells scrim which labels a secret at the target reference would get
(`doppler.project`, `doppler.config`, `doppler.secret`, `doppler.managed`, and the workplace,
environment and `doppler.config.*` once an earlier call has fetched them) without contacting
Doppler, so a write rule matches before the secret exists.

### Labels without the value

When a rule needs the labels of a secret that is not in a redaction set (a write to an existing
secret, or `scrim catalog labels`), scrim asks Doppler for the config's secret names
(`GET /v3/configs/config/secrets/names`), which carries no value. The secret exists when its name is
listed, and its labels are the location labels a read reports. A failure (unreachable, refused,
unknown project or config) fails the lookup.

## Watch and refresh

Doppler's public API has no change feed and no per-secret version that comes without the value, so
the adapter polls `GET /v3/configs/config/secrets/download?format=json` every `watch.interval`,
sending the `ETag` of the previous answer in `If-None-Match`. An unchanged config costs one request
answered with `304 Not Modified`, which carries no values. When the config changed, the values that
arrive are fingerprinted with HMAC-SHA256 under a random key that exists only in that watch, wiped
straight away, and compared with the previous fingerprints, so only the secrets whose computed value
changed (a reference target changing included) are reported. scrim then reads those secrets again.

Polls back off exponentially up to `watch.max-backoff` while Doppler keeps failing, and the watch
keeps running through an outage. Each poll counts against Doppler's secret-read rate limit (120 a
minute on the Developer plan); with several watched configs keep `watch.interval` at a minute or
more. Without a watch, scrim refreshes on `refresh.interval`.

## Writes

A write sends one change request to `POST /v3/configs/config/secrets`: a new secret, or a new value
for an existing one. The secret's visibility and value type are left as they are, so a secret a
person marked Restricted stays Restricted. A new secret gets Doppler's default visibility (masked).
The response echoes every secret of the config with its values; scrim wipes it unread.

Doppler has no create-only operation, so a create-only write (`secret_capture` and `secret_gen` into
a new name) first checks the config's names and refuses with a conflict if the name exists. A secret
someone else creates between that check and the write is not overwritten: the change request says
the secret is new, and Doppler refuses it. An existing secret deleted between the check and an update
fails the update the same way.

A value containing `${` is refused before anything is sent. Doppler would treat it as a secret
reference, now or once the referenced secret appears, so the computed value would differ from the
one scrim redacts and injects. Values that are not valid UTF-8 are refused too. Labels passed to a
write are not stored: Doppler has nowhere to keep them.

## Per-agent identity

Each agent can use Doppler with a token of its own, so Doppler's access rules for that token decide
alongside scrim's rules ([Agent identity](../identity.md#store-identity-per-agent)):

- a static token per agent in `identity.store-credentials.<store>/<agent>`: a service token for the
  agent's config, or a service account token whose project roles say what it may use;
- or a service account identity with OIDC authentication, `identity.store-login.<store>:
  doppler-oidc identity:<identity ID> audience:<aud>`. Trust scrim's issuer URL as the identity's
  discovery URL, require the audience and the subject `agent:<name>` (`{agent}`, `{agent_slug}`,
  `{namespace}` and `{service_account}` work in `identity` to pick one identity per agent). scrim
  signs a token for the agent, trades it at `POST /v3/auth/oidc` for a short-lived Doppler token,
  caches that until two thirds of its life and drops it when the agent's session ends.

```yaml
identity:
  store-login:
    dop: "doppler-oidc identity:{agent_slug}-identity-id audience:https://api.doppler.com"
  store-credentials:
    dop/ci-bot: file:/run/secrets/doppler-ci-bot-service-token
```

Doppler has no call that says what a token may do without using it, so before scrim injects or
restores a value it reads the secret with the agent's token and wipes the value unread. A value
Doppler withholds from that token (restricted visibility) refuses the use. Writes cannot be checked
without writing.

## Errors

Doppler answers errors with `{"messages": [...], "success": false}`. scrim maps them:

| Doppler | scrim error |
| --- | --- |
| 401, 403 (bad token, token outside its config, read-only token, plan or role) | permission denied |
| 404 (unknown project, config or secret) | not found |
| 429 (rate limited), 5xx, timeouts, connection errors | store unavailable |
| other 4xx (invalid name, value rejected by its value type) | invalid reference |
| restricted value withheld (`null`) from a personal or CLI token | permission denied |

Doppler's own message is kept, unless it quotes a value from the request, in which case it is
replaced by `(store message withheld)`.

## Limitations

- Dynamic secrets are not requested (`include_dynamic_secrets=false`): issuing and revoking leases
  for them is not implemented.
- Secret notes, reminders, tags on projects, secret history and config logs are not read.
- Doppler's secret naming mode (Classic or Permissive) is the workplace's; a name the mode refuses
  fails the write with Doppler's message.
- Visibility and value type labels need a read (see [Policy labels](#policy-labels)).
- The per-agent check reads the value with the agent's token, and cannot check writes.
- `doppler-oidc` is tested against the fake only: the request and response follow Doppler's API
  reference, and the status Doppler answers for a refused identity token is assumed.

## Testing

There is no Doppler emulator and no test account in CI. The adapter's tests run the shared
conformance suite (`internal/stores/storetest`) against an in-process fake of the API in
`internal/stores/doppler/fake_test.go`, with a service account token and with a read/write service
token. Its responses follow recorded fixtures in `internal/stores/doppler/testdata`: the examples
from Doppler's API reference and the field types the Doppler CLI decodes. `TestRecordedFixtures`
reads those fixtures through the adapter as served, and `TestFakeMatchesFixtures` keeps the fake's
answers in step with them.

What the fake does not prove:

- Error texts, and the status Doppler picks for some refusals (a change request that creates an
  existing secret, a name the naming mode rejects), are assumptions. The adapter only relies on the
  status class.
- References resolve `${NAME}`, `${config.NAME}` and `${project.config.NAME}` recursively; quoting
  of dotted names (`${"a.b"}`) is not modelled.
- That Doppler sends an `ETag` and honours `If-None-Match` on the download endpoint comes from the
  Doppler CLI, which relies on it for its fallback file; the fake's ETag is a hash of the body. A
  server that never answered 304 would still work, with values fetched on every poll.
- Whether a service token may call `GET /v3/configs/config` is not documented. It is optional:
  without it the environment and config labels are missing and everything else works. Health uses
  `GET /v3/me`, documented as information about the calling token.
- Rate limits, pagination and trusted IPs are not modelled.

```sh
go test -race ./internal/stores/doppler/
```
