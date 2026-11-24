## Why

Redaction matches the values scrim's stores hold. A secret in no store (an agent reads a `.env` or
a config file with a cloud key) reaches the provider unless a fallback detector recognises it, and
the built-in detectors cover a dozen formats. Their on/off settings exist in the redaction core but
no configuration key reaches them.

## What Changes

- The fallback pattern rules grow from 12 to 37 known formats (38 with the generic rule) with distinctive prefixes or key
  names: AWS secret access keys (after a key name, or next to an access key id), more GitLab token
  kinds, Slack app tokens and webhook URLs, Stripe webhook secrets, Google OAuth client secrets,
  PyPI, Docker Hub, Hugging Face, Twilio, SendGrid, Azure storage and shared access keys, Azure AD
  client secrets, DigitalOcean, Shopify, Atlassian, the password of database and broker URLs,
  HashiCorp Vault, Doppler, 1Password service accounts, Grafana, Sentry, Linear, Postman, age and
  Databricks. A generic `password = ...` rule exists but is off by default.
- New settings `redaction.detectors.enabled`, `redaction.detectors.disable` and
  `redaction.detectors.enable` switch the pattern rules as a group and one by one; they travel to
  the data plane in `RedactionSettings` (additive fields, protocol unchanged).
- Rules found by a key name or inside a URL replace only the value, so the key name and the URL
  stay readable.
- The bypass matrix gains `unknown-secret` rows: a value in one of these formats that is in no
  store must be redacted (gated); formats no rule covers are `limitation` rows.

## Capabilities

### Modified Capabilities

- `redaction`: fallback detectors (known formats, value-only replacement, settings).
- `leak-assurance`: unknown-secret matrix rows.

## Impact

- `dataplane/crates/scrim-redact/src/detect.rs`, `scrim-dataplane/src/snapshot.rs`,
  `proto/scrim/dataplane/v1/dataplane.proto` (three additive fields), `internal/daemon` (settings,
  snapshot), `internal/leak/matrix` (rows), docs.
- Matching stays one prefix automaton plus anchored regular expressions (design D13); the
  `detect` bench group measures the rules alone.
