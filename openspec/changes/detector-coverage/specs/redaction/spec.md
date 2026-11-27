## ADDED Requirements

### Requirement: Encoded forms of known formats

When `redaction.detectors.encoded` is true, the pattern rules SHALL also run over the decoded form
of base64 runs (either alphabet), hex runs and percent-encoded text, within bounded run lengths, and
SHALL replace the characters that encode a match with the rule's placeholder, leaving the text
around them unchanged. It SHALL be off by default.

#### Scenario: Token in a Kubernetes secret

- **WHEN** encoded forms are on and a tool result holds `token: ` followed by the base64 of a GitHub token that no store holds
- **THEN** the base64 characters are replaced by a `det-github-token` placeholder and the other keys of the secret are forwarded unchanged

#### Scenario: Encoded forms off

- **WHEN** no detector settings are configured
- **THEN** the base64 of a GitHub token is forwarded unchanged and the bypass matrix row `base64-encoded-token` is a limitation

### Requirement: Entropy detector context

The entropy detector SHALL be switched by `redaction.detectors.entropy.enabled` (off by default)
and tuned by `context`, `threshold`, `min-length` and `min-classes`. With the default `key-name`
context it SHALL only consider values assigned to a key name that says secret, and SHALL skip
pagination, sync and anti-forgery token names, paths, calls and references; `any` SHALL consider
every token.

#### Scenario: Random password in a .env file

- **WHEN** entropy is enabled and a tool result holds `SESSION_SECRET=` followed by a random 20-character value
- **THEN** the value is replaced by a `det-high-entropy` placeholder and the key name is forwarded

#### Scenario: Pagination token

- **WHEN** entropy is enabled with the key-name context and a tool result holds `"nextPageToken": "<random 24 characters>"`
- **THEN** the value is forwarded unchanged

### Requirement: Detector status

`scrim status` SHALL list a `fallback detectors` protection naming how many pattern rules are in
force and whether encoded forms and entropy are on, inactive when `redaction.detectors.enabled`
is false, and `scrim doctor` SHALL report the same as a check.

#### Scenario: Detectors off

- **WHEN** `redaction.detectors.enabled` is false
- **THEN** `scrim status` shows the `fallback detectors` protection inactive and `scrim doctor` warns
