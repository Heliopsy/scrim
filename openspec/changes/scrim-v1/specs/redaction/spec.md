## Purpose

Redaction finds every known secret value in traffic bound for a model provider and replaces it with
a deterministic placeholder, checks the result independently, and resolves placeholders in responses
only where the tool policy allows.

## ADDED Requirements

### Requirement: Known values are matched

Redaction SHALL match every secret value currently known from the configured stores, wherever it
appears in a request, and SHALL refuse requests while the set of known values has not yet loaded.

#### Scenario: Secret read from a file

- **WHEN** a tool result in the request contains a value stored in a configured store
- **THEN** the forwarded request contains the value's placeholder instead of the value

#### Scenario: Known values not loaded yet

- **WHEN** a request arrives before the known values have loaded from the stores
- **THEN** the request is refused with an error stating redaction is not ready

### Requirement: Encoded variants are matched

Redaction SHALL also match each known value in its JSON-escaped, base64 (standard and URL-safe, at
every byte offset), hexadecimal and URL-encoded forms, and SHALL replace each occurrence with the
placeholder.

#### Scenario: Base64-encoded secret in a log

- **WHEN** a request contains the base64 encoding of a known value embedded at any offset
- **THEN** the forwarded request contains no substring that decodes back to the value

### Requirement: Short values

Values shorter than the configured minimum length (`redaction.min_length`, default 8 bytes) SHALL
be matched only verbatim and in their complete encodings, never as fragments such as the inner
base64 substring of a longer stream, and the status command SHALL list how many known values fall
below the minimum.

#### Scenario: Eight-character password

- **WHEN** a known value is shorter than the minimum length
- **THEN** it is replaced where it appears whole and the status command reports it as a short value

#### Scenario: Short value inside base64

- **WHEN** a short value is base64-encoded together with other bytes
- **THEN** the encoded stream is not altered, while the base64 encoding of the value alone is replaced

### Requirement: Value floor

Values shorter than the floor (`redaction.short_floor`, default and minimum 4 bytes) SHALL be
rejected when the value set is built, listed by reference in the status output and documented as
not protected.

#### Scenario: Value below the floor

- **WHEN** a store holds a three-byte value
- **THEN** the value set builds without it and the status command names its reference as unprotected

### Requirement: Deterministic placeholders

Each value SHALL map to a placeholder derived from a keyed hash of the value, so the same value
always yields the same placeholder across requests, sessions and replicas sharing the key. The
placeholder SHALL name the secret reference's alias, never the value.

#### Scenario: Same secret in two requests

- **WHEN** the same value appears in two separate requests
- **THEN** both forwarded requests contain the identical placeholder

### Requirement: Placeholder format

Placeholders SHALL use a fixed, documented format with distinctive delimiters that compression and
tokenisation do not split or alter, and SHALL be valid inside JSON strings, shell words and source
code without escaping. The format SHALL be `⟦scrim:<slug>:<vv><tag>⟧` with `⟦` U+27E6 and `⟧`
U+27E7, at most 79 bytes.

#### Scenario: Placeholder survives a compression proxy

- **WHEN** a placeholder passes through a chained context-compression proxy and back
- **THEN** the placeholder returned by the model is byte-identical and resolves

#### Scenario: Placeholder in a shell command

- **WHEN** a placeholder appears unquoted in a shell word, a JSON string or a YAML plain scalar
- **THEN** it needs no escaping and contains no whitespace or shell metacharacter

### Requirement: Placeholder fields

The slug SHALL be the reference alias in `[a-z0-9-]`, 1 to 48 bytes, not starting or ending with
`-`. `<vv>` SHALL be the key version as two lowercase hexadecimal digits, `01` to `ff`. `<tag>`
SHALL be the first 8 bytes of `HMAC-SHA256(key, "scrim-placeholder-v1" || 0x00 || value)` as 16
lowercase hexadecimal digits.

#### Scenario: Pinned derivation

- **WHEN** the value `correct horse battery staple` with slug `db-password` is placeholdered under key version 1 with key `0123456789abcdef0123456789abcdef`
- **THEN** the placeholder is `⟦scrim:db-password:0120a7d732ee4c8da2⟧` in every process and on every replica

### Requirement: Placeholder key rotation

The placeholder key SHALL be versioned. After rotation, new placeholders SHALL use the new key and
placeholders made with retained older keys SHALL still resolve until those keys are retired.

#### Scenario: Conversation spanning a rotation

- **WHEN** the key is rotated during an open conversation
- **THEN** placeholders from before the rotation still resolve in later responses

### Requirement: Fallback detectors

Redaction SHALL run configurable fallback detectors (pattern rules and entropy thresholds) for
secrets not in any store, replacing matches with placeholders. Each detector SHALL be individually
enabled, disabled or tuned in configuration.

#### Scenario: Unknown token matching a pattern

- **WHEN** a request contains a token matching an enabled pattern rule that no store holds
- **THEN** the token is replaced with a placeholder and the audit log records the detector name

#### Scenario: Detector defaults

- **WHEN** no detector settings are configured
- **THEN** every built-in pattern rule is enabled, the entropy detector is disabled, and detector placeholders use the slug `det-<rule>` and never resolve to a value

### Requirement: Independent guard

After redaction, an independent guard SHALL scan the exact outgoing bytes for every known value and
its variants, repair any it finds, and refuse the request when it cannot repair. The guard SHALL
not share matching logic with the redactor.

#### Scenario: Redactor misses a value

- **WHEN** a known value remains in the bytes after redaction
- **THEN** the guard replaces it or refuses the request
- **AND** the audit log records a guard intervention

#### Scenario: Guard decodes what the redactor does not

- **WHEN** a known value of at least the minimum length reaches the guard upper-cased, JSON-escaped twice, percent-encoded, base64-encoded at any alignment (wrapped or not) or hex-encoded in any case
- **THEN** the guard finds it in the decoded view, replaces the covering bytes with the value's placeholder, and checks the repaired bytes again

#### Scenario: Repair cannot complete

- **WHEN** a known value is still present after repair, or more values reach the guard than `redaction.guard.max_repairs` allows
- **THEN** the request is refused and nothing is forwarded

### Requirement: Split placeholders in streams

Placeholder resolution SHALL handle placeholders split across stream chunks and events of the same
content block, and SHALL emit an unresolvable fragment unchanged rather than a partial value.

#### Scenario: Placeholder across two chunks

- **WHEN** a placeholder arrives split across two streamed chunks
- **THEN** the agent receives the resolved form exactly once, in order

### Requirement: Signed content is byte-identical

Content the provider signs or verifies on return, such as thinking blocks and their signatures,
SHALL reach the provider again with exactly the bytes the provider produced.

#### Scenario: Thinking block sent back

- **WHEN** an agent sends a prior thinking block and its signature back in a later request
- **THEN** the provider receives the block byte-identical to what it originally emitted

### Requirement: Prompt-cache stability

Redaction of an unchanged conversation prefix SHALL produce byte-identical output on every request,
so provider prompt caching keeps working.

#### Scenario: Repeated prefix

- **WHEN** two consecutive requests share the same conversation prefix
- **THEN** the redacted prefixes are byte-identical

#### Scenario: Placeholder from an earlier turn

- **WHEN** a request carries a placeholder that resolves with the current keyring, and a known value happens to occur inside its text
- **THEN** the placeholder is forwarded byte-identical rather than redacted again

### Requirement: Resolution follows tool policy

Placeholders in responses SHALL be resolved to real values only in tool calls the tool policy
allows. Read, search and shell tools MAY receive values classed as display data; edit and write
tools only values already in the target file; unknown and network-capable tools none.

#### Scenario: Unknown tool

- **WHEN** a model calls a tool the policy does not name, with a placeholder in its arguments
- **THEN** the tool receives the placeholder unresolved

#### Scenario: Write introducing a new value

- **WHEN** a write tool call would put a resolved value into a file that does not already contain it
- **THEN** the value stays a placeholder in that call

### Requirement: Credentials are never restored into commands

Values classed as credentials SHALL never be resolved into tool arguments, commands or file
contents. They SHALL reach their destination only through credential injection.

#### Scenario: Curl command with a token placeholder

- **WHEN** the model writes a shell command containing a credential placeholder
- **THEN** the shell tool receives the placeholder, not the credential

### Requirement: Context-aware escaping

A resolved value SHALL be escaped for every language layer it lands in, including shell words,
heredocs, command substitution, interpreter `-c` strings, SQL literals, JSON and YAML. Where the
resolved output would itself be executed as code, the value SHALL stay a placeholder.

#### Scenario: Value containing shell metacharacters

- **WHEN** a value containing `$(` and quotes is resolved into a shell command
- **THEN** the command treats the value as data and executes nothing from it

#### Scenario: Output piped into a shell

- **WHEN** a resolved value would flow into a pipeline that executes its input
- **THEN** the value stays a placeholder

### Requirement: Tool aliases

The tool policy SHALL accept aliases that map another agent's tool names onto the built-in tool
roles, and tools without an alias or role SHALL be treated as unknown.

#### Scenario: Agent with differently named shell tool

- **WHEN** an alias maps an agent's `run_shell` tool to the shell role
- **THEN** placeholders in `run_shell` calls follow the shell rules

### Requirement: Display modes

Users SHALL be able to switch, without restart, between showing resolved values and showing
placeholders in responses the agent displays, for example while screen sharing.

#### Scenario: Screen sharing

- **WHEN** the display mode is set to placeholders
- **THEN** text shown to the user keeps placeholders while tool policy resolution continues

### Requirement: Share and reveal

The CLI SHALL offer `share`, which replaces known values in a text or file with placeholders, and
`reveal`, which resolves placeholders in a text or file locally. `reveal` SHALL refuse credential
values unless explicitly allowed by policy.

#### Scenario: Preparing a bug report

- **WHEN** a user runs `share` on a log file containing known values
- **THEN** the output contains placeholders in place of every known value
