## Purpose

Defines how scrim proves, to its developers and its users, that known secret values do not reach
model providers: capture, an audit harness with real agents, an adversarial bypass matrix, fuzzing
and a strict leak checker, all used as release gates.

## ADDED Requirements

### Requirement: Capture mode

scrim SHALL offer a capture mode that writes every outbound provider request exactly as sent, and the
response as received, to a configured directory with a configurable retention. Capture SHALL only
ever record post-redaction bytes and SHALL refuse to start if the directory is world-readable.

#### Scenario: Verify what left

- **WHEN** capture is enabled and an agent sends a request containing a known secret
- **THEN** the captured request contains the placeholder and not the value

#### Scenario: Retention

- **WHEN** captured files are older than the configured retention
- **THEN** they are deleted

### Requirement: Audit harness

`scrim audit` SHALL drive real agent CLIs (at least Claude Code and Codex) through scrim against a
local fake model, seeded with generated secrets, and SHALL report per request what the provider would
have received, every leak found, and the prompt-cache hit rate.

#### Scenario: Clean audit

- **WHEN** `scrim audit --driver claude` runs a scripted session over files containing seeded secrets
- **THEN** the report shows zero leaks
- **AND** shows the cache hit rate across turns

#### Scenario: Leak fails the audit

- **WHEN** any seeded value reaches the fake model in any encoding
- **THEN** `scrim audit` exits non-zero and names the request, field and encoding

### Requirement: Strict leak checker

The leak checker used by the audit harness and test suites SHALL decode every supported transform
(escapes, base64 variants, hex, URL encoding, case changes, reversal, spacing, truncation) and SHALL
be independent of the redactor, so it detects anything the redactor misses.

#### Scenario: Checker catches an encoded leak

- **WHEN** a test inserts a base64url form of a seeded secret into an outbound fixture
- **THEN** the leak checker reports it

### Requirement: Bypass matrix as a gate

A bypass matrix SHALL exercise one-command transforms an agent can apply to secret-bearing output (byte
dumps, base64, escape printing, reversal, rot13, case changes, one character per line, spaced letters,
truncation, SQL hex, upper and substring functions). Each SHALL be contained (blocked, withheld or
redacted), and any uncontained transform SHALL fail the release.

#### Scenario: Reversal contained

- **WHEN** the matrix runs a command that prints a secret-bearing file reversed
- **THEN** the reversed value does not reach the fake model

### Requirement: Fuzzing gates

Stream parsing, placeholder resolution and value escaping SHALL be fuzzed continuously. A fuzzing
finding of a leak, a corrupted signed block, or a restored value executing as code SHALL fail the
release.

#### Scenario: Escaping fuzz

- **WHEN** the fuzzer resolves hostile secret values into generated shell and interpreter commands and executes them in a sandbox
- **THEN** no value executes as code

### Requirement: Recorded provider fixtures

The test suite SHALL include recorded streaming and non-streaming exchanges for every supported
provider API, with secrets replaced by generated values, and SHALL check redaction and resolution
against them byte for byte.

#### Scenario: Fixture regression

- **WHEN** a change alters resolved output for a recorded fixture
- **THEN** the suite fails and shows the byte difference

### Requirement: Results published per release

Each release SHALL publish its audit, bypass matrix and fuzzing results, including any known
uncontained transform and its tracking issue.

#### Scenario: Release notes include assurance

- **WHEN** a user opens a release
- **THEN** its assurance report lists audit leaks, matrix status and fuzzing hours

### Requirement: Documented limitations

The documentation SHALL state what scrim does not protect: the agent's local transcripts and memory,
images and other binary content passed through unscanned, transforms not covered by the matrix,
values shorter than the documented minimum, and secrets unknown to any store and missed by fallback
detection.

#### Scenario: Limitations are discoverable

- **WHEN** a user reads the security documentation
- **THEN** each listed limitation is described with its mitigation, if any
