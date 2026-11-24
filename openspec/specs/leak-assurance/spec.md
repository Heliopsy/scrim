# leak-assurance Specification

## Purpose
Defines how scrim proves, to its developers and its users, that known secret values do not reach
model providers: capture, an audit harness with real agents, an adversarial bypass matrix, fuzzing
and a strict leak checker, all used as release gates.

## Requirements

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

`scrim audit run` SHALL drive agents through scrim against a local fake model, seeded with generated
secrets, and SHALL report per request what the provider would have received, every leak found, and
the prompt-cache hit rate. It SHALL drive real agent CLIs (at least Claude Code and Codex) and a
built-in synthetic agent for every supported provider API. The report SHALL identify seeds by name,
kind, length and a short hash, never by value.

#### Scenario: Clean audit

- **WHEN** `scrim audit run --driver claude` runs a scripted session over files containing seeded secrets
- **THEN** the report shows zero leaks
- **AND** shows the cache hit rate across turns

#### Scenario: Leak fails the audit

- **WHEN** any seeded value reaches the fake model in any encoding
- **THEN** `scrim audit run` exits non-zero and names the request, field and encoding

#### Scenario: Restored value sent back

- **WHEN** the fake model calls a tool with a placeholder, the proxy restores it, and the agent sends that call back in its history
- **THEN** the next request carries the placeholder again, byte-identical to the first

#### Scenario: Cache measured

- **WHEN** a scenario runs twice through the proxy
- **THEN** the report shows, per turn, whether the previous turn's whole prompt was a cached prefix
- **AND** whether the replay produced byte-identical requests, failing the audit if either does not hold

#### Scenario: Report holds no value

- **WHEN** a run finds leaks
- **THEN** neither the JSON report nor the printed summary contains any seeded value

### Requirement: Testing a user's own setup

`scrim audit run` SHALL run against any proxy URL. It SHALL write its generated seeds to a file with
mode 0600 for loading into the user's store, or read seeds the user already loaded, SHALL listen for
the proxy's provider traffic on a configurable address, and SHALL optionally start and stop the
proxy itself with the fake provider's address, the seed file and the listen address in its
environment.

#### Scenario: Own deployment

- **WHEN** a user writes the seeds with `--seeds-out`, loads them into their store and points their proxy's routes at the fake provider
- **THEN** `scrim audit run --proxy <url>` reports leaks and outcomes for that deployment

#### Scenario: Proxy does not start

- **WHEN** the command given with `--proxy-cmd` does not listen within the start timeout
- **THEN** the run stops with an error and the proxy process is terminated

### Requirement: Fake provider

The suite SHALL include a fake provider, usable in process and as a standalone binary, that speaks
the Anthropic Messages, OpenAI Chat Completions and OpenAI Responses APIs, streaming and not, with
tool-call round trips, that records every byte of every request, splits streamed text and tool
arguments into small deltas, and reports prompt-cache usage by byte-identical prefix blocks.

#### Scenario: Placeholder split across events

- **WHEN** the fake provider streams a reply containing a placeholder
- **THEN** the placeholder arrives split across several delta events

#### Scenario: Changed prefix

- **WHEN** a request changes one byte in an early message of an otherwise repeated conversation
- **THEN** the fake provider reports only the blocks before that message as cached

### Requirement: Strict leak checker

The leak checker used by the audit harness and test suites SHALL decode every supported transform
(escapes, base64 variants, hex, URL encoding, case changes, reversal, spacing, truncation) and SHALL
be independent of the redactor, so it detects anything the redactor misses.

#### Scenario: Checker catches an encoded leak

- **WHEN** a test inserts a base64url form of a seeded secret into an outbound fixture
- **THEN** the leak checker reports it

### Requirement: Fragments and split values

The leak checker SHALL decode recursively, SHALL report fragments of a value at or above a
configurable threshold (by default half the value, at least 8 bytes outside format-fixed parts such
as prefixes, at most 24 bytes for long values), and SHALL join strings across fields, messages and
consecutive requests to find split values.

#### Scenario: One line of a private key

- **WHEN** a single 64-character line of a seeded private key reaches the fake model
- **THEN** the checker reports a partial leak of that seed

#### Scenario: Checker sees every matrix transform

- **WHEN** every bypass matrix row is sent through a proxy that forwards requests unchanged
- **THEN** the checker reports a leak for every row and seed, except fragments below the threshold

#### Scenario: No false positives

- **WHEN** the checker scans traffic holding placeholders, random base64 and hex, and format prefixes but no seeded value
- **THEN** it reports nothing

### Requirement: Bypass matrix as a gate

A bypass matrix SHALL exercise one-command transforms an agent can apply to secret-bearing output (byte
dumps, base64, escape printing, reversal, rot13, case changes, one character per line, spaced letters,
truncation, SQL hex, upper and substring functions). Each SHALL be contained (blocked, withheld or
redacted), and any uncontained transform SHALL fail the release.

#### Scenario: Reversal contained

- **WHEN** the matrix runs a command that prints a secret-bearing file reversed
- **THEN** the reversed value does not reach the fake model

#### Scenario: Expectations follow the redaction spec

- **WHEN** a matrix row's transform is one the guard decodes under the redaction spec
- **THEN** the row expects `guard`, and only the transforms the redaction spec lists as
  limitations (look-alike Unicode, spelling alphabets, compression, the base85 family, values
  split across fields or requests, binary parts) are marked `limitation`, each with its reason in
  the row note and in the documented limitations

#### Scenario: Gate against the real proxy

- **WHEN** CI runs the matrix through `scrim proxy` with the seeds in a file store
- **THEN** no row expecting `redacted`, `guard` or `withheld` leaks

### Requirement: End-to-end matrix

The bypass matrix SHALL also run end to end, with the real data plane, across interception modes,
stores and provider routes, the seeds in the store under test. Its cells SHALL cover every pair of
values from two axes, and any gated leak, unexpected outcome, unauthenticated cloud request or seed
in scrim's log SHALL fail CI.

#### Scenario: Cloud route through the transparent listener

- **WHEN** an agent with no configuration sends the matrix to a Bedrock route's host and the
  redirect lands it on the transparent listener, with the AWS keys in OpenBao
- **THEN** every request the fake Bedrock receives carries a valid signature made by scrim and no
  row expecting `redacted`, `guard` or `withheld` leaks

#### Scenario: MCP only

- **WHEN** an agent lists, generates and captures secrets through `scrim mcp` and sends the tool
  results to the provider itself
- **THEN** neither the tool results nor what the provider received holds a seeded, generated or
  captured value

#### Scenario: Every pair covered

- **WHEN** a mode, store or provider is added to the matrix
- **THEN** the covering check fails until every pair it forms with the other axes runs in a cell

### Requirement: Matrix rows state their outcome

Every matrix row SHALL name its transform, its placement in the request and its provider API, and
SHALL state its expected outcome: `redacted` (forwarded with a placeholder), `guard` (redacted,
repaired or withheld), `withheld` (refused, nothing forwarded) or `limitation` (documented, run and
reported but not gating). A row whose observed outcome its expectation does not accept SHALL fail
the run.

#### Scenario: Verbatim value refused instead of redacted

- **WHEN** a row expecting `redacted` is refused by the proxy
- **THEN** the run fails with an unexpected outcome, not a leak

#### Scenario: Limitation row leaks

- **WHEN** a row marked `limitation` reaches the fake model
- **THEN** the report lists it as a known-limitation leak and the gate does not fail on it

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
