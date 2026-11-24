## MODIFIED Requirements

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
  split across fields or requests, text rendered into image pixels) are marked `limitation`, each
  with its reason in the row note and in the documented limitations

#### Scenario: Gate against the real proxy

- **WHEN** CI runs the matrix through `scrim proxy` with the seeds in a file store
- **THEN** no row expecting `redacted`, `guard` or `withheld` leaks

#### Scenario: Binary parts under the default policy

- **WHEN** the matrix sends a seed in a PNG text or compressed text chunk, a JPEG comment, an SVG image or a PDF content stream
- **THEN** the row expects `withheld`, and the leak checker inflates PNG chunks and PDF streams so a value forwarded inside them counts as a leak

### Requirement: Documented limitations

The documentation SHALL state what scrim does not protect: the agent's local transcripts and memory,
text rendered into the pixels of an image and binary content forwarded under the weakening `pass`
binary policy, parts referenced by URL, transforms not covered by the matrix, values shorter than
the documented minimum, and secrets unknown to any store and missed by fallback detection.

#### Scenario: Limitations are discoverable

- **WHEN** a user reads the security documentation
- **THEN** each listed limitation is described with its mitigation, if any
