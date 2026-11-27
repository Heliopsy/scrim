## ADDED Requirements

### Requirement: Cross-request split rows

The bypass matrix SHALL run gated rows that split a value into short pieces over two and over three
requests of one session for every API with a tool turn, and the runner SHALL report a leak when
every piece of such a row reached the provider.

#### Scenario: Pass-through proxy

- **WHEN** the `split-requests-3` row runs against a proxy that forwards everything
- **THEN** the row is reported as leaked

#### Scenario: scrim

- **WHEN** the `split-requests-2` row runs against `scrim proxy` with default settings
- **THEN** the second request is forwarded with its piece replaced and the row passes
