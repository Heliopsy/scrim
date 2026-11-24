## 1. Detectors

- [x] 1.1 Known-format rules in `scrim-redact` (`detect.rs`): anchor automata with per-anchor dispatch, key-name and URL rules, value-only groups, AWS secret next to its key id
- [x] 1.2 Rule tests: every rule in context, disabled one by one and as a group, near misses, repository corpus
- [x] 1.3 `detect` bench group; deltas against the previous rules

## 2. Settings

- [x] 2.1 `redaction.detectors.enabled`, `.disable`, `.enable` in the control plane, validated against `internal/daemon/detectors.json`
- [x] 2.2 `RedactionSettings` fields `detectors_off`, `detectors_disabled`, `detectors_enabled`; data plane builds `DetectorConfig` from them
- [x] 2.3 Rust and Go check the shared rule list

## 3. Leak suite

- [x] 3.1 `unknown-secret` matrix rows, generated values never in the seed file
- [x] 3.2 Self-tests: pass-through and naive leak them; the gate against `scrim proxy` redacts them

## 4. Docs

- [x] 4.1 `docs/limitations.md`, `docs/leak-assurance.md` (catalogue, row count), configuration reference
