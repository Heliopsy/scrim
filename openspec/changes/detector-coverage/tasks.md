## 1. Detectors

- [x] 1.1 Pattern rules for formats current in November 2026, with generated cases in `tests/detectors.rs`
- [x] 1.2 Anchor automata grouped by fingerprint; `detect` bench group per detector setting
- [x] 1.3 Encoded forms: base64, hex and percent-encoded runs decoded and scanned, matches mapped to the encoding characters
- [x] 1.4 Entropy key-name context, exclusions, false-positive rates on the repository, generated bodies and the synthetic corpus

## 2. Settings

- [x] 2.1 `redaction.detectors.encoded` and `redaction.detectors.entropy.*` in the control plane, validated
- [x] 2.2 `RedactionSettings.detectors_encoded` and `EntropySettings`; the data plane builds `DetectorConfig` from them
- [x] 2.3 `fallback detectors` protection in `scrim status`, `redaction: detectors` check in `scrim doctor`

## 3. Leak suite

- [x] 3.1 `unknown-secret` rows for new formats; limitation notes name the opt-in settings

## 4. Docs

- [x] 4.1 `docs/limitations.md`, `docs/leak-assurance.md`, `docs/configuration.md` (settings reference and measurements)
