## 1. Guard transforms

- [x] 1.1 `TransformConfig` threaded from `Config` through the guard, its oracle and the transform hooks
- [x] 1.2 Confusables view and skeleton forms (guard index and fragment index)
- [x] 1.3 Spelled-out view from an anchor automaton
- [x] 1.4 Split-fragment assembly in the fragment index
- [x] 1.5 base85 indexed forms
- [x] 1.6 Compressed documents in base64 runs, bounded
- [x] 1.7 Tests per transform, on and off; quiet on ordinary text; cost per transform measured

## 2. Settings

- [x] 2.1 `redaction.guard.disable` (weakening) and `redaction.guard.enable`, validated against `internal/daemon/guard_transforms.json`
- [x] 2.2 `RedactionSettings.guard_disabled` and `guard_enabled`; the data plane builds `TransformConfig`
- [x] 2.3 `guard transforms` in `scrim status`, `redaction: guard transforms` in `scrim doctor`

## 3. Leak suite

- [x] 3.1 Gated rows for confusables and spelled-out forms; limitation rows name the settings for base85 and compressed
- [x] 3.2 The gate against `scrim proxy` passes every row

## 4. Docs

- [x] 4.1 `docs/limitations.md`, `docs/leak-assurance.md`, `docs/configuration.md`
