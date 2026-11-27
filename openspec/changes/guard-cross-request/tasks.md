## 1. Guard

- [x] 1.1 `CrossMemory` (`guard_cross.rs`): pieces per session, joined and remembered under one lock, bounded, with a TTL
- [x] 1.2 Short pieces collected for either rule; joined after a whole check only; `CrossRequest` view
- [x] 1.3 `looks_random` filter, chosen from measured false positives
- [x] 1.4 `Guard::check_in`; unit tests (two and three requests, slack, expiry, other sessions and values, bounds) and integration tests (verdict cache, snapshot change, toggle, quiet conversations)
- [x] 1.5 Pieces keyed by a keyed fingerprint of the value form; one memory per data plane process shared by every snapshot; pieces of values that left the set dropped

## 2. Session

- [x] 2.1 `SessionKey`, `Guard::check_in` on the engine trait, `Admission::Forward.session`, the proxy binds the guard
- [x] 2.2 `Identity::guard_session` in the data plane's LLM gate

## 3. Settings

- [x] 3.1 `cross-request` in `guard_transforms.json` (on), `redaction.guard.disable` text, `scrim status` and `scrim doctor` through the transform list

## 4. Leak suite

- [x] 4.1 `split-requests-2` and `split-requests-3` rows with named pieces; the runner reports a leak when every piece arrived
- [x] 4.2 Pass-through and naive stubs report them leaked
- [ ] 4.3 The gate against `scrim proxy` passes them (CI `leak.yaml`)

## 5. Docs

- [x] 5.1 `docs/limitations.md`, `docs/leak-assurance.md`, `docs/configuration.md`, `docs/performance.md`
