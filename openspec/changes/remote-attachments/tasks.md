# Tasks

## 1. Setting and snapshot

- [x] 1.1 `redaction.remote-attachments` (`inline`, `refuse`, `pass`; default `inline`; `pass`
  weakening) and `redaction.remote-attachments-allowed-networks` (weakening when set) sent in
  `RedactionSettings`; verify: `TestRemoteAttachmentsSetting`, `TestRemoteAllowedNetworksSetting`,
  `remote_policy_from_snapshot`
- [x] 1.2 Both listed by `scrim status` and `scrim doctor` when weakening; verify:
  `TestRemoteAttachmentsPassIsWeakened`

## 2. Data plane

- [x] 2.1 Codecs record references (Anthropic, OpenAI Chat, Responses, Realtime, Gemini, Converse);
  verify: `tests/remote.rs`
- [x] 2.2 Policy check before redaction, `remote_attachment` and `attachment_unavailable` refusals;
  verify: `remote::tests`
- [x] 2.3 Fetcher: upstream proxy, address checks, fixed resolution, redirects, bounds, media type;
  verify: `remote::addr::tests`, `remote::fetch::tests`, `tests/remote.rs`
- [x] 2.4 Inline forms per provider, body planned again; verify: `tests/remote.rs`
- [x] 2.5 Upload scanning and per-route file IDs; verify: `remote::files::tests`, `tests/remote.rs`
- [x] 2.6 Requests without references: latency budgets hold; verify: `latency_gate`

## 3. Leak suite and docs

- [x] 3.1 Fake provider files, matrix rows `remote-*`, leak gate config allows the fake's loopback
  address; verify: `TestPassThroughLeaksEverything`, `TestDocsMatchCatalogue`, the gate against
  `scrim proxy`
- [x] 3.2 docs/limitations.md, docs/configuration.md (`just config-docs`), docs/providers.md,
  docs/leak-assurance.md, ROADMAP.md
