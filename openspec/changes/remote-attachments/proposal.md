## Why

A provider request can reference an attachment instead of carrying it: an image or document URL, a
file ID from the provider's Files API, a Cloud Storage or S3 location. The provider fetches the
content, so scrim never sees it and a secret in it reaches the model (docs/limitations.md,
"Attachments referenced by URL are not fetched"). The binary scan only covers what the request
carries inline.

## What Changes

- New setting `redaction.remote-attachments` (`inline`, `refuse`, `pass`; default `inline`), sent
  to the data plane in `RedactionSettings.remote_attachments`. `pass` is weakening.
- `inline`: the data plane fetches each URL itself, through the upstream proxy in force, and
  replaces the reference with the provider's own inline form (a base64 `data:` URL, an Anthropic
  base64 or text source, a Gemini `inlineData` part). The new body is planned again, so the content
  goes through `redaction.binary` like any inline attachment: what was scanned is exactly what the
  model sees.
- Fetch safety: only public addresses unless `redaction.remote-attachments-allowed-networks`
  (weakening) names the network; the host is resolved once, every address checked, and the
  connection made to those addresses; redirects followed by hand (at most 5), each checked; no
  agent headers; a URL carrying a known secret value is not fetched. Bounds reuse the scan bounds:
  64 MiB fetched per request, 18 s for all fetches of a request.
- `refuse`: a request with a URL is refused.
- File IDs: scrim cannot read a file the provider holds. Under `inline` and `refuse` a file ID
  passes only when scrim scanned its upload on the same route (Anthropic and OpenAI
  `POST .../files`, Gemini single-request uploads); the IDs are kept per route in memory, bounded.
  Storage locations (`gs://`, `s3Location`) and YouTube URIs are refused. Under `pass` everything
  is forwarded and audited as unscanned (`remote:url`, `remote:file-id`, `remote:storage`).
- WebSocket messages cannot fetch: a URL or unknown file ID in one refuses it under `inline` and
  `refuse`.
- New refusal codes: `remote_attachment` (422) and `attachment_unavailable` (502).
- Leak suite: the fake provider holds files that requests reference and records a request that
  names one as having read it; new matrix rows `remote-image-url`, `remote-document-url`,
  `remote-text-url` and `remote-file-id`.

## Impact

- Specs: llm-proxy (images and binary content, remote attachments, fetch safety, scanned uploads),
  redaction (referenced content), leak-assurance (remote attachment rows). Builds on
  `binary-parts-policy`, which must be archived first: this change replaces its "Image by URL"
  scenario.
- Code: `proto/scrim/dataplane/v1` (`RemoteAttachments`, two `RedactionSettings` fields),
  `internal/daemon` (settings, snapshot), `dataplane/crates/scrim-llm` (`remote` module, codecs,
  `outgoing`, `proxy`, refusal codes), `dataplane/crates/scrim-dns` (`FixedResolver`),
  `dataplane/crates/scrim-dataplane` (snapshot), `internal/leak` and
  `internal/testing/fakeprovider` (rows, files), `test/leak/start-proxy.sh`.
- Behaviour change for users: a request with an image or document URL now makes scrim fetch it;
  one with a provider file ID uploaded outside scrim, or a storage location, is refused by
  default. `redaction.remote-attachments: pass` restores the old behaviour and is reported as
  weakened.
