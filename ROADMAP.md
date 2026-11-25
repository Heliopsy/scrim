# Roadmap

Work the maintainers have decided to do but have not scheduled. What scrim does not protect against
today is in [docs/limitations.md](docs/limitations.md); an item leaves this page when it ships and its
limitation is removed there.

## Redaction

- **Text in images (OCR).** Read text rendered into image pixels and PDF pages drawn without a
  ToUnicode map, so a screenshot of a terminal showing a secret is caught like the same text would
  be. Needs an OCR engine that runs in the data plane within the scan bounds and the latency
  budgets, behind a setting. Audio and video stay out of scope.
- **Attachments referenced by URL.** Today an `image_url` with an `https:` URL, an uploaded file ID
  or a Gemini `fileData` URI passes as text, and the provider fetches content scrim never sees. The
  only reliable option is for scrim to fetch the content itself, scan it, and send the provider the
  scanned bytes inline instead of the reference, so what was scanned is what the model sees. A
  setting would choose between that, refusing references, and passing them as today. File IDs are
  covered only when the upload went through scrim.

## Platforms

- **Windows parity.** Windows runs a subset of scrim ([install.md](docs/install.md#windows)). Open
  items: transparent and eBPF interception equivalents, brokered commands, the database proxies,
  plugins, the ssh-agent and the session filesystem view in `scrim run`, telling accounts apart on
  scrim's sockets, locking the data plane's memory and suppressing crash dumps, the certificate
  store, Authenticode-signed binaries and a race detector run in CI.
- **Notarised macOS binaries.** The release workflow signs and notarises the darwin binaries once
  the maintainers add the Apple Developer ID certificate and App Store Connect API key as repository
  secrets ([install.md](docs/install.md#for-maintainers-macos-signing-and-notarisation)).

## Testing

- **Live store checks.** Google Secret Manager, Azure Key Vault, Infisical, 1Password, Doppler and
  Bitwarden Secrets Manager are tested against fakes, and Google and Azure token exchange against
  in-process fakes. Run the store conformance suite and the per-agent identity tests against the
  real services with maintainer credentials.
