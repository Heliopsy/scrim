# Limitations

What scrim 1.0 does not protect against, what it protects only partly, and what its tests do not
cover. Each entry says what happens and what you can do about it. The redaction limits that the
bypass matrix can express also have matrix rows; [leak-assurance.md](leak-assurance.md#known-limitations)
lists them, and every release's results list the ones that leaked in that run
([Published results](leak-assurance.md#published-results)).

Report a gap that is not here as described in [SECURITY.md](../SECURITY.md).

## What scrim trusts

- **The machine and the account that run scrim.** Root, or anyone who can read scrim's memory or
  its state directory, can read every value in the redaction set, the placeholder key and the CA
  key. scrim locks and wipes its own copies, but that does not stop a debugger. Give scrim a
  dedicated user (`scrim install --system`) and a dedicated store identity that only holds agent
  secrets.
- **The agent's own disk.** Transcripts, memory and history files hold whatever the agent read, in
  clear: a `cat .env` is in the local transcript even though the provider only saw placeholders.
  scrim protects the wire to the provider, not the agent's files. Keep agent state on an encrypted
  disk.
- **Every data plane replica and sidecar holds the whole redaction set.** In Kubernetes sidecar
  mode, every agent pod has every value in memory. Prefer the central deployment
  ([kubernetes.md](kubernetes.md)).

## Redaction

- **Secrets scrim does not know.** Redaction matches the values your stores hold. A secret in no
  configured store is caught only if a fallback detector recognises its format: the detectors
  cover cloud keys, API tokens of common services and AI providers, private keys, JWTs and
  database URL passwords ([configuration.md](configuration.md#redactiondetectorsdisable) lists
  them). By default they match the value as written and leave passwords and random keys with no
  known prefix or key name alone. Three opt-in settings widen them, each off by default for its
  cost or its false positives ([configuration.md](configuration.md#fallback-detectors)): the
  generic `password = ...` rule (`redaction.detectors.enable`), base64, hex and percent-encoded
  forms of a known format (`redaction.detectors.encoded`, not encodings of encodings or base64
  wrapped across lines), and an entropy check on values after a key name that says secret
  (`redaction.detectors.entropy.enabled`). A random value under a neutral name (`config.json`
  holding `"value": "..."`) is not detected even then. Point a store at every secret source the
  agent can reach.
- **Transforms the guard does not read.** By default the guard reads look-alike Unicode
  (confusables, fullwidth and mathematical letters, tag and invisible characters), values spelled
  out as NATO, digit and symbol words, and short fragments of a value spread over one request
  ([configuration.md](configuration.md#guard-transforms)). Not matched: spelling in other
  languages or alphabets, look-alikes outside Unicode's Cyrillic, Greek, Armenian and Latin
  confusables, fragments shorter than the minimum length (8 bytes by default), and encodings of
  encodings beyond those listed in [leak-assurance.md](leak-assurance.md#what-the-guard-decodes).
  Compressed documents in base64 (gzip, zlib, zstd, brotli, deflate) and the base85 family are
  read only with `redaction.guard.enable` naming `compressed` or `base85`: they cost a third more
  guard time on requests with base64 data, and with ten thousand values, respectively.
- **Values split across requests.** Pieces of a value sent in separate requests of one agent
  session, including turns the provider keeps (`previous_response_id`, conversations, a WebSocket
  session), are joined by the guard's `cross-request` transform: it remembers which pieces of which
  value each session sent (never the bytes) and repairs the pieces of the request that completes a
  value. What still passes: pieces shorter than the minimum length (8 bytes by default); pieces
  that read as words rather than random (no capital after a lower-case letter, no letter next to a
  digit, no punctuation inside, fewer than four consonants in a row), since the words of a long
  session would otherwise join into any value made of words, and an AWS access key ID's letters
  between its digits can read that way; pieces more than 30 minutes apart, or past the 256 pieces
  kept per session or the 1,024 sessions kept; pieces sent under different sessions (the session
  is what the transport says: a client certificate, the session id, a Kubernetes token, the Unix
  user, or one shared session for unknown callers, so an agent that can change its session id
  starts over); pieces sent through different replicas, since each data plane replica remembers
  only its own requests; pieces of a value removed from the redaction set and added again (they are
  dropped at the session's next check); and pieces sent before the data plane restarted. Changes
  to the redaction set, such as a session starting or ending, keep the memory. The earlier pieces
  have already left when the last one is repaired: the provider holds part of the value, never all
  of it.
- **Short values.** Values shorter than the minimum length (8 bytes by default) are matched only
  whole and in their encoded forms, never as fragments. `scrim status` lists them.
- **Text in image pixels is not read.** Under the default `redaction.binary: scan`, scrim decodes
  images, PDFs and other attachments and scans their bytes, metadata and document text, and refuses
  a request whose attachment holds a secret. It does not recognise text rendered into pixels (no
  OCR), audio or video content, or PDF text drawn with fonts whose encoding needs a ToUnicode map to
  read. A screenshot of a terminal showing a secret reaches the provider. Keep secrets off screen
  when the agent takes screenshots.
- **Attachments referenced by URL are not fetched.** An `image_url` with an `https:` URL, an
  uploaded file ID or a Gemini `fileData` URI is passed on as text; the provider fetches the content
  and scrim never sees it.
- **Attachments scrim cannot decode are refused.** Encrypted PDFs, archives other than gzip and
  ZIP with deflate, and parts past the scan bounds (64 MiB decoded or inflated, 100,000 objects,
  nesting depth 4, 2 seconds plus 250 ms per MiB) are refused under `scan` with
  `unscannable_content`. Set `redaction.binary: pass` to forward them unscanned; that is weakening
  and reported by `scrim status` and `scrim doctor`.
- **Large attachments add latency under `scan`.** Each part is decoded and every view of it goes
  through the redactor and the guard: about 55 ms per MiB for an image and 250 ms per MiB for a
  text-heavy PDF on the reference machine (design.md of the `binary-parts-policy` change).
- **Clients that pin certificates** fail to connect under TLS interception. That fails closed, but
  such a client cannot be used through the forward proxy, transparent or DNS modes.

## How traffic reaches scrim

- **The wrapper, base URL and forward proxy modes rely on the agent using the settings it is
  given.** They stop accidents, not an agent or a prompt-injected command that sets out to reach
  the provider directly. Transparent mode, Kubernetes injection with a NetworkPolicy and managed
  agent settings enforce; DNS override is bypassed by connecting to an address; hooks see tool
  results and prompts, never the model traffic. [interception.md](interception.md) has the table.
- **MCP-only use intercepts nothing.** The agent's model requests go straight to the provider.
- **WebSocket restore covers the Realtime and Gemini Live protocols.** Client messages on every
  provider route are redacted and guarded like request bodies. Placeholders in provider messages
  are restored for the OpenAI Realtime API (`/v1/realtime`, also Azure Voice Live and Azure
  OpenAI Realtime under `/openai/` on a Foundry route), the Responses API WebSocket mode
  (`/v1/responses`) and the Gemini Live API (`BidiGenerateContent` on the Gemini API and Vertex
  AI). Elsewhere the agent sees placeholders: OpenAI's GPT-Live sessions (`/v1/live/sessions`)
  and any other WebSocket on a provider route. Azure OpenAI's own host
  (`<resource>.openai.azure.com`) has no route. Server messages are not written by capture mode.
  Other upgrades than WebSocket are refused (`501 upgrade_unsupported`).
- **Audio is not restored, transcripts are.** A model that reads a placeholder aloud says the
  placeholder, not the value, and scrim cannot change audio. The transcripts the provider sends
  with it (Realtime `response.output_audio_transcript.*`, Live `outputTranscription`) carry the
  placeholder as text and are restored, so the value is in the transcript and not in the sound;
  likewise the provider's transcripts of the user's audio. Audio the agent sends is a binary part
  ([Redaction](#redaction)): a value spoken by the user reaches the provider. scrim adds no
  instruction telling the model to avoid saying placeholders (see the
  [design note](../openspec/changes/websocket-provider-restore/design.md)).
- **Amazon Nova Sonic's bidirectional stream does not work through scrim.**
  `InvokeModelWithBidirectionalStream` is an HTTP/2 event stream whose request body stays open for
  the whole session; scrim reads a request body whole before forwarding it, so the session never
  starts.
- **A running scrim keeps its own upstream proxy.** `scrim run` chains an inherited `HTTPS_PROXY`
  behind scrim only when it starts scrim itself; a scrim already running as a service uses the
  upstream proxy it was configured with for every session, and `scrim run` only warns when yours
  differs ([run.md](run.md#corporate-proxies)). Runtimes with their own trust store (Java, for one)
  do not trust scrim's CA inside the session ([run.md](run.md#limitations)).
- **Not every outbound connection uses the upstream proxy.** PostgreSQL, Valkey and NATS
  connections, plugins and Kubernetes TokenReview connect directly
  ([configuration.md](configuration.md#upstream-proxy)). Connections already open when the proxy
  changes keep their route until they close.

## Implementation

- **A few copies on the boundary between the control plane and the data plane are not zeroed.**
  The snapshot carries every value to the data plane over gRPC, and asks and captures carry
  Kubernetes tokens and captured values back. Both sides zero the buffers they encode a message
  into, the buffers they receive DATA frames into and the bytes they decode from (design.md of the
  `transport-copy-zeroing` change). These copies are not:
  - In the data plane, h2's read buffer when it is reallocated while it holds part of a frame: the
    part already read stays in the old buffer, which is freed without zeroing.
  - In the data plane, DATA frames shorter than 256 bytes (1 KiB under `--stdio`), which h2 copies
    into its reused write buffer: a small ask or capture, or the tail of a longer message.
  - Under `--stdio` (Windows), tokio's stdin and stdout buffers, which every byte passes through.
  - The kernel's socket or pipe buffers.

  Plugin connections do not zero gRPC's transport buffers ([plugins.md](plugins.md#secret-handling)).
- **Credentials that SDKs and HTTP clients take as strings are copied out of scrim's secret
  type.** Go strings cannot be wiped; scrim builds them as late as it can and keeps none for
  longer than one request, except where a library keeps its own:
  - Bearer tokens of stores, notifiers and audit sinks are one header string per request. Go's
    HTTP client copies them into its reused per-connection write and TLS buffers, where they stay
    until later writes overwrite them. HTTP/2 header compression is off, so no header stays in a
    connection's compression table.
  - The upstream proxy password is one `Proxy-Authorization` string per CONNECT. For a plain
    `http://` destination reached through an authenticating proxy, Go only authenticates from the
    proxy URL's user info, so the password is in that URL as a string, and Go keeps it with the
    pooled connection while the connection stays open (90 seconds when idle).
  - AWS static keys are new strings for each signature. The SDK's SigV4 signer builds
    `AWS4` plus the secret key once a day per region and service and keeps the derived signing key
    until the next day; the session token is a header string per request. Credentials from the
    default chain (environment, shared files, instance metadata, web identity) and assumed roles
    are kept as strings in the SDK's cache until they expire, which for environment and file
    credentials is the adapter's lifetime.
  - Google's x/oauth2 keeps the current access token as a string until it expires (about an hour)
    and a service account's parsed private key for the adapter's lifetime. Azure's azidentity keeps
    the client secret for the adapter's lifetime and access tokens until they expire.
  - Vaultwarden's login form values are strings for the length of the login.
- **Short credentials of scrim's own are not redacted.** scrim's own credentials (notifier
  tokens, the admin and metrics tokens, audit sink, Valkey, NATS and Postgres passwords, signing
  keys, store credentials) are in the redaction set, but a value shorter than 8 bytes is left out
  and named in a start-up warning, because redacting it would rewrite unrelated text. Per-agent
  store tokens (`identity.store-credentials`) and the edge forwarder's token file are not in the
  set either: scrim does not keep the first in memory, and the second lives in the agent pod.
- **The chart's generated edge CA is not name-constrained.** The edge listener has a CA of its own,
  trusted only by the edge forwarders, and a CA scrim generates is constrained to the edge names.
  Helm cannot add name constraints, so the edge CA the chart generates can sign for any name; only
  the forwarders trust it, but its key should be protected like the interception CA's. Supply a
  constrained one with `edge.ca.existingSecret` ([edge-forwarder.md](edge-forwarder.md#the-edge-ca)).
  While `edge.legacy-interception-certificate` is on during an upgrade, forwarders from 1.0 still
  trust the interception CA for the edge listener.
- **Added request latency is above the performance spec's 5 ms target on the reference runner.**
  The target (5 ms on a 1 MB body with 1,000 secrets, 10 ms with 10,000) is measured on an agent's
  next turn, where the guard's verdict cache skips what it checked one request earlier. On ho-z10
  that takes 4.7 to 12 ms at p99 across runs, mostly the codec's JSON plan and the redactor over
  the whole body; the budgets are 10 and 12 ms. A 1 MB body seen for the first time, any body with
  `redaction.guard-cache` off, and the first request after a snapshot push (which starts an empty
  cache) go through every decoder: 10 to 27 ms at p99 on ho-z10. The latency gate fails a change
  that misses a budget in two runs; its comparison with the previous release is report only
  ([performance.md](performance.md#budgets)).
- **The performance gate measures on a shared runner.** The latency gate drops samples during which
  the measuring thread waited for a CPU, but not those where one of the guard's worker threads did;
  those measurements rely on the median over rounds. The runner's clock speed varies between runs
  (up to about two times), so the budgets are wide and the regression check compares measurements
  relative to a calibration workload, which tracks clock speed better than memory or cache
  contention. It only compares runs on the same runner class and CPU, so a change of the reference
  runner's hardware skips a comparison instead of failing it.

## Identity and per-agent settings

- **Same-user processes share an identity.** Peer credentials identify the Unix user, so your
  shell and editor are that user's identity too. An agent that runs as root or can `ptrace` another
  agent can act as it. Run agents as separate users or in containers when they must not
  impersonate each other.
- **Session tokens and Kubernetes tokens are bearer credentials toward scrim.** On the agent API
  and Unix sockets a session token only works inside the session's process tree, but on the TCP
  base URL and forward proxy listeners, which cannot see the client's process, any same-user
  process that holds the token is that session. Any process in a pod that can read the projected
  service account token is that agent ([identity.md](identity.md#what-this-does-not-protect-against)).
- **`identity.kubernetes.unmapped` defaults to `derive`.** A verified service account that no
  `identity.kubernetes.agents` rule maps becomes the agent `NAMESPACE/NAME`. Any pod that can mint
  a token for scrim's audience is therefore an agent, and gets whatever your rules allow an agent
  of that name. Set `identity.kubernetes.unmapped: unknown` and map service accounts explicitly when
  more than the intended pods can mint that token.
- **`redaction.limit-to-agent-identity` is a weakening setting.** With it on, a session's provider
  requests are not redacted for values its store credential cannot read. The data plane checks the
  session token, not the process tree it was minted for, so a process that steals a session token
  gets that session's narrower redaction. It applies only to agents with a static credential in
  `identity.store-credentials`: Kubernetes passthrough agents and agents that log in by token
  exchange are never narrowed (they keep the whole redaction set). [identity.md](identity.md#redaction-identity)
- **OCSP for client certificates is checked by the control plane, not stapled.** With
  `identity.client-certificates.ocsp.enabled`, the first connection of each certificate waits for
  its responder, the responder learns which certificates connect, and with the default `fail-closed`
  a responder outage refuses every certificate no current CRL covers. Without CRLs or OCSP, a stolen
  client certificate and key work until the certificate expires; use short-lived certificates
  ([identity.md](identity.md#revocation)).
- **Per-agent store identity is not available for every store.** `openbao`, `vault`, `awssm`,
  `ssm`, `gcpsm`, `azkv`, `infisical`, `doppler`, `onepassword`, `bws` and `vaultwarden` take
  per-agent credentials; a store configured for one that does not (`env`, `file`, `sops`,
  `keyring`, `kubernetes`, plugins) refuses every use. 1Password takes Connect tokens only, not
  service account tokens. Vaultwarden needs an account per agent (a seat each on bitwarden.com).
  [identity.md](identity.md#stores-without-a-token-exchange)
- **Agent writes are not checked against the agent's own store identity.** The per-agent check runs
  before a value is used (injection, restore). `secret_gen`, `secret_capture` and `scrim secret put`
  write with scrim's own store identity once scrim's rules allow them. Where a store could check a
  write (OpenBao, Vault, Google, Bitwarden Secrets Manager, Vaultwarden) the adapter can answer it,
  but nothing asks yet; AWS, Azure Key Vault, Infisical, Doppler and 1Password Connect cannot say
  whether an identity may write without writing.
- **Some per-agent checks read the value as the agent.** AWS, Azure Key Vault, Infisical and Doppler
  have no call that says whether an identity may read a secret, so the check reads it with the
  agent's credential and wipes it unread.

## Several replicas

- **The state database and the placeholder key together reveal every live scrim token.** Replicas
  share session, service account and identity tokens through PostgreSQL, sealed under a key derived
  from the placeholder key, so every replica redacts them. Whoever holds both the database (or a
  backup of it) and the placeholder key can open them until they expire. Someone who can write the
  database can delete the rows, and a token is then redacted only by the replica that minted or
  verified it.
- **Values split across requests are joined per replica.** The guard's memory of the pieces a
  session sent (`cross-request`) lives in each data plane replica, so pieces sent through
  different replicas are never joined. Pin a session to one replica (session affinity on the
  proxy's Service or load balancer) where that matters.
- **Decision links need a shared key.** Without `approvals.signing-key`, each process signs with a
  random key, and links stop working on restart and on other replicas
  ([approvals.md](approvals.md)).

## What the tests do not cover

- **Stores without an emulator are not in the end-to-end matrix**: Google Secret Manager, Azure Key
  Vault, Infisical, 1Password, Doppler, Bitwarden Secrets Manager and Vaultwarden. SSM, Kubernetes,
  SOPS, the keyring, `env` and plugins are not in it either. Their adapters pass the store
  conformance suite against fakes or containers, and they feed the same redaction set as the stores
  in the matrix.
- **Google and Azure token exchange are tested against in-process fakes only**, as is Vault JWT
  login (OpenBao JWT login is tested against a real server).
- **AWS per-agent identity is tested against LocalStack, which does not verify the web identity
  token or enforce IAM.** The assume-role flow and the session name CloudTrail records are tested;
  the refusals are not, against real IAM.
- **The Kubernetes cell of the matrix and the multi-replica load test run in CI on every change,
  not in the release workflow**, so their results are not among a release's files.
- **The agent drivers of the leak suite cover one provider API each and pinned releases.** `scrim
  audit run --driver` plays the agent sessions with Claude Code and OpenCode on the Anthropic
  Messages API and with Codex on the Responses API over WebSocket, at the versions CI pins
  ([leak-assurance.md](leak-assurance.md#agent-drivers)). OpenCode on OpenAI or Gemini, other
  agents, and other releases are covered by the built-in synthetic agent and the bypass matrix,
  not by the real CLIs.
- **Fuzzing for a release is 10 minutes per target.** It starts from the corpus the nightly runs
  (1 hour per target) keep on the `fuzz-corpus` branch, so its coverage depends on those runs having
  happened; the release results give the hours behind the corpus. Each target fuzzes in one
  process on a 4-core GitHub-hosted runner (Go fuzzing uses every core, libFuzzer one). The Go
  corpora are not minimised, Go having no minimiser, so they only grow. The scrim-llm stream
  parsers and codecs have no fuzz target of their own; their recorded streams seed the redaction
  targets ([leak-assurance.md](leak-assurance.md#fuzzing)).

## Limits of particular features

These pages list their own limits in more detail:

- [run.md](run.md#limitations): `scrim run` with Codex and OpenCode, custom model providers and
  trust stores.
- [interception.md](interception.md#what-it-does-not-protect): what hooks-only mode leaves uncovered.
- [ssh-agent.md](ssh-agent.md#limitations): `IdentityAgent` in `~/.ssh/config`, RSA and ECDSA keys
  that cannot be wiped, encrypted and security keys.
- The store guides, each under "Limitations": for example [openbao.md](stores/openbao.md#limitations),
  [infisical.md](stores/infisical.md#limitations), [gcp.md](stores/gcp.md#limitations),
  [doppler.md](stores/doppler.md#limitations) and [local.md](stores/local.md#limitations).

## Platforms

- **The macOS binaries are notarised only once the maintainers have added Apple's signing
  credentials** ([install.md](install.md#for-maintainers-macos-signing-and-notarisation)). Until
  then the release notes say the darwin binaries are not notarised, and a browser download has to
  have its quarantine attribute cleared after you verify it. Signed or not, the checksums are signed
  and every archive has provenance.
- **Windows runs a subset of scrim** ([install.md](install.md#windows)). scrim refuses to start on
  Windows, naming the setting, when any of these is configured: `proxy.socket` (Unix socket LLM
  listeners), `proxy.transparent-listen` and `interception.ebpf.*` (transparent and eBPF
  interception), `exec.commands` (brokered commands, `secret_exec`), `databases` (the database
  proxies), `api.permissions` and `api.group`, `identity.peers` selectors by `uid:`, `gid:` or
  `group:`, and `dataplane.memory-lock: require`.
- **On Windows, other accounts are not told apart.** A caller on scrim's sockets is either the
  account scrim runs as or unknown; `identity.peers` can name only that account. Separate agents
  with `scrim run` session tokens. A peer is identified by the process ID Windows records when it
  connects; if that process exits and the ID is reused before scrim looks it up, the new process's
  account is the one checked.
- **Not on Windows:** plugins, the ssh-agent in `scrim run` (`SSH_AUTH_SOCK` is left as it is, so
  the session can use your own agent's keys), the session filesystem view (credential files in your
  profile stay readable from the session), the docker credential helper when neither a symbolic nor a
  hard link to `scrim.exe` can be made, `scrim install`, the Windows certificate store (`scrim ca install`
  writes the bundle files only; import the CA with `certutil -user -addstore Root`), configuration reload on
  `SIGHUP` (use `config.watch` or the admin API) and the CA directory lock between two processes.
- **The Windows data plane does not lock its memory or suppress crash dumps.** Values can be paged
  to disk and end up in a Windows Error Reporting dump. Keep the page file and dumps on an encrypted
  disk (BitLocker).
- **Windows binaries are not Authenticode-signed**, so SmartScreen may warn about a browser
  download. Verify them with the signed checksums and provenance.
- **The capture directory is not checked by the data plane on Windows.** The control plane refuses
  a `proxy.capture.dir` that other accounts can reach, but the data plane creates the files without
  checking again. Keep it under your profile.
- **Windows has no race detector run in CI.** The Go tests run there without `-race` (it needs cgo);
  Linux CI runs every package with it. Packages and tests that cannot run on Windows are listed with
  their reason in `scripts/test-windows.sh` and in `//go:build unix` constraints.
