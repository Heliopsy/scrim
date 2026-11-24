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
  configured store is caught only if a fallback detector (pattern rules and entropy) recognises
  it. Point a store at every secret source the agent can reach.
- **Transforms outside the bypass matrix.** Look-alike Unicode, values spelled out in words,
  compressed content, the base85 family, and values the agent splits across fields, tool results
  or requests (including server-side state such as `previous_response_id`) are not matched. The
  guard's fragment rules catch long halves of a split value; short ones pass.
- **Short values.** Values shorter than the minimum length (8 bytes by default) are matched only
  whole and in their encoded forms, never as fragments. `scrim status` lists them.
- **Images, PDFs and other binary parts pass unscanned**, including text in image metadata. In the
  Gemini API that is every `inlineData` part, a `text/plain` document included. The spec describes
  a `block` policy for binary parts; scrim 1.0 has no setting for it, and the data plane always
  passes them. Keep secrets out of images and documents the agent attaches.
- **Clients that pin certificates** fail to connect under TLS interception. That fails closed, but
  such a client cannot be used through the forward proxy, transparent or DNS modes.

## How traffic reaches scrim

- **The wrapper, base URL and forward proxy modes rely on the agent using the settings it is
  given.** They stop accidents, not an agent or a prompt-injected command that sets out to reach
  the provider directly. Transparent mode, Kubernetes injection with a NetworkPolicy and managed
  agent settings enforce; DNS override is bypassed by connecting to an address; hooks see tool
  results and prompts, never the model traffic. [interception.md](interception.md) has the table.
- **MCP-only use intercepts nothing.** The agent's model requests go straight to the provider.
- **WebSocket traffic to a provider is not redacted.** The LLM proxy refuses the upgrade
  (`501 upgrade_unsupported`); Codex falls back to HTTPS, a client that cannot fall back fails.
- **`scrim run` replaces an inherited `HTTPS_PROXY`** instead of chaining to it, and runtimes with
  their own trust store (Java, for one) do not trust scrim's CA inside the session
  ([run.md](run.md#limitations)).

## Implementation

- **The gRPC transport between the control plane and the data plane does not zero its buffers.**
  The snapshot that carries the values crosses the boundary over gRPC on an inherited socket. scrim
  wipes its own copies on both sides, but the buffers gRPC and protobuf allocate while encoding,
  sending and decoding are returned to the allocator with the bytes still in them.
- **Credentials that SDKs and HTTP clients take as strings are copied out of scrim's secret
  type.** The AWS SDK takes access keys as Go strings, so every signature copies them, and the
  copies live as long as the SDK's own. Store tokens sent in an HTTP `Authorization` header (for
  example Infisical's access token) are strings for the length of the request. None of these can
  be wiped; they are freed and eventually overwritten.
- **Short credentials of scrim's own are not redacted.** scrim's own credentials (notifier
  tokens, the admin and metrics tokens, audit sink, Valkey, NATS and Postgres passwords, signing
  keys, store credentials) are in the redaction set, but a value shorter than 8 bytes is left out
  and named in a start-up warning, because redacting it would rewrite unrelated text. Per-agent
  store tokens (`identity.store-credentials`) and the edge forwarder's token file are not in the
  set either: scrim does not keep the first in memory, and the second lives in the agent pod.
- **The edge listener's certificate is issued by the interception CA.** One CA key signs the
  certificates scrim presents for TLS interception and the certificate the edge forwarders check.
  Anyone holding that key can impersonate scrim to the forwarders as well as to agents. Protect it
  like the placeholder key ([ca.md](ca.md)).
- **Added request latency is above the performance spec's targets for large bodies.** The spec
  aims for 5 ms on a 1 MB body with 1,000 secrets and 10 ms with 10,000; the guard takes about
  20 ms per 1 MB at the median on the reference runner, and around 2 to 3 ms per 100 KB. The
  latency gate holds the production engine to budgets set from what it does today, and the
  regression check fails a release that got slower than the previous one, but neither makes it
  meet the spec's targets ([performance.md](performance.md#budgets)).
- **The performance gate measures on a shared runner.** The latency gate drops samples during which
  the measuring thread waited for a CPU, but not those where one of the guard's worker threads did;
  those measurements rely on the median over rounds. The regression check only compares runs on the
  same runner class and CPU, so a change of the reference runner's hardware skips a comparison
  instead of failing it.

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
- **Client certificates are not an agent identity in 1.0**, although the agent-identity spec
  describes them. Callers are identified by peer credentials, session tokens and Kubernetes service
  account tokens.
- **Per-agent store identity is not available for every store.** Only `openbao`, `vault`, `awssm`,
  `ssm`, `gcpsm`, `azkv` and `infisical` take per-agent credentials; a store configured for one
  that does not refuses every use. Infisical cannot check writes per agent, and Bitwarden Secrets
  Manager, Doppler, 1Password and Vaultwarden have no per-agent identity at all.

## Several replicas

- **Session tokens are redacted only by the replica that minted them.** Each scrim keeps the
  session tokens it minted in its own redaction set; the shared state holds only their hashes. A
  token minted through one replica is accepted by the others, but if the agent prints it and the
  request goes through another replica, that replica does not redact it. Where agents use `scrim
  run` sessions against several replicas, keep each agent's connections on one replica (session
  affinity on the load balancer).
- **Narrowed redaction follows the same rule.** `redaction.limit-to-agent-identity` narrows only on
  the replica whose data plane holds the session's token; elsewhere the session gets the whole
  redaction set, which is safe but inconsistent.
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
- **The leak suite drives the provider APIs directly.** A Codex driver for `scrim audit run` is not
  implemented; Claude Code and Codex are covered by the scenario corpus and the `scrim run` tests,
  not by driving the real agents.
- **Fuzzing for a release is short.** Each target runs for 10 minutes from an empty corpus in the
  release and for 15 minutes in the weekly run; no corpus is kept between runs.

## Limits of particular features

These pages list their own limits in more detail:

- [run.md](run.md#limitations): `scrim run` with Codex, custom model providers and trust stores.
- [interception.md](interception.md#what-it-does-not-protect): what hooks-only mode leaves uncovered.
- [ssh-agent.md](ssh-agent.md#limitations): `IdentityAgent` in `~/.ssh/config`, RSA and ECDSA keys
  that cannot be wiped, encrypted and security keys.
- The store guides, each under "Limitations": for example [openbao.md](stores/openbao.md#limitations),
  [infisical.md](stores/infisical.md#limitations), [gcp.md](stores/gcp.md#limitations),
  [doppler.md](stores/doppler.md#limitations) and [local.md](stores/local.md#limitations).

## Platforms

- Release binaries are for Linux and macOS only. The keyring source supports Windows' Credential
  Manager in code, but there is no Windows release.
- The macOS binaries are covered by the signed checksums and provenance like the others, but they
  are not notarised by Apple.
