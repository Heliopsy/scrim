# Architecture

This page shows how scrim is put together and how a request moves through it. It describes the
v0.1.0 design. The normative contract is the OpenSpec change in
[`openspec/changes/scrim-v1`](../openspec/changes/scrim-v1/): the decisions D1 to D13 are in
[`design.md`](../openspec/changes/scrim-v1/design.md), the requirements in its `specs/` directory.
Where this page and the specs disagree, the specs win.

scrim is one binary with two processes at runtime. The Go control plane reads secret stores,
evaluates policy, runs approvals, serves the agent tools and writes the audit log. The Rust data
plane carries every byte of agent traffic: it redacts model requests, restores placeholders in
responses and injects credentials into tool traffic. The control plane pushes everything the data
plane needs as a snapshot, so the data plane decides on its own and calls back only when a rule
asks for a human.

Some parts are not on `main` yet. Each diagram has a status line under it naming them. The
diagrams show the design those branches implement.

## System context

```mermaid
flowchart LR
  agent["Agent<br>Claude Code, Codex,<br>API clients, CLI tools"]
  operator["Operator<br>config, scrim status,<br>scrim approve, audit"]
  scrim["scrim<br>control plane + data plane"]
  provider["LLM provider APIs"]
  toolapis["Tool APIs<br>api.github.com, ..."]
  stores[("Secret stores<br>OpenBao, Infisical,<br>Vaultwarden, env, file")]
  approvers["Approvers<br>ntfy, webhook, terminal"]

  agent -- "model requests" --> scrim
  scrim -- "placeholders only" --> provider
  agent -- "HTTPS with placeholders" --> scrim
  scrim -- "real credential, bound hosts only" --> toolapis
  agent -. "MCP / CLI: names and references" .-> scrim
  scrim -- "read, watch, write" --> stores
  scrim -- "approval request, no values" --> approvers
  approvers -- "signed decision link" --> scrim
  operator -- "admin socket, config files" --> scrim
```

The agent talks to scrim instead of to the provider and the tool APIs directly. The provider only
ever sees placeholders. Tool APIs see the real credential, and only the hosts a credential is bound
to. scrim is the only holder of store credentials (D6), so agents never reach a store themselves:
they create and update secrets through scrim's MCP server or CLI and never read a value back.
Approvers get a message with names and references only, and decide through a signed link. The
operator configures scrim with files, `SCRIM_*` variables and flags (D10) and works through the
admin API.

Status: everything in this picture is on `main` for v0.1.0. `scrim proxy` runs the control plane,
the data plane and every socket, and `scrim run` starts or reuses it for one agent.

## Components

```mermaid
flowchart TB
  agent["Agent"]
  operator["Operator"]
  approver["Approver's phone"]
  prom["Prometheus"]

  subgraph cp["Control plane (Go), scrim process"]
    direction TB
    cli["cli<br>scrim proxy, run, mcp,<br>secret, approve, status"]
    app["app<br>composition root"]
    config["config<br>settings registry"]
    stores["stores + refresh<br>adapters, in-memory values"]
    catalog["catalog<br>names, bindings,<br>declared placeholders"]
    policy["policy<br>CEL rules, decision table"]
    gate["gate<br>single decision path"]
    approval["approval, grant,<br>breakglass, notify"]
    identity["identity<br>peer creds, session tokens"]
    agenttools["agenttools<br>localapi, mcp, entrypage"]
    builder["snapshot builder"]
    sup["dataplane.Supervisor<br>launch, push, restart"]
    state[("state<br>memory, SQLite, Postgres")]
    audit["audit, obs, status"]
  end

  subgraph dp["Data plane (Rust), child process"]
    direction TB
    server["scrim-dataplane<br>gRPC server, snapshot,<br>engine, listeners"]
    llm["scrim-llm<br>provider codecs, LLM proxy"]
    redact["scrim-redact<br>Redactor, Independent guard,<br>Restorer"]
    tp["scrim-toolproxy<br>Tool proxy, CA, injection,<br>response redaction"]
    dppolicy["scrim-policy<br>decision table, restore policy,<br>escaping"]
  end

  subgraph listen["Listeners"]
    base["Base URL<br>TCP or Unix socket"]
    fwd["Forward proxy<br>CONNECT"]
    tpl["Tool proxy<br>HTTPS"]
    api["Local agent API<br>api.sock"]
    admin["Admin API<br>admin.sock"]
    entry["Entry page<br>loopback"]
    links["Decision links<br>approvals.public-url"]
    metrics["Metrics and health<br>metrics.listen"]
  end

  cli --> app
  config --> app
  app --> stores & catalog & policy & gate & identity & agenttools & sup
  stores & catalog & policy --> builder --> sup
  gate --> approval
  approval --> state
  gate --> audit
  agenttools --> gate
  agenttools --> stores

  sup == "socketpair, fd 3: Hello, ApplySnapshot, Status" ==> server
  server == "Events, Asks, Captures" ==> sup

  server --> llm & tp & dppolicy
  llm --> redact
  tp --> redact
  fwd -- "provider hosts" --> llm
  fwd -- "other hosts" --> tp

  agent --> base & fwd & tpl & api
  base --> llm
  tpl --> tp
  api --> agenttools
  entry --> agenttools
  operator --> admin --> approval
  approver --> links --> approval
  prom --> metrics --> audit
```

Each half is a set of packages or crates with one job. In the control plane, `app` builds every
long-lived component from the effective configuration and holds no logic. `gate` is the one place
a decision is taken, for agent tool calls and for asks from the data plane alike. The data plane
crates split along the traffic: `scrim-llm` understands provider APIs, `scrim-toolproxy` handles
tool HTTPS, and both call `scrim-redact`, whose redactor and guard share no matching code (D4).

The thick arrows are the boundary (D12): gRPC over a socketpair the control plane creates and the
child inherits as fd 3. Nothing else can connect to it. The control plane pushes snapshots and
reads status; the data plane streams audit events in batches, sends asks and sends captured
values. Every message carries the protocol version, and a mismatch stops the supervisor. The
forward proxy is one listener in front of both engines: provider hosts go to the LLM proxy, every
other host to the tool proxy (D8).

Status: all of this is on `main`. The data plane binds base URL (TCP and Unix socket),
forward-proxy and tool-proxy listeners; provider hosts reached through the forward proxy go to
`scrim-llm`, everything else to the tool proxy. `scrim proxy` runs the snapshot builder, the admin,
agent API, entry page, decision-link and metrics listeners. The data plane decides with
`scrim-policy` (decision table and restore policy from the snapshot, `policy_engine` `table/v1`).

## Request path

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent
  participant L as Base URL listener
  participant C as Provider codec
  participant R as Redactor
  participant G as Independent guard
  participant P as LLM provider API
  participant S as Restorer
  participant T as Restore policy

  A->>L: POST /anthropic/v1/messages
  alt no snapshot applied or redaction not ready
    L-->>A: 503 with Retry-After, nothing sent
  end
  L->>C: route by path prefix
  C->>R: raw request bytes and field plan
  R->>R: match known values and encoded variants, unknown fields redacted
  alt malformed, ambiguous or redactor error
    R-->>A: 422, nothing sent
  end
  R->>G: redacted bytes
  G->>G: scan exact outgoing bytes, decode extra transforms
  alt guard finds a value it cannot repair, or errors
    G-->>A: 422, nothing sent
  end
  G->>P: placeholders only
  alt provider or chained upstream unreachable
    P-->>A: 502
  end
  P-->>S: streamed response, SSE events
  loop each content block delta
    S->>S: find placeholders, hold back at most one placeholder length
    S->>T: placeholder, value class, restore site, tool name
    T-->>S: resolve with escaping, or keep the placeholder
    S-->>A: delta, restored where allowed
  end
```

The redactor runs over the raw bytes of the request and never decodes and re-serialises the body
(D2), so signed content such as thinking blocks passes byte-identical and prompt caching keeps
working. Placeholders are an HMAC of the value under a versioned key (D3), so the same value always
gives the same bytes. The guard runs after the redactor on the exact bytes about to leave and
decodes transforms the redactor does not try (D4). Any error in either check refuses the request
with a documented status, and there is no fallback that sends the request unredacted.

On the way back the restorer works per content block and holds back enough text to catch a
placeholder split across chunks. The restore policy decides per site and tool: a display value can
be restored with escaping for the shell, SQL, JSON or YAML it lands in, while a credential is never
restored into a command, file edit or tool argument (D5). A placeholder that cannot be resolved
stays a placeholder, which is safe and visible.

Status: on `main`. The LLM proxy, codecs, restorer and fail-closed handling live in `scrim-llm`,
the redactor and guard in `scrim-redact`, and the data plane wires them behind the base URL
listener. Request headers and the request target are redacted and guarded as well as the body. The
data plane restores under
`scrim-policy` ([README](../dataplane/crates/scrim-policy/README.md)): text follows the display mode,
shell and edit tool calls are buffered and restored escaped, credentials are never restored, and
deny or ask rules on `op == "restore"` keep the placeholder. The control plane fills
`Snapshot.restore` from the `restore.*` settings; a snapshot without it restores nothing.

## Tool call with a credential

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent tool, curl
  participant F as Forward proxy
  participant X as Tool proxy
  participant D as Control plane
  participant U as Tool API
  participant O as Other host

  A->>F: CONNECT api.github.com:443
  F->>X: TLS terminated with a leaf from scrim's CA
  X->>X: Host, authority and SNI must match the CONNECT target
  alt mismatch
    X-->>A: 421 misdirected_request
  end
  X->>X: find every placeholder in URL, headers, cookies, body
  X->>X: check each one against its binding: host, method, path, location
  alt credential not in memory, past the staleness limit, or a placeholder nothing resolves
    X-->>A: 503 credential_unavailable
  end
  X->>X: substitute, encoded for where each value lands
  X->>U: request with the real token
  U-->>X: response
  opt a capture rule matches the response
    X->>D: CaptureRequest with the new token
    D->>D: write it to the store, redact it at once
    D-->>X: placeholder, or error
    Note over X: on error or timeout the field is withheld
  end
  X->>X: redact known values in headers, trailers and body
  X-->>A: response with placeholders only

  A->>F: CONNECT attacker.example:443, same placeholder
  F->>X: TLS terminated
  X->>X: placeholder is not bound to attacker.example
  X-->>A: 403 unbound_destination, nothing sent upstream
  Note over O: never contacted
```

The agent runs the command the model wrote, placeholder and all. With `HTTPS_PROXY` set, the
command's HTTPS goes through the forward proxy, which terminates TLS with scrim's own CA and hands
the decrypted request to the tool proxy. Bindings are checked against the connection scrim opened,
not against what the request claims, so a shared front end cannot route an injected token to
another tenant (D5). Every placeholder in a request is checked before any is substituted, so one
unbound placeholder refuses the whole request. Every refusal and every injection is an audit event.

Capture rules cover APIs that issue a new secret, such as a token-creation endpoint. The value goes
to the control plane, which writes it to the store and adds it to the redaction set before
answering, and the agent receives the placeholder. A response the proxy cannot scan is withheld,
and so is a captured field whose store write fails.

Status: the tool proxy, CA, bindings, injection, capture and response redaction are on `main` in
`scrim-toolproxy`, and the supervisor's capture stream is on `main`. After the binding checks, every
injection is decided by the decision table (`op == "inject"`), asking the control plane where a rule
says so, and a denial is `403 policy_denied`. The control plane handles captures (stored through
the gate as `store.write`) and holds the CA, which it pushes in the snapshot.

## Ask and approval

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent
  participant DP as Data plane, decision table
  participant SV as Supervisor
  participant GT as Gate
  participant GR as Grants
  participant AP as Approvals
  participant N as Notifier
  participant H as Human approver

  A->>DP: request that needs a secret
  DP->>DP: evaluate every rule: match, no match or unknown
  alt deny wins
    DP-->>A: refused, audited
  else allow, no side effect
    DP-->>A: proceeds locally
  else ask, unknown, or allow with a grant ttl
    DP->>SV: AskRequest with request attributes and a deadline
    SV->>GT: Check
    GT->>GT: break-glass, then full CEL rule set
    GT->>GR: grant covering this agent and reference?
    alt grant found
      GR-->>GT: yes, use counted
      GT-->>DP: AskAnswer allow
    else no grant
      GT->>AP: create pending approval
      AP->>N: approval message with names only
      N->>H: ntfy, webhook or terminal
      H->>AP: open signed link, GET shows, POST decides
      AP->>GR: approved with a ttl, grant created
      AP-->>GT: settled
      GT-->>DP: AskAnswer allow or deny
    end
    DP-->>A: proceed, or refuse
  end
  Note over DP: no answer by the deadline denies
  A->>DP: retry after the deadline
  DP->>SV: ask again
  SV->>GT: Check finds the grant, allow
```

The data plane does not run CEL. The control plane lowers each rule into a decision table of plain
string conditions, and anything the table cannot express (time, regular expressions, field to field
comparisons) becomes a residual that returns unknown (D7). The data plane decides alone only when
its answer is certain to match the control plane's; otherwise it asks. This keeps the common case
off the boundary, which matters because synchronous calls across it cost 15 to 30% of throughput
in the D1 benchmark.

The gate re-evaluates the full rule set before it looks at grants, and grants are read from the
state backend on every use, so a revocation or an expiry applies to the next request on every
replica sharing the backend. Decision links are single-use HMAC tokens over approval ID, action,
expiry and notifier. A held request that times out is denied. The approval stays pending, and once
it is approved the grant it leaves behind lets the agent's retry through. Approvals deny on
timeout, and break-glass denies everything except redaction.

Status: the gate, approvals, signed links, notifiers, grants and break-glass are on `main`, as is
the Go reference evaluator for the decision table. The data plane evaluates the table with
`scrim-policy` for every injection and provider request and sends asks over the `Asks` stream,
bounded by `Policy.ask_timeout_millis` (denied on timeout or with the stream down, grants never
cached). An ask carries what the transport said about the caller (`AskCaller`: the session a
request names, Unix peer credentials), since the data plane cannot verify sessions. Connecting the
supervisor's ask stream to the gate, the decision links and the admin API are on `main`. Resolving
`AskCaller` to a verified agent, filling `ask_timeout_millis` from `approvals.timeout`, and `scrim
run` naming its session on every request are in progress on `feat/control-plane-decisions`.

## Snapshot lifecycle

```mermaid
flowchart LR
  subgraph sources["Control plane inputs"]
    direction TB
    st[("Secret stores")]
    ref["stores/refresh<br>load, watch, interval"]
    cat["catalog<br>bindings, classes,<br>declared placeholders"]
    pol["policy<br>CEL compiled to table"]
    cfg["config<br>routes, listeners,<br>capture rules, keys"]
    bg["breakglass"]
  end

  st -- "values" --> ref
  ref --> b["Snapshot builder<br>debounced"]
  cat --> b
  pol --> b
  cfg --> b
  bg --> b

  b -- "version N+1" --> sup["Supervisor.Push<br>wipes secret bytes after send"]
  sup -- "ApplySnapshot" --> val{"version greater<br>and valid?"}
  val -- "no" --> keep["reject, version N stays in force"]
  val -- "yes" --> build["build matcher and<br>tool proxy view off the hot path"]
  build --> swap["atomic swap"]
  swap -- "applied_version N+1" --> sup
```

Every input that can change what the data plane does feeds one builder: the values the refresher
holds, catalog bindings and declared placeholders, the policy table, routes, listeners, capture
rules, placeholder keys and the break-glass flag. Each snapshot has a higher version than the last.
The data plane validates it, builds the new matcher without touching live traffic, and swaps it in
with one atomic store, so a request never waits for a rebuild (D2). A rejected snapshot leaves the
previous one in force. A restarted data plane reports version 0 and gets a full push.

Store outages do not weaken redaction. A value stays in the redaction set while its store is
unreachable, and a rotated or deleted value stays for the retention period (24 hours by default).
Injection fails closed: the refresher hands out a value only if the store confirmed it within the
staleness limit (15 minutes by default), and redaction is not ready until the first load completes.
A written or captured value joins the set before the write is reported. If the data plane dies,
the supervisor marks scrim not ready, so health checks fail and nothing is served, then restarts
it with backoff.

Status: on `main`. The daemon builds the full snapshot (values with their bindings, placeholder
keys, decision table, restore settings, routes, listeners, capture rules and CA), pushes it after
every relevant change, debounced, and the data plane applies it as one bundle swapped atomically.

## Trust boundaries

```mermaid
flowchart TB
  subgraph values["Holds secret values"]
    direction LR
    stores[("Secret stores")]
    subgraph host["Same host, separate processes"]
      direction LR
      cpm["Control plane memory<br>secret.Value, wiped after use"]
      dpm["Data plane memory<br>mlocked, not dumpable,<br>zeroed on drop"]
      cpm == "socketpair only, snapshot" ==> dpm
    end
    stores -- "store credentials held by scrim only" --> cpm
  end

  subgraph none["Never holds a value"]
    direction LR
    db[("State backend<br>approvals, grants,<br>sessions, outbox")]
    logs["Logs, metrics,<br>traces"]
    aud["Audit sinks"]
    prov["LLM provider"]
    ag["Agent context<br>placeholders only"]
    appr["Approvers"]
  end

  cpm -. "references, decisions" .-> db
  cpm -. "scrubbed" .-> logs
  cpm -. "metadata events" .-> aud
  dpm -. "placeholders" .-> prov
  dpm -. "placeholders, restored display values" .-> ag
  cpm -. "names and references" .-> appr
```

Values live in three places: the stores, the control plane's memory and the data plane's memory.
In the control plane a value is a `secret.Value` from the moment it is read; that type redacts
itself in every formatting and encoding path. The data plane runs as a separate child process that
inherits one end of a socketpair and nothing else (D11). It locks its memory where the limit allows
(`dataplane.memory-lock=require` refuses to start without it), disables core dumps and ptrace
attach, and zeroes values on drop. A crash on either side makes the other refuse traffic.

Nothing in the lower group receives a value. The state backend stores approvals, grants,
sessions and the event outbox, never a value or a placeholder-to-value mapping (D9). Logs pass a
scrubber, metric labels are configured names only, and events from the data plane carry
references and counts. Display values do reach the agent where the restore policy allows them.
The agent's own transcript on disk is outside scrim's protection: the user's machine is trusted,
and a file the agent reads locally is in that transcript before scrim sees any traffic.

Status: all of this is on `main` for the components that exist there.

## Deployments

```mermaid
flowchart TB
  subgraph laptop["Laptop: scrim run"]
    direction LR
    sh["shell"] --> run["scrim run -- claude"]
    run --> lcp["scrim control plane"]
    lcp --> ldp["data plane child<br>from memfd"]
    run --> lag["agent child<br>base URL, HTTPS_PROXY,<br>CA bundle, MCP, session token"]
    lag --> ldp
    lcp --- lsq[("SQLite file")]
  end

  subgraph vm["VM or workstation: local service, M2"]
    direction LR
    unit["systemd unit or Quadlet<br>dedicated user"] --> vcp["scrim proxy"]
    vcp --> vdp["data plane child"]
    nft["nftables per UID<br>transparent mode, M2"] -.-> vdp
    vag["agents"] --> vdp
  end

  subgraph k8s["Kubernetes: M2, scaling parts M3"]
    direction LR
    subgraph agentpod["Agent pod, labelled"]
      kag["agent"]
      edge["edge forwarder<br>ssh-agent, db ports,<br>no values, M2"]
    end
    subgraph central["scrim Deployment, HPA on streams"]
      kcp["scrim replicas<br>control plane + data plane"]
    end
    pg[("PostgreSQL<br>shared state, notify")]
    np["NetworkPolicy<br>agents reach only scrim and DNS"]
    kyv["admission policy<br>injects env, CA, MCP, token"]
    side["optional sidecar<br>full scrim proxy, egress guard"]
    kag --> kcp
    edge --> kcp
    kcp --- pg
    np -.-> agentpod
    kyv -.-> agentpod
    side -. "alternative to central" .-> agentpod
  end
```

On a laptop, `scrim run` makes sure a scrim is running for the user, mints a session token bound to
the agent's process tree and starts the agent as its child with every setting applied to that
process only: provider base URLs, the forward proxy, a CA bundle, the MCP registration and the
token. Nothing persistent changes, and if the data plane is not ready the agent is not started.
SQLite is the local state default and refuses a second process on the same file.

A local service (M2) runs `scrim proxy` under a dedicated user from a systemd unit or Quadlet, and
`scrim uninstall` reverts every change. Transparent mode with nftables (M2) or eBPF (M3) catches
agents that were not configured to use scrim. In Kubernetes (M2) a central Deployment serves agent
pods, a NetworkPolicy keeps them from reaching providers directly, an admission policy configures
labelled pods without changing their images, and replicas share PostgreSQL so approvals and grants
agree everywhere. Placeholders need no shared lookup table across replicas because they are an HMAC
of the value (D3). The edge forwarder exposes local sockets such as ssh-agent in the pod and holds
no values. A sidecar (a full `scrim proxy` per pod) holds the dictionary in every pod, so the
central deployment is the default. Valkey and NATS events and extra audit sinks are M3.

Status: v0.1.0 ships the laptop path and the forward proxy; `scrim run` and `scrim proxy` are on
`main`. The Helm chart with central and sidecar modes, the NetworkPolicies and the Kyverno admission
policy are on `main` ([kubernetes.md](kubernetes.md)); the sidecar is a full `scrim proxy`, not
the standalone data plane. The local service, transparent mode, edge forwarder, TokenReview
identity and Postgres notify events are planned for M2;
Valkey, NATS and eBPF for M3. The PostgreSQL state backend and the standalone `scrim-dataplane`
image are on `main`.

## Where to find it in the code

| Component | Code | Design | Docs |
| --- | --- | --- | --- |
| Composition root | `internal/app` | D1 | |
| Command line | `internal/cli` | | [agent-tools.md](agent-tools.md) |
| Settings | `internal/config` | D10 | [configuration.md](configuration.md) |
| Secret value type | `internal/secret` | D9 | |
| Store adapters | `internal/stores/{openbao,infisical,vaultwarden,env,file}` | D6 | [stores/README.md](stores/README.md) |
| Refresh and outages | `internal/stores/refresh` | D6 | [stores/README.md](stores/README.md#freshness-and-outages) |
| Catalog and bindings | `internal/catalog` | D5 | [catalog.md](catalog.md) |
| Policy and decision table | `internal/policy` | D7 | [policy.md](policy.md#how-the-data-plane-decides) |
| Decision path | `internal/gate` | D7 | [policy.md](policy.md) |
| Approvals, grants, break-glass | `internal/approval`, `internal/grant`, `internal/breakglass` | D7 | [approvals.md](approvals.md) |
| Notifiers | `internal/notify/{ntfy,webhook,terminal}` | D7 | [approvals.md](approvals.md#notifiers) |
| Agent identity | `internal/identity` | | [identity.md](identity.md) |
| Agent tools | `internal/agenttools`, `internal/localapi`, `internal/mcp`, `internal/entrypage`, `internal/agentapi` | D6 | [agent-tools.md](agent-tools.md) |
| State backends | `internal/state/{memstate,sqlite,postgres}` | D9 | [state-and-observability.md](state-and-observability.md) |
| Audit | `internal/audit`, `internal/auditlog` | D9 | [state-and-observability.md](state-and-observability.md#audit-log) |
| Logs, metrics, traces, health | `internal/obs` | | [state-and-observability.md](state-and-observability.md#metrics-and-health) |
| `scrim status`, `scrim doctor` | `internal/status` | D10 | [state-and-observability.md](state-and-observability.md) |
| Data plane supervisor | `internal/dataplane` | D11, D12 | [install.md](install.md) |
| Boundary schema | `proto/scrim/dataplane/v1/dataplane.proto` | D12 | |
| Data plane server, snapshot, listeners | `dataplane/crates/scrim-dataplane` | D8, D11, D12 | |
| LLM proxy and provider codecs | `dataplane/crates/scrim-llm` | D2, D4 | |
| Redactor, guard, restorer, placeholders | `dataplane/crates/scrim-redact` | D2, D3, D4, D13 | |
| Tool proxy, CA, injection | `dataplane/crates/scrim-toolproxy` | D5 | |
| Generated boundary code (Rust) | `dataplane/crates/scrim-proto` | D12 | |
| Data plane policy, restore policy, escaping | `dataplane/crates/scrim-policy` | D5, D7 | [README](../dataplane/crates/scrim-policy/README.md) |
| Leak suite | `internal/leak` | D4 | [leak-assurance.md](leak-assurance.md) |
