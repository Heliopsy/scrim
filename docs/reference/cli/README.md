# scrim command line

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Keeps secret values away from LLM providers while AI agents keep working.

The settings reference is [configuration.md](../../configuration.md); every setting declared
with a flag is a global flag below.

## Usage

```text
scrim [flags] [command]
```

## Commands

| Command | Description |
| --- | --- |
| [`scrim api`](api.md#scrim-api) | Run or inspect the local agent API |
| [`scrim api serve`](api.md#scrim-api-serve) | Serve the local agent API and the human entry page until interrupted |
| [`scrim api whoami`](api.md#scrim-api-whoami) | Show the identity the local agent API gives this process |
| [`scrim approvals`](approvals.md#scrim-approvals) | List and inspect approvals |
| [`scrim approvals list`](approvals.md#scrim-approvals-list) | List approvals (pending by default) |
| [`scrim approvals show`](approvals.md#scrim-approvals-show) | Show one approval |
| [`scrim approve`](approve.md#scrim-approve) | Approve a pending approval and create its grant |
| [`scrim audit`](audit.md#scrim-audit) | Query the audit log of decisions, approvals, grants, store writes and injections |
| [`scrim audit log`](audit.md#scrim-audit-log) | List audit entries, newest first |
| [`scrim audit run`](audit.md#scrim-audit-run) | Run the leak suite against a proxy and report every seeded value that reached the fake provider |
| [`scrim ca`](ca.md#scrim-ca) | Export, rotate and install the tool proxy's interception CA |
| [`scrim ca export`](ca.md#scrim-ca-export) | Print the PEM certificates clients must trust (current CA, and the previous one during an overlap) |
| [`scrim ca install`](ca.md#scrim-ca-install) | Trust the CA in the per-user trust stores and write bundle files for runtimes with their own trust |
| [`scrim ca rotate`](ca.md#scrim-ca-rotate) | Make a new CA current; the previous one stays trusted for tool-proxy.ca.overlap |
| [`scrim ca uninstall`](ca.md#scrim-ca-uninstall) | Revert every trust change `scrim ca install --user` recorded |
| [`scrim catalog`](catalog.md#scrim-catalog) | Show and suggest secret catalog entries |
| [`scrim catalog labels`](catalog.md#scrim-catalog-labels) | List every label a secret has, as policy rules see it in secret.labels |
| [`scrim catalog show`](catalog.md#scrim-catalog-show) | Show the effective catalog and which reference each entry selects |
| [`scrim catalog suggest`](catalog.md#scrim-catalog-suggest) | Print draft catalog entries from the project, tool profiles and store contents; nothing is applied |
| [`scrim config`](config.md#scrim-config) | Inspect and validate configuration |
| [`scrim config schema`](config.md#scrim-config-schema) | Print the JSON Schema of the config file |
| [`scrim config show`](config.md#scrim-config-show) | Print configuration values and where each came from |
| [`scrim config validate`](config.md#scrim-config-validate) | Check the merged configuration without starting anything |
| [`scrim credential-helper`](credential-helper.md#scrim-credential-helper) | Credential helper for git, docker, AWS credential_process and kubectl exec; returns placeholders only |
| [`scrim database`](database.md#scrim-database) | List configured databases and run read-only queries by placeholder |
| [`scrim database ls`](database.md#scrim-database-ls) | List the configured databases and their local proxy endpoints (database_list) |
| [`scrim database query`](database.md#scrim-database-query) | Run one read-only statement (database_query) |
| [`scrim deny`](deny.md#scrim-deny) | Deny a pending approval |
| [`scrim deny-all`](deny-all.md#scrim-deny-all) | Break-glass: deny every injection, grant and approval while redaction continues |
| [`scrim doctor`](doctor.md#scrim-doctor) | Check the local setup and suggest a fix for each problem |
| [`scrim ebpf`](ebpf.md#scrim-ebpf) | Attach, detach and inspect the eBPF transparent mode (Linux, cgroup v2) |
| [`scrim ebpf attach`](ebpf.md#scrim-ebpf-attach) | Attach the programs to the control groups (privileged; replaces an existing attachment in place) |
| [`scrim ebpf detach`](ebpf.md#scrim-ebpf-detach) | Detach the programs from the control groups (privileged) |
| [`scrim ebpf status`](ebpf.md#scrim-ebpf-status) | Report each covered control group; only a process with CAP_NET_ADMIN can confirm one as active |
| [`scrim edge`](edge.md#scrim-edge) | Forward an agent pod's ssh-agent, database ports and agent API to a central scrim |
| [`scrim edge check`](edge.md#scrim-edge-check) | Check that the central scrim accepts this pod (for a startup probe) |
| [`scrim exec`](exec.md#scrim-exec) | Run an allowed command with a secret you never hold (secret_exec) |
| [`scrim grants`](grants.md#scrim-grants) | List and revoke just-in-time grants |
| [`scrim grants list`](grants.md#scrim-grants-list) | List active grants |
| [`scrim grants revoke`](grants.md#scrim-grants-revoke) | Revoke a grant at once |
| [`scrim hooks`](hooks.md#scrim-hooks) | Agent hooks that redact tool results and check prompts (installed by scrim install --hooks) |
| [`scrim hooks run`](hooks.md#scrim-hooks-run) | Handle one hook call: the agent's hook JSON on standard input, the answer on standard output |
| [`scrim install`](install.md#scrim-install) | Run scrim as a service: a systemd user unit, a hardened system unit, or a podman Quadlet container |
| [`scrim mcp`](mcp.md#scrim-mcp) | Serve the agent tools over MCP (stdio) |
| [`scrim policy`](policy.md#scrim-policy) | Check, evaluate and compile policy rules |
| [`scrim policy check`](policy.md#scrim-policy-check) | Validate a rules file (default: policy.rules-file) |
| [`scrim policy eval`](policy.md#scrim-policy-eval) | Evaluate one request against the rules and explain the decision |
| [`scrim policy snapshot`](policy.md#scrim-policy-snapshot) | Print the decision table the data plane receives |
| [`scrim profiles`](profiles.md#scrim-profiles) | List, show and test tool profiles for command-line tools |
| [`scrim profiles list`](profiles.md#scrim-profiles-list) | List tool profiles and whether scrim run applies them |
| [`scrim profiles show`](profiles.md#scrim-profiles-show) | Show a tool profile and what it generates for the current catalog |
| [`scrim profiles test`](profiles.md#scrim-profiles-test) | Check that installed tools read only the generated placeholder configuration |
| [`scrim project`](project.md#scrim-project) | Find secret values in project files and move them into a store |
| [`scrim project move`](project.md#scrim-project-move) | Move secret values from project files into a store, asking before each one |
| [`scrim project scan`](project.md#scrim-project-scan) | List the secret values in project files, by file, line and key; values are never printed |
| [`scrim proxy`](proxy.md#scrim-proxy) | Run the scrim daemon: LLM proxy, tool proxy, agent API and admin API |
| [`scrim run`](run.md#scrim-run) | Run an agent with its traffic through scrim |
| [`scrim secret`](secret.md#scrim-secret) | Work with secrets without seeing their values |
| [`scrim secret ask`](secret.md#scrim-secret-ask) | Ask a human to enter a value on the local entry page (secret_ask_human) |
| [`scrim secret capture`](secret.md#scrim-secret-capture) | Store a value a command prints without showing it (secret_capture) |
| [`scrim secret gen`](secret.md#scrim-secret-gen) | Generate a random value inside scrim and store it (secret_gen) |
| [`scrim secret grants`](secret.md#scrim-secret-grants) | List your active grants (grants_list) |
| [`scrim secret ls`](secret.md#scrim-secret-ls) | List the secrets you may use (secrets_list) |
| [`scrim secret put`](secret.md#scrim-secret-put) | Store a value read from standard input, never echoing it |
| [`scrim secret request`](secret.md#scrim-secret-request) | Ask for time-limited use of a secret (secret_request) |
| [`scrim secret status`](secret.md#scrim-secret-status) | Check an approval or an ask (approval_status) |
| [`scrim status`](status.md#scrim-status) | Report protections, interception, stores, state and weakened settings |
| [`scrim uninstall`](uninstall.md#scrim-uninstall) | Revert every change `scrim install` recorded |
| [`scrim version`](version.md#scrim-version) | Print the version |

## Global flags

Every command accepts these.

```text
      --admin-url string                              Address of the scrim admin API for operator commands:
                                                      unix:/path/to/socket or http(s)://host:port. Empty means
                                                      unix:$XDG_RUNTIME_DIR/scrim/admin.sock.
      --api-socket string                             Unix socket of the local agent API. Empty uses
                                                      $XDG_RUNTIME_DIR/scrim/api.sock.
      --approvals-listen string                       TCP address that serves only the decision-link endpoint, for
                                                      approvals.public-url to point at (usually through a TLS
                                                      reverse proxy). Empty means decision links are served on the
                                                      admin listener only.
      --approvals-timeout string                      How long an approval waits for a decision before it is
                                                      denied. A rule's approval.timeout overrides it. (default "2m0s")
      --catalog-environment string                    Catalog environment that selects per-environment references.
      --catalog-profile string                        Catalog profile (for example dev or prod) that selects
                                                      per-profile references.
      --config string                                 config file (default: first of
                                                      $XDG_CONFIG_HOME/scrim/config.yaml,
                                                      ~/.config/scrim/config.yaml, /etc/scrim/config.yaml)
      --edge-forwarder-api-socket string              Unix socket the forwarder serves the agent API on, the exec
                                                      broker included (point SCRIM_API_SOCKET at it). Empty serves
                                                      none.
      --edge-forwarder-ca-file string                 PEM file of the edge CA the central scrim's certificate must
                                                      chain to (never the interception CA). No system roots are
                                                      used. (default "/etc/scrim/edge-trust/scrim-edge-ca.pem")
      --edge-forwarder-central string                 host:port of the central scrim's edge listener (edge.listen).
      --edge-forwarder-client-cert-file string        PEM client certificate (chain) the forwarder presents to the
                                                      central scrim instead of a service account token, for a
                                                      central scrim with identity.client-certificates. Read again
                                                      for every connection, so a rotated certificate is used at
                                                      once. Needs edge-forwarder.client-key-file.
      --edge-forwarder-client-key-file string         PEM private key of edge-forwarder.client-cert-file. It stays
                                                      in the pod: the TLS handshake proves the forwarder holds it.
      --edge-forwarder-server-name string             Name the central scrim's certificate is verified for. Empty
                                                      takes the host of edge-forwarder.central.
      --edge-forwarder-ssh-agent-socket string        Unix socket the forwarder serves the ssh-agent on (point
                                                      SSH_AUTH_SOCK at it). Empty serves none.
      --edge-forwarder-token-file string              Projected service account token for scrim's audience, read
                                                      again for every connection and sent to the central scrim
                                                      only. (default "/var/run/secrets/scrim/token")
      --edge-listen string                            Address of the edge listener the forwarders in agent pods
                                                      connect to (TLS; callers present a Kubernetes service
                                                      account token). Empty turns it off. Needs
                                                      identity.kubernetes.enabled and edge.server-names.
      --events-backend string                         How replicas learn about state changes made elsewhere
                                                      (approval decisions, grant and session changes, break-glass,
                                                      configuration reloads). local reads the outbox every
                                                      events.poll-interval and serves one process; postgres adds
                                                      LISTEN/NOTIFY on the state database (needs state.backend
                                                      postgres); valkey and nats publish a wake-up on a Valkey
                                                      channel (valkey.*) or a NATS subject (nats.*). Every backend
                                                      delivers from the outbox, so a lost wake-up costs latency,
                                                      never an event. One of postgres, valkey or nats is required
                                                      when deployment.replicas is more than 1. (default "local")
      --log-format string                             Log record format: text (logfmt) or json, one object per
                                                      line. (default "text")
      --log-level string                              Minimum level of log records. (default "info")
      --metrics-enabled[=true|false]                  Serve Prometheus metrics (control plane and data plane) at
                                                      metrics.path on metrics.listen. Off: nothing is measured on
                                                      the request path and no metrics listener is bound.
      --metrics-listen string                         Address of the metrics and health endpoint (/healthz or
                                                      /livez, /readyz, and metrics.path while metrics.enabled).
                                                      Used when metrics.enabled is true; set explicitly with
                                                      metrics.enabled false it serves the health endpoints only.
                                                      Bind to loopback unless scraped remotely. (default
                                                      "127.0.0.1:9792")
      --policy-deny-all[=true|false]                  Break-glass: deny every injection, grant and approval while
                                                      redaction continues. While set in configuration it cannot be
                                                      released from the CLI.
      --policy-rules-file string                      Path of the policy rules file (YAML or JSON with default and
                                                      rules). Empty means no rules: every request gets policy.default.
      --profile local                                 Built-in preset of defaults for a deployment shape: local
                                                      for a laptop or VM, `k8s` for Kubernetes, `ci` for throwaway
                                                      runs. Any value a profile sets can be overridden. (default
                                                      "local")
      --proxy-capture-dir scrim proxy --capture=DIR   Capture mode: write every provider request exactly as it
                                                      left, and the response as received, to this directory (mode
                                                      0700; refused if group or others can access it). Empty
                                                      disables capture. scrim proxy --capture=DIR sets it.
      --proxy-forward-listen string                   TCP address of the forward proxy for agents with HTTPS_PROXY
                                                      set (scrim run sets it): provider hosts go to the LLM proxy,
                                                      every other host to the tool proxy with credential
                                                      injection. Empty disables it; keep it on loopback. (default
                                                      "127.0.0.1:9791")
      --proxy-forward-tls-listen string               TCP address of the forward proxy over TLS
                                                      (HTTPS_PROXY=https://<address>). Callers must present a
                                                      client certificate to the proxy
                                                      (identity.client-certificates). Empty disables it.
      --proxy-listen string                           TCP address of the LLM proxy base URL (agents use
                                                      http://<address>/anthropic and http://<address>/openai/v1).
                                                      Empty disables it; keep it on loopback. (default
                                                      "127.0.0.1:9790")
      --proxy-sni-listen string                       TCP address of the SNI listener for DNS override mode:
                                                      provider names resolve to its address (scrim install --dns
                                                      writes /etc/hosts entries and sets 127.0.83.1:443), it
                                                      serves certificates for them from the scrim CA and routes by
                                                      TLS server name. Connections made by address bypass it.
                                                      Empty disables it.
      --proxy-socket string                           Unix socket path for the LLM proxy base URL, for agents that
                                                      can connect to one. Empty disables it.
      --proxy-tls-listen string                       TCP address of the LLM proxy base URL over TLS
                                                      (https://<address>/anthropic and so on). Callers must
                                                      present a client certificate (identity.client-certificates).
                                                      Empty disables it.
      --proxy-transparent-listen string               TCP addresses of the transparent listener (Linux):
                                                      connections redirected to it by nftables are routed by TLS
                                                      server name or Host header, provider hosts to the LLM proxy,
                                                      bound tool hosts to the tool proxy. scrim install
                                                      --transparent sets 127.0.0.1:9793 and [::1]:9793 (9792 is
                                                      metrics.listen). Empty disables it. (default "[]")
      --ratelimit-backend string                      Where per-agent rate limits are counted. local counts in
                                                      each replica's memory, so with several replicas an agent can
                                                      get up to that many times each limit (approximate); valkey
                                                      counts in Valkey (valkey.*), one exact limit shared by every
                                                      replica. When the backend cannot answer, the request is
                                                      refused. (default "local")
      --redaction-binary string                       Images, PDFs and other binary parts of provider requests.
                                                      scan decodes each part and scans it and the text it carries
                                                      (image metadata, PDF text, SVG) with the redactor and the
                                                      guard, and refuses the request when it finds a secret value
                                                      or cannot decode the part within its bounds; block refuses
                                                      every request with a binary part; pass forwards them
                                                      unscanned and audits it. Parts referenced by URL are not
                                                      fetched or scanned. (default "scan")
      --restore-display-mode string                   What the agent displays for display-class values: values
                                                      resolves them in assistant text, placeholders keeps
                                                      placeholders (for example while screen sharing). Tool
                                                      arguments follow the tool roles either way; credentials are
                                                      never restored. (default "values")
      --run-allow-unredacted-start[=true|false]       Start the agent anyway when scrim cannot start, its data
                                                      plane is not ready or no session can be minted. The agent
                                                      then reaches providers directly and unredacted; scrim run
                                                      prints a warning.
      --run-fs-view string                            Session filesystem view for credential files at fixed home
                                                      paths: auto (a user and mount namespace where the host
                                                      allows it, the home mirror elsewhere), namespace (refuse to
                                                      start the agent without one), home (HOME points at a mirror
                                                      of the home directory without the real credential files) or
                                                      off. See docs/run.md. (default "auto")
      --run-mcp[=true|false]                          Register scrim mcp with the agent for this session (Claude
                                                      Code --mcp-config, Codex -c mcp_servers.scrim, OpenCode
                                                      OPENCODE_CONFIG_CONTENT). Nothing is written to the agent's
                                                      own configuration. (default true)
      --run-placeholder-env[=true|false]              Export each declared catalog placeholder that resolves for
                                                      the session as an environment variable of the same name
                                                      holding the placeholder, for example
                                                      SCRIM_ACME_KEY=SCRIM_ACME_KEY. (default true)
      --run-profiles auto                             Tool profiles scrim run applies: profile names, auto for
                                                      every profile at least one catalog entry fills (an entry
                                                      naming the profile in its tools list), or `none`. Profiles a
                                                      selected one requires are added. See docs/cli-tools.md.
                                                      (default "[\"auto\"]")
      --run-scan-interval string                      How often scrim run rescans the project files while the
                                                      agent runs and registers changed values; 0 scans once at
                                                      start. (default "10s")
      --run-scan-project[=true|false]                 Scan the agent's working directory for secret values in
                                                      project files (.env*, *.tfvars, application config, compose
                                                      files, .npmrc) and redact them from the session's first
                                                      request. scrim run refuses to start the agent when they
                                                      cannot be registered. (default true)
      --run-ssh-agent[=true|false]                    Point SSH_AUTH_SOCK at scrim's ssh-agent for the session:
                                                      ssh and git over ssh sign with the catalog's ssh_key
                                                      entries, decided and audited by scrim, and an inherited
                                                      agent with your own keys is not reachable through it.
                                                      (default true)
      --state-backend string                          State backend for approvals, grants, sessions and audit
                                                      metadata. The local profile uses sqlite
                                                      ($XDG_STATE_HOME/scrim/state.db); ci and k8s use memory,
                                                      which writes nothing to disk (set postgres for shared
                                                      state). (default "memory")
      --state-sqlite-path string                      SQLite state file. Empty means
                                                      $XDG_STATE_HOME/scrim/state.db (~/.local/state/scrim/state.db).
      --tool-proxy-listen string                      TCP address of the HTTPS tool proxy (credential injection
                                                      and response redaction) for tools pointed at it directly.
                                                      Empty disables it.
      --tool-proxy-tls-listen string                  TCP address of the HTTPS tool proxy over TLS. Callers must
                                                      present a client certificate to the proxy
                                                      (identity.client-certificates). Empty disables it.
      --tracing-endpoint string                       OTLP/HTTP collector URL for traces, for example
                                                      http://127.0.0.1:4318. Empty disables export; incoming W3C
                                                      trace context is still propagated.
```
