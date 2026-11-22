## Purpose

Credential injection lets an agent use a credential without holding it. The credential stays a
placeholder in the agent's commands and is swapped in only on outbound connections to the hosts it
is bound to.

## ADDED Requirements

### Requirement: Credentials are bound to destinations

Every credential SHALL declare the hosts it may be sent to, and MAY further restrict methods and
paths. A credential with no binding SHALL never be injected anywhere.

#### Scenario: Credential without binding

- **WHEN** a request carries the placeholder of a credential that has no destination binding
- **THEN** the request is refused and the audit log records the unbound credential

### Requirement: Injection only toward bound hosts

The HTTPS tool proxy SHALL replace a credential placeholder with the real value only on requests to
a host, method and path the credential is bound to, and SHALL refuse any request carrying that
placeholder to any other destination.

#### Scenario: Token sent to its own API

- **WHEN** an agent sends a request to `api.github.com` with the GitHub credential placeholder
- **THEN** the upstream receives the real token and the agent's command never contained it

#### Scenario: Token sent to another host

- **WHEN** an agent sends the GitHub credential placeholder to a host it is not bound to
- **THEN** the request is refused and nothing is sent to that host

### Requirement: Injection locations

Injection SHALL support placing the credential in a header, a query parameter or a body field, as
declared per credential, and SHALL refuse a request whose placeholder appears in a location the
credential does not declare.

#### Scenario: Placeholder in an undeclared location

- **WHEN** a placeholder for a header-only credential appears in the request body
- **THEN** the request is refused

### Requirement: Interception certificate authority

scrim SHALL generate its own certificate authority for TLS interception, keep its private key out
of agents' reach, support rotation with an overlap period, and export only the public certificate
for trust installation.

#### Scenario: CA rotation

- **WHEN** the CA is rotated
- **THEN** connections made with the previous CA keep working until the overlap period ends

#### Scenario: Client trusting only the previous CA

- **WHEN** a client that trusts only the previous CA connects during the overlap period
- **THEN** the handshake succeeds through a cross certificate, and fails once the overlap ends

#### Scenario: Chain builders that match key identifiers

- **WHEN** an OpenSSL-based client (curl, git, Python, Node.js) that trusts only the previous CA
  connects during the overlap period
- **THEN** the cross certificate's subject key identifier is the one the leaf's authority key
  identifier names, its authority key identifier names the previous CA, and the client accepts the
  chain

#### Scenario: Restart during an overlap

- **WHEN** scrim restarts while a rotation's overlap period is running
- **THEN** it uses the same current CA and keeps the previous one until the recorded end of the overlap

#### Scenario: Operator-supplied CA

- **WHEN** `tool-proxy.ca.cert-file` and `tool-proxy.ca.key` name an operator's CA certificate and key reference
- **THEN** scrim uses that CA, never rotates it, and warns before it expires

#### Scenario: CA key readable by others

- **WHEN** the generated CA's key file is readable by group or others
- **THEN** scrim refuses to use it and names the file, without printing its content

### Requirement: Private upstream roots

The data plane SHALL trust the system roots for upstream TLS, plus the roots of a PEM bundle named by
`dataplane.upstream-ca-file`, in the LLM proxy and the tool proxy alike, for API hosts with a private
CA and TLS-inspecting corporate proxies. A bundle that is set but unreadable, or holds no
certificate, SHALL stop the data plane from starting rather than leave the trust silently missing.

#### Scenario: Internal API host

- **WHEN** a credential is bound to a host whose certificate is issued by a private CA named in
  `dataplane.upstream-ca-file`
- **THEN** the tool proxy verifies the host against that CA and injects the credential

#### Scenario: Bundle missing

- **WHEN** `dataplane.upstream-ca-file` names a file that does not exist
- **THEN** the data plane does not start, so nothing is served

### Requirement: Pinned certificates fail closed

When a client refuses the interception certificate, scrim SHALL not fall back to passing the
connection through uninspected, and SHALL report the refusing destination in status and the audit
log.

#### Scenario: Client with certificate pinning

- **WHEN** a client pins the upstream certificate and rejects the interception certificate
- **THEN** the connection fails and the destination is listed as unsupported in status

### Requirement: Response capture

Capture rules SHALL store a configured field of a matching response (for example a newly created
token) into a configured store reference and replace it with that reference's placeholder before
the agent receives the response. If storing fails, the field SHALL be withheld.

#### Scenario: Creating an API token

- **WHEN** an agent's request matches a capture rule and the response contains a new token
- **THEN** the token is written to the configured store and the agent receives its placeholder

#### Scenario: Store write fails during capture

- **WHEN** the store write for a captured field fails
- **THEN** the agent receives the response with the field withheld and an error marker

### Requirement: Destination is the connection

The tool proxy SHALL check bindings against the host and port it actually connects to (the CONNECT
target or the absolute-form URI), SHALL refuse a request whose `Host` header, `:authority` or TLS
server name names a different host, and SHALL match path bindings after removing dot segments.

#### Scenario: Host header pointing elsewhere

- **WHEN** an agent opens a tunnel to a bound host and sends a request whose `Host` header names
  another host
- **THEN** the request is refused as misdirected and nothing is sent upstream

#### Scenario: Dot segments in the path

- **WHEN** a credential is bound to `/v1/*` and the agent requests `/v1/../admin` with its placeholder
- **THEN** the request is refused because the effective path is `/admin`

### Requirement: Plain HTTP injection is opt-in

A credential SHALL only be injected into plain `http://` requests when its binding explicitly allows
plain HTTP, a setting named for what it weakens.

#### Scenario: Bound host over plain HTTP

- **WHEN** an agent sends a credential placeholder to its bound host over `http://` and the binding
  does not allow plain HTTP
- **THEN** the request is refused as an unbound destination

### Requirement: Injection follows the decision table

After a credential's binding allows a request, the tool proxy SHALL decide the injection with the
decision table (`op` `inject`, with the credential's reference, name, store and class, the
destination host, method and path, and the caller) before anything is substituted. A deny SHALL
refuse the whole request with status 403 and code `policy_denied`. An ask SHALL hold the request for
the control plane's answer, bounded as every ask is, and the data plane SHALL NOT cache a grant.

#### Scenario: Deny rule on a bound host

- **WHEN** a credential is bound to `api.github.com` and a rule denies `op == "inject"` for `dest.path` `/admin`
- **THEN** a request to `https://api.github.com/admin` carrying its placeholder is refused with `policy_denied` and nothing is sent upstream

#### Scenario: Approval answered, then asked again

- **WHEN** an ask rule covers an injection and the control plane allows the first request
- **THEN** the first request is injected, and the next one is asked about again

#### Scenario: Approval times out

- **WHEN** an ask rule covers an injection and no answer arrives within the ask timeout
- **THEN** the request is refused with `policy_denied` and nothing is sent upstream

### Requirement: Injection works out of the box

The system SHALL ship a built-in rule, `builtin.inject-bound`, allowing `op == "inject"` for an
identified agent after the configured rules, so deny and ask rules still win. Injection is only
decided after the binding matched, so it allows exactly injection toward bound hosts.
`policy.builtin.inject` SHALL select allow (default), ask or off; the rule SHALL appear in the
compiled snapshot, and `builtin.` rule names SHALL be reserved.

#### Scenario: Default configuration

- **WHEN** `policy.default` is deny, no rule mentions `inject`, and a `scrim run` agent sends a request with a credential placeholder to a host the credential is bound to
- **THEN** the credential is injected, and the same request to an unbound host is refused

#### Scenario: Unknown caller

- **WHEN** a process without a session sends the same request through the forward proxy
- **THEN** the injection is refused with `policy_denied`

#### Scenario: Built-in rule switched off

- **WHEN** `policy.builtin.inject` is off and no rule allows `inject`
- **THEN** nothing is injected

### Requirement: Documented refusals

Every refusal and withheld response from the tool proxy SHALL carry a stable error code in an
`x-scrim-error` header and a JSON body, SHALL name credentials only by alias, and SHALL be recorded
in the audit log without any value.

#### Scenario: Agent reads the refusal

- **WHEN** a request is refused because its placeholder is not bound to the destination
- **THEN** the agent receives status 403 with code `unbound_destination` and the credential alias,
  and the audit entry names the alias and destination

#### Scenario: Signature not made with the placeholder

- **WHEN** a SigV4 request names a credential's placeholder access key id and is signed with another secret
- **THEN** the agent receives status 403 with code `signature_invalid` naming both credentials by alias

### Requirement: Unresolved placeholders are refused

A request toward a host with bound credentials that carries a placeholder no credential with a
value resolves (generated in any form the proxy reads, reference, or declared for a catalog
credential not loaded yet) SHALL be refused with 503 `credential_unavailable`, audited, and SHALL
send nothing upstream. Only the exact placeholder grammar SHALL count.

#### Scenario: Store not loaded yet

- **WHEN** a catalog credential bound to `api.acme.test` with placeholder `SCRIM_ACME_KEY` has no value yet and a tool sends `SCRIM_ACME_KEY` to `api.acme.test`
- **THEN** the request is refused with 503 `credential_unavailable` and audited
- **AND** nothing reaches `api.acme.test`, so the placeholder is never sent as text

#### Scenario: Unknown generated or reference placeholder

- **WHEN** a request toward a bound host carries `⟦scrim:<slug>:<code>⟧` (or its percent form) or `{{scrim:<ref>}}` that matches no credential with a value
- **THEN** it is refused with 503 `credential_unavailable` and nothing is sent

#### Scenario: Look-alike text passes

- **WHEN** a request toward a bound host carries text such as `⟦scrim:acme⟧`, `{{scrim:not a ref}}` or the word scrim
- **THEN** it is forwarded unchanged

### Requirement: Bodies too large to rewrite

Request bodies above the configured buffering limit SHALL be streamed unmodified and cut off if a
placeholder appears in them, and an encoded oversized body toward a host with bound credentials
SHALL be refused. The upstream's answer to a cut-off request SHALL not reach the agent.

#### Scenario: Placeholder in a large upload

- **WHEN** an agent uploads a body larger than the buffering limit with a placeholder near its end
- **THEN** the upload is cut off before the placeholder leaves scrim and the agent receives
  `body_too_large`

### Requirement: Protocol upgrades are refused

The tool proxy SHALL refuse protocol upgrades (for example WebSocket) because the upgraded stream
cannot be scanned.

#### Scenario: WebSocket handshake

- **WHEN** an agent sends a WebSocket upgrade request through the tool proxy
- **THEN** the request is refused with `upgrade_unsupported`

### Requirement: Exec broker

The exec broker SHALL run commands on an agent's behalf under a separate operating-system identity,
with requested secrets in the command's environment. Only commands on the secret's allow list SHALL
run; others SHALL be refused or sent for approval per policy.

#### Scenario: Allowed command

- **WHEN** an agent asks the broker to run `psql` with the database credential and `psql` is allowed
- **THEN** the command runs with the credential in its environment and the agent's process never holds it

#### Scenario: Command not on the allow list

- **WHEN** an agent asks the broker to run a command not on the secret's allow list
- **THEN** the broker refuses it or asks for approval, as the policy decides

### Requirement: Exec broker output is redacted

The exec broker SHALL redact known values and their encoded variants from command output before
returning it, and SHALL refuse to run commands that transform secret-bearing output (byte dumps,
encoders, reversers, character splitting) when they are applied to a secret.

#### Scenario: Attempt to base64 the environment

- **WHEN** an agent asks the broker to run a command that encodes the environment
- **THEN** the broker refuses it and the audit log records the blocked transform

### Requirement: SSH agent

scrim SHALL act as an SSH agent offering keys from configured stores. Agents SHALL be able to sign
with a key but never read it, and policy MAY require approval for each signature. `scrim run`
SHALL point the session's `SSH_AUTH_SOCK` at a socket that holds no key and forwards every request
to the control plane as the session, replacing an inherited agent.

#### Scenario: Git push over SSH with approval

- **WHEN** an agent's SSH client requests a signature with a key whose policy requires approval
- **THEN** the signature is produced only after a human approves, and refused on timeout

#### Scenario: Denied signature fails the push

- **WHEN** a human denies the approval for the signature of a `git push` over SSH
- **THEN** the agent answers SSH_AGENT_FAILURE, the push fails and the server is unchanged

#### Scenario: Session socket

- **WHEN** `scrim run` starts an agent with `run.ssh-agent` on
- **THEN** `SSH_AUTH_SOCK` names a socket in the session directory, readable by the user only, and
  the control plane sees each request as that session

### Requirement: SSH signatures are decided with what they sign

Each signature SHALL be decided by policy as operation `ssh.sign` with the key's catalog entry,
the session, and what the data says: an SSH login's user, an SSHSIG namespace, the key's
fingerprint, and the server's verified host key. Data that is neither a login nor an SSHSIG blob
SHALL be refused.

#### Scenario: Login to a named host

- **WHEN** an OpenSSH client binds to a server whose host key is listed as `git.example.com` in
  `ssh-agent.known-hosts` and asks to sign its login as `git`
- **THEN** rules see `ssh.user == "git"`, `ssh.host_key` and `dest.host == "git.example.com"`

#### Scenario: Login for another session

- **WHEN** the login to sign carries another session identifier than the connection's binding
- **THEN** the signature is refused before policy and the refusal is audited

#### Scenario: Arbitrary data

- **WHEN** a caller asks the agent to sign bytes that are not an SSH login or an SSHSIG blob
- **THEN** the signature is refused

### Requirement: SSH host keys come from verified bindings

The agent SHALL trust a server's host key only from a `session-bind@openssh.com` whose signature
over the session identifier verifies, and only for a login that carries that session identifier.
The host key SHALL get a name only from known_hosts files the operator configures.

#### Scenario: Unbound client

- **WHEN** a client that sends no session binding asks to sign a login
- **THEN** rules see an empty `ssh.host_key` and `dest.host`

### Requirement: SSH agent offers only what policy may allow

The agent SHALL list a key only when policy could allow or ask for a signature with it on that
connection, evaluating with the attributes a list cannot know (user, kind, namespace) unknown, and
SHALL list nothing while break-glass deny-all is on. Every signature SHALL still be decided on its
own.

#### Scenario: Key for another host

- **WHEN** the only rule for a key allows logins to `github.com` and the connection is bound to
  another host
- **THEN** the key is not listed

### Requirement: SSH agent cannot be changed or forwarded

The agent side SHALL NOT add, remove or replace keys, or lock or unlock the agent. A connection
bound with `is_forwarding` SHALL be refused for every list and signature.

#### Scenario: Agent forwarding

- **WHEN** a remote host reaches the agent through `ssh -A`
- **THEN** its binding is refused and so is every request on that connection

### Requirement: SSH signatures are audited

Every signature, allowed, denied or refused before policy, SHALL leave an audit entry with the
key's reference, the rule, the outcome and the parsed login or namespace and fingerprints. No
audit entry, error, log line or API response SHALL contain key material.

#### Scenario: Signature audit

- **WHEN** an agent signs a login as `git` through scrim's agent
- **THEN** the audit log records `ssh.sign` with the user, key and host key fingerprints and the
  rule that decided

### Requirement: Database auth proxies

scrim SHALL offer local PostgreSQL and MySQL endpoints that accept the agent's connection without a
password and authenticate to the real database with the bound credential. A connection to an
unbound database SHALL be refused.

#### Scenario: Agent connects to a database

- **WHEN** an agent connects to the local database endpoint for a configured database
- **THEN** the session is authenticated upstream and the agent never receives the password

### Requirement: Read-only database tool

scrim SHALL offer a read-only database tool that turns placeholders inside string literals into
bound parameters carrying real values, rejects writes and multiple statements, enforces row and
time limits, and returns results redacted.

#### Scenario: Query by placeholder

- **WHEN** an agent queries with a placeholder inside a string literal
- **THEN** the database receives the real value as a bound parameter, never as SQL text

#### Scenario: Write attempt

- **WHEN** an agent submits a data-modifying statement to the database tool
- **THEN** the statement is refused and not executed

### Requirement: Placeholder credentials for command-line tools

`scrim run` and the Kubernetes injection SHALL provision, per configured tool profile, the
environment variables and generated config files a CLI reads its credentials from (for example
`GH_TOKEN`, an AWS config, a kubeconfig, `.npmrc`, `.netrc`, a container registry auth file). They
SHALL contain placeholders only, and SHALL be removed when the session ends.

#### Scenario: gh with a placeholder token

- **WHEN** an agent started with `scrim run` runs `gh pr list`
- **THEN** `GH_TOKEN` holds a placeholder, the request to `api.github.com` carries the real token
- **AND** no file or environment variable in the agent's session contains the real token

#### Scenario: Generated kubeconfig

- **WHEN** the `kubectl` profile is enabled for a cluster credential
- **THEN** `KUBECONFIG` points at a generated file whose token is a placeholder and whose server
  traffic is injected by scrim

### Requirement: Built-in tool profiles

The system SHALL ship tool profiles for at least git, gh, glab, aws, gcloud, az, kubectl, helm,
terraform and OpenTofu, docker and podman registries, npm, pnpm, pip and twine, cargo, hcloud,
doctl, psql, mysql and ssh, each declaring where the tool reads credentials, which hosts it talks
to and which injection or proxy mode it needs. Profiles SHALL be overridable and extendable in
configuration.

#### Scenario: Custom profile

- **WHEN** configuration adds a profile for an in-house CLI reading `ACME_TOKEN` and calling
  `api.acme.internal`
- **THEN** that CLI works through scrim like a built-in profile

#### Scenario: Override a built-in profile

- **WHEN** configuration sets `tool-profiles.docker.params.username: robot`
- **THEN** the docker profile keeps its built-in variables and files and writes `robot` as the
  registry user name

### Requirement: Tool profile selection

`scrim run` SHALL apply the tool profiles `run.profiles` names, where `auto` (the default) stands for
every profile a resolved catalog credential fills by naming it in its tools list (`gh`, or
`aws.secret-access-key` for a slot other than the first) and `none` applies none, plus the profiles
they require. A profile whose required credential is not filled SHALL NOT be applied, and
`scrim run` SHALL name the missing catalog tools entry.

#### Scenario: Automatic selection

- **WHEN** the catalog maps `github` with `tools: [gh, git]` and nothing else names a profile
- **THEN** `scrim run` applies the gh and git profiles and no other

#### Scenario: Required credential missing

- **WHEN** an entry names `aws` and no entry names `aws.secret-access-key`
- **THEN** the aws profile is not applied and `scrim run` warns that no entry names
  `aws.secret-access-key`

### Requirement: Tool profiles stay within their tool

A tool profile SHALL NOT set or remove a variable `scrim run` owns (proxy, trust, session and
`SCRIM_` variables, `HOME`, `PATH`, `XDG_RUNTIME_DIR`). Two profiles setting one variable to
different values SHALL refuse the session. Profiles SHALL only be applied when the forward proxy
runs, because their placeholders are injected there.

#### Scenario: Profile sets a proxy variable

- **WHEN** a configured profile sets `HTTPS_PROXY`
- **THEN** the configuration is rejected naming the profile and the variable

### Requirement: Catalog entries take their tool profile's binding

A catalog credential that names a tool profile slot and declares no hosts SHALL be bound to the
hosts that slot declares, and its injection locations SHALL default to the slot's. One that declares
no placeholder SHALL get the declared placeholder `SCRIM_<NAME>` (its name upper-cased, other
characters as underscores), unique like any declared placeholder. `scrim catalog show` SHALL mark
the fields derived this way.

#### Scenario: Entry without hosts

- **WHEN** the catalog maps `github: {ref: bao://kv/agents/github#token, tools: [gh]}`
- **THEN** the credential is bound to `api.github.com`, `github.com` and `uploads.github.com`
- **AND** `GH_TOKEN` in the session holds `SCRIM_GITHUB`, which the tool proxy swaps for the token
  toward those hosts only

### Requirement: Testing tool profiles

`scrim profiles test` SHALL run each installed profile's test command with an empty home directory,
the profile applied with sample placeholders, and decoys placed at the tool's fixed credential paths
and in the variables the profile removes. It SHALL fail when the tool prints a decoy or not the
generated placeholder, and SHALL never read or send a real credential.

#### Scenario: Tool ignores its override variable

- **WHEN** a kubectl profile no longer sets `KUBECONFIG` and `~/.kube/config` holds a decoy
- **THEN** `scrim profiles test kubectl` fails, naming the decoy read

### Requirement: Re-signing for signed request protocols

For protocols where the client signs requests with the secret (AWS SigV4 first), the tool proxy
SHALL discard the client's signature made with the placeholder and re-sign the request with the real
credential toward bound endpoints only. A request that cannot be re-signed SHALL be refused.

#### Scenario: aws CLI with placeholder keys

- **WHEN** the agent runs `aws s3 ls` with placeholder access keys
- **THEN** scrim re-signs the request with the real keys and S3 accepts it
- **AND** a request signed for an unbound account or region is refused

#### Scenario: Caller identity against LocalStack

- **WHEN** the agent runs `aws sts get-caller-identity` with placeholder keys through the tool proxy toward a LocalStack endpoint the credentials are bound to
- **THEN** LocalStack sees the real access key id, and the agent sees its placeholder where the response names it

### Requirement: SigV4 requests are signed with the placeholder

An AWS secret access key credential SHALL name its access key id credential and MAY restrict
regions and services. A request whose SigV4 access key id is that credential's placeholder SHALL
use both credentials, with their bindings and injection decisions; its signature SHALL be verified
as sent with the secret's placeholders, refused with `signature_invalid` when none made it and with
`unbound_destination` for a region or service not allowed.

#### Scenario: Signed with another secret

- **WHEN** a request names the access key id placeholder but is signed with a secret that is not a placeholder of the bound secret
- **THEN** it is refused with `signature_invalid` and nothing is sent upstream

#### Scenario: Region not allowed

- **WHEN** a request signed with the placeholder keys names `eu-west-1` and the credential allows only `us-east-1`
- **THEN** it is refused with `unbound_destination` naming the region, and nothing is sent upstream

### Requirement: SigV4 forms and payloads

After substitution the tool proxy SHALL sign the request again with the real access key id and
secret, keeping the client's URI canonicalisation and payload mode, for the `Authorization`
header and presigned query forms, body hashes, `UNSIGNED-PAYLOAD` and a substituted session token.
Signed headers the proxy removes SHALL leave the signed header list.

#### Scenario: Presigned URL

- **WHEN** a presigned URL made with the placeholder keys is fetched through the tool proxy
- **THEN** the upstream receives it with the real access key id and a signature made with the real secret, and the same URL sent directly is refused by the upstream

#### Scenario: Body changed by substitution

- **WHEN** an S3 request with a body hash has a placeholder substituted in its body
- **THEN** `x-amz-content-sha256` and the signature cover the body as sent

### Requirement: Chunk-signed bodies are re-chained

For a chunk-signed body (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, with or without a signed trailer),
the tool proxy SHALL verify every chunk and trailer signature against the placeholder chain and
replace it with the real chain, buffered or streamed, and SHALL refuse a placeholder inside a
chunk-signed or `aws-chunked` body.

#### Scenario: Chunk-signed upload

- **WHEN** an upload with a chunk-signed body larger than the buffering limit is sent through the tool proxy
- **THEN** every chunk and trailer signature the upstream receives chains from the real seed signature, and a chunk signed with another secret cuts the upload off

### Requirement: Signing credentials are never sent as text

A secret access key with `aws_sigv4` and a client certificate credential SHALL only be used by
the tool proxy, never substituted into a request as text.

#### Scenario: Secret placeholder sent as text

- **WHEN** a request carries the secret access key's placeholder in a header
- **THEN** it is refused with `undeclared_location`

### Requirement: Format-preserving placeholders

A credential MAY be configured to use a placeholder that keeps the real secret's prefix, length and
alphabet, for clients that validate a token's shape before sending it. Format-preserving
placeholders SHALL still be unique, deterministic and recognised by the redactor and the guard
(redaction spec "Format-preserving placeholders"), and the tool proxy SHALL treat them exactly like
any other placeholder of the credential.

#### Scenario: Client that checks the token prefix

- **WHEN** a CLI rejects tokens that do not start with `ghp_`
- **THEN** the format-preserving placeholder starts with `ghp_` and the CLI sends it

#### Scenario: Shaped placeholder toward another host

- **WHEN** a client sends a credential's format-preserving placeholder to a host the credential is not bound to
- **THEN** the request is refused with `unbound_destination`, as for any placeholder

### Requirement: Client certificates toward upstreams

When an upstream authenticates clients with certificates (for example a Kubernetes API server or a
database requiring mTLS), scrim SHALL present the client certificate from the store on the upstream
connection. The private key SHALL never be written to the agent's filesystem.

#### Scenario: kubectl with certificate authentication

- **WHEN** a cluster credential is a client certificate and key stored in a store
- **THEN** kubectl reaches the API server through scrim, which presents the certificate upstream

#### Scenario: Placeholder certificate in a kubeconfig

- **WHEN** kubectl's kubeconfig holds the placeholder certificate and key, the scrim CA and the tool proxy as `proxy-url`, and the cluster's admin certificate is the credential bound to the API server
- **THEN** `kubectl get nodes` succeeds as the admin, and the kubeconfig holds no part of the real key

### Requirement: Placeholder client certificates

The agent's configuration SHALL hold a placeholder certificate: a self-signed certificate over an
Ed25519 key whose seed is `SHA-256("scrim-placeholder-cert-v1" || 0x00 || placeholder)` for one of
the credential's placeholder strings. Only on a tunnel toward a host a client certificate
credential is bound to SHALL the tool proxy ask the agent for a client certificate, never
requiring one.

#### Scenario: Host without a certificate credential

- **WHEN** a client holding a placeholder certificate opens a tunnel to a host no client certificate credential is bound to
- **THEN** the proxy does not ask for a certificate and the request is handled as usual

### Requirement: Client certificate use follows bindings

A request on a connection that presented a credential's placeholder certificate SHALL count as
using that credential: its binding and the injection decision apply, and the real certificate
SHALL be presented upstream on a connection used for that certificate only. Without the
placeholder certificate no client certificate SHALL be presented upstream.

#### Scenario: Another certificate

- **WHEN** the agent presents a certificate that is no credential's placeholder certificate
- **THEN** nothing is presented upstream and the API server sees an anonymous client

#### Scenario: Path outside the binding

- **WHEN** a request on a connection with the placeholder certificate goes to a path the credential is not bound to
- **THEN** it is refused with `unbound_destination` and nothing is sent upstream

### Requirement: Edge forwarder for local sockets

Where scrim runs centrally, an edge component in the agent's pod or host SHALL expose the local
endpoints tools expect (the ssh-agent socket, database ports on localhost, the exec broker) and
forward them to the central instance over an authenticated, encrypted channel. The edge SHALL hold
no secret values.

#### Scenario: ssh in a pod with central scrim

- **WHEN** an agent pod runs `git push` over SSH and scrim runs as a central deployment
- **THEN** the edge forwarder provides `SSH_AUTH_SOCK` in the pod and signatures are made by the
  central instance

### Requirement: Environment overrides before file tricks

A tool profile SHALL point the tool at its generated placeholder config through the tool's own
override variable when one exists (for example `AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG`,
`DOCKER_CONFIG`, `GH_CONFIG_DIR`, `NPM_CONFIG_USERCONFIG`, `PGPASSFILE`, `TF_CLI_CONFIG_FILE`,
`CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR`), and SHALL use a filesystem view only for tools without one.

#### Scenario: Tool with an override variable

- **WHEN** the docker profile is enabled
- **THEN** `DOCKER_CONFIG` points at a generated directory whose auth entries are placeholders

#### Scenario: Inherited credential variable

- **WHEN** the caller's environment holds `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY` with a real
  value and the gh or aws profile is applied
- **THEN** the variable is removed from the agent's environment, and the tool reads the placeholder
  from the profile's variable or generated file

### Requirement: Session filesystem view for fixed paths

On Linux, `scrim run` SHALL be able to start the agent in an unprivileged user and mount namespace
where configured credential paths (the applied tool profiles' fixed paths such as
`~/.aws/credentials`, and `run.fs-view-hide` such as `~/.ssh/id_*`), in `$HOME` and in the
password-database home, show placeholder versions or are hidden, and the rest of the home stays as
it is. The real files SHALL not be readable from the session.

#### Scenario: Tool that ignores environment overrides

- **WHEN** a tool reads `~/.aws/credentials` directly from the home directory in the password
  database
- **THEN** inside the session it reads the placeholder version and its requests are injected

#### Scenario: Real file hidden

- **WHEN** the agent runs `cat ~/.ssh/id_ed25519` inside the session
- **THEN** the file is absent or unreadable and the agent is pointed at `SSH_AUTH_SOCK`

### Requirement: Filesystem view integrity

A hidden path SHALL be an empty, unreadable, read-only file or directory. The agent SHALL run with
no capabilities, so it cannot unmount the view. If any part of the view cannot be set up, `scrim
run` SHALL refuse to start the agent (exit 125) rather than start it with a partial view.

#### Scenario: Agent tries to remove the view

- **WHEN** the agent unmounts `~/.aws/credentials`, directly or from a user namespace of its own
- **THEN** the unmount fails and the path still shows the placeholder version

#### Scenario: View cannot be set up

- **WHEN** a mount of the view fails, or the helper that sets it up does not run
- **THEN** `scrim run` exits 125 and the agent is not started

### Requirement: Filesystem view selection

`run.fs-view` SHALL select `auto` (the default: the namespace where the host allows it, the fallback
elsewhere), `namespace` (refuse to start the agent when the host has no unprivileged user
namespaces), `home` (the fallback) or `off`. A session with no configured path present SHALL start
without a namespace.

#### Scenario: Namespace required on a host without one

- **WHEN** `run.fs-view` is `namespace` and the host forbids unprivileged user namespaces
- **THEN** `scrim run` refuses to start the agent, naming the reason, and `scrim doctor` fails the
  `run-fs-view` check

### Requirement: Filesystem view fallback without namespaces

Where mount namespaces are unavailable (macOS, restricted containers), scrim SHALL fall back to a
session home directory that mirrors the real one except configured credential paths, and SHALL
report in status which tools may still read the real files because they bypass `HOME`.

#### Scenario: macOS session

- **WHEN** `scrim run` starts an agent on macOS
- **THEN** `HOME` points at the session directory and `scrim status` lists the fallback and its gaps

### Requirement: Session home mirror

The session home SHALL link every other entry to the real home, so the agent's writes there land in
the real files, and SHALL move the XDG base directory variables that point into the real home along
with `HOME`. `scrim run` SHALL print the fallback and its gaps before the agent starts, and `scrim
doctor` SHALL warn about it with the fix.

#### Scenario: Linux host without user namespaces

- **WHEN** `scrim run` starts an agent on a Linux host whose AppArmor policy forbids unprivileged
  user namespaces, with `run.fs-view` left at `auto`
- **THEN** the agent gets the session home, `scrim status` names the reason, and `scrim doctor`
  warns with the sysctl or profile that allows the namespace view

### Requirement: Credential helpers

The system SHALL provide credential helpers for tools that support them (git credential helper,
docker credential helper, AWS `credential_process`, kubectl exec plugin) returning placeholders by
default, or short-lived scoped credentials only where policy allows it and with the grant recorded.
A helper SHALL answer only from what the session's tool profiles generated, SHALL NOT read a store or
the home directory's credential files, and SHALL NOT store a credential a tool hands it.

#### Scenario: git asks its credential helper

- **WHEN** git pushes over HTTPS and calls the scrim credential helper
- **THEN** the helper returns a placeholder and the push succeeds through the tool proxy

#### Scenario: docker login with a typed password

- **WHEN** a client whose registry configuration names the scrim docker credential helper asks it to
  store a credential other than the placeholder it returns
- **THEN** the helper refuses and nothing is stored

#### Scenario: kubectl exec plugin

- **WHEN** the kubectl profile's helper is on and kubectl calls the API server
- **THEN** the exec plugin returns an ExecCredential holding the placeholder, the kubeconfig holds no
  token, and the request is injected toward the bound host

#### Scenario: AWS credential_process

- **WHEN** the aws profile's helper is on
- **THEN** the AWS CLI obtains placeholder keys from scrim's `credential_process` and the generated
  credentials file holds none

#### Scenario: Helper outside a session

- **WHEN** the docker credential helper runs without a session's generated configuration
- **THEN** it knows no credentials and returns none, even if the home directory holds a docker
  configuration with real ones

### Requirement: Tools that print their own credentials

Commands that print stored credentials (for example `aws configure get`, `gh auth token`,
`kubectl config view --raw`, docker credential helpers called directly) SHALL only ever print
placeholders inside a session, and any real value they emit SHALL be redacted from tool output.

#### Scenario: Agent asks gh for its token

- **WHEN** the agent runs `gh auth token`
- **THEN** the output is a placeholder

### Requirement: Secrets in project files

The system SHALL scan the session's working directory for secret values in files such as `.env*`,
`*.tfvars` and application config, register what it finds as known values for redaction, watch those
files for changes, and offer to move each value into a configured store and replace it in the file
with a reference. Nothing is moved or rewritten without confirmation.

#### Scenario: Unregistered secret in .env

- **WHEN** a project's `.env` contains an API key that no store holds
- **THEN** scrim redacts it from LLM traffic from the start of the session
- **AND** `scrim doctor` lists it with an offer to move it into a store

#### Scenario: Value written while the agent runs

- **WHEN** the agent or the user adds a secret value to a project file during the session
- **THEN** the rescan registers it and later requests carry its placeholder

#### Scenario: Move only after confirmation

- **WHEN** the user runs `scrim project move` and answers no
- **THEN** the store and the file are unchanged
- **AND** after a yes the value is written to the store and the file holds a `{{scrim:<ref>}}`
  reference in its place

### Requirement: Project values in force before the first request

Values found in project files SHALL be in force in the data plane before the agent's first request,
SHALL be redacted and never injected, and SHALL leave the redaction set when the session ends. If
they cannot be registered, `scrim run` SHALL NOT start the agent.

#### Scenario: Registration fails

- **WHEN** the values found in project files cannot be added to the redaction set
- **THEN** `scrim run` refuses to start the agent

#### Scenario: Session ends

- **WHEN** the session that registered project values ends or is swept
- **THEN** the values are wiped and the next snapshot no longer holds them

### Requirement: User-declared placeholders

Users SHALL be able to declare their own placeholder strings (for example `SCRIM_GITHUB_TOKEN` or
`{{scrim:bao://kv/agents/github#token}}`) and map each to a secret reference and its bound hosts, so
hand-written config files can carry readable placeholders. Declared placeholders SHALL be substituted
on the wire exactly like generated ones and SHALL be unique across the configuration.

#### Scenario: Placeholder written into a config file

- **WHEN** `config/app.yaml` contains `api_key: SCRIM_ACME_KEY` and a tool sends it to the bound host
- **THEN** the request leaves scrim with the real key in place of `SCRIM_ACME_KEY`
- **AND** the tool and the agent behave as if the real key were configured

#### Scenario: Duplicate declaration

- **WHEN** two secrets declare the same placeholder string
- **THEN** configuration validation fails and names both

### Requirement: Substitution in any declared part of the request

For a credential whose configuration allows it, the tool proxy SHALL substitute its placeholder
anywhere in the request (URL, headers, cookies, form, JSON or multipart body), decompressing and
recompressing bodies, recomputing lengths and content digests, and re-signing where the protocol
requires. A body it cannot rewrite safely SHALL be refused, never sent with the placeholder replaced
partially.

#### Scenario: Gzip-compressed JSON body

- **WHEN** a tool uploads a gzip-compressed JSON document containing a placeholder to its bound host
- **THEN** the upstream receives a valid gzip body with the real value and a correct length

#### Scenario: Unsupported body encoding

- **WHEN** the placeholder sits inside a body encoding scrim cannot rewrite
- **THEN** the request is refused with an error naming the encoding

### Requirement: Tool proxy responses are redacted

Every response returned through the tool proxy SHALL be scanned for known values in headers and
bodies, including streamed and compressed bodies, and each value SHALL be replaced with its
placeholder before the agent receives it, so an API that echoes a credential back shows the agent
the same placeholder it sent. A response that cannot be scanned SHALL be withheld.

#### Scenario: API echoes the credential

- **WHEN** an API's error message repeats the Authorization header it received
- **THEN** the agent sees the placeholder in the error, not the real token

#### Scenario: Created resource returns its secret

- **WHEN** a tool creates a webhook whose response includes the signing secret already held in a store
- **THEN** the agent receives the placeholder for that secret

#### Scenario: Echo of a declared placeholder

- **WHEN** an agent sends `SCRIM_ACME_KEY` and the API echoes the injected key back
- **THEN** the agent sees `SCRIM_ACME_KEY`, the placeholder it sent

#### Scenario: Captured token returned again

- **WHEN** a capture rule stored a token and a later response from any host contains the same token
- **THEN** the agent receives its placeholder, even before the next snapshot includes the value
