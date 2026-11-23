# ssh-agent

`scrim run` gives the agent an ssh-agent of scrim's own. ssh, git over SSH and `ssh-keygen -Y sign`
use it like any agent, but the keys live in your stores and never leave scrim: the agent side gets
public keys and signatures. Every signature is a policy decision (op `ssh.sign`) that can allow,
deny or ask a human, and every one is audited.

Spec: `openspec/changes/scrim-v1/specs/credential-injection` ("SSH agent" and the requirements
after it). Code: `internal/sshagent` (protocol), `internal/sshkeys` (keys, policy, signing),
`internal/run/sshagent.go` (the session socket).

## How it fits together

```text
ssh / git ──▶ SSH_AUTH_SOCK ──▶ scrim run ──────────▶ scrim (control plane)
             <session>/        agent protocol,       POST /v1/ssh/keys, /v1/ssh/sign as the session:
             ssh-agent.sock    session bindings      catalog ssh_key entries, store read,
                               no keys               policy gate, approval, audit, signing
```

1. `scrim run` listens on `ssh-agent.sock` in the session directory (mode 0600, this user only)
   and sets `SSH_AUTH_SOCK` to it. An inherited `SSH_AUTH_SOCK` is replaced, with a notice: your own
   agent holds your own keys, and the session should not sign with them behind scrim's back.
2. The socket speaks the agent protocol and holds no key. It forwards each list and sign request
   to the local agent API with the session token, so the control plane knows which session asks.
3. The control plane reads the key from its store, decides through the same gate as every other
   operation, signs, and drops the parsed key.

The filesystem view already hides `~/.ssh/id_*` from the session (`run.fs-view-hide`), so an agent
that runs ssh finds no key file and uses scrim's agent.

## Keys

A key is a catalog entry with `ssh_key: true` whose value is an SSH private key: OpenSSH or PEM,
ed25519, ECDSA or RSA, without a passphrase (the store protects it).

```yaml
catalog:
  entries:
    deploy:
      ref: bao://kv/agents/deploy#private_key
      ssh_key: true
    signing:
      ref: bao://kv/agents/signing#private_key
      ssh_key: true
      ssh_certificate: bao://kv/agents/signing#certificate   # optional OpenSSH certificate
```

Store the key with your store's own tools, or let an agent create one it can never read back
(`scrim secret put`, `secret_capture`). An `ssh_key` takes no `hosts` or `inject`: it is signed
with, never injected. Its value is still in the redaction set, so a key that turns up in a tool
result reaches the model as a placeholder.

The comment the agent lists is `scrim:<entry name>`. With a certificate the agent lists the key and
the certificate.

## Policy

Rules see `op == "ssh.sign"`, the key's catalog entry (`secret.name`, `secret.ref`,
`secret.labels`), the session (`agent.*`), `tool.name == "ssh"`, and what scrim parsed from the
data to sign:

| Field | Meaning |
| --- | --- |
| `ssh.kind` | `userauth` (an SSH login), `sshsig` (`ssh-keygen -Y sign`, git commit signing), `list` while deciding which keys to offer |
| `ssh.user` | The login's user name, `git` for GitHub, GitLab and most git servers |
| `ssh.namespace` | The SSHSIG namespace: `git` for commit signing, `file` for files |
| `ssh.key` | SHA256 fingerprint of the signing key |
| `ssh.host_key` | SHA256 fingerprint of the server's host key, from a verified session binding; empty without one |
| `dest.host` | The server's name, when its host key is listed in `ssh-agent.known-hosts` |

```yaml
rules:
  - name: git-over-ssh
    decision: ask
    when: >-
      op == "ssh.sign" && secret.name == "deploy" && ssh.kind == "userauth" &&
      ssh.user == "git" && dest.host == "github.com"
    grant: {ttl: 15m, scope: host}
  - name: commit-signing
    decision: allow
    when: op == "ssh.sign" && secret.name == "signing" && ssh.kind == "sshsig" && ssh.namespace == "git"
```

Data that is neither an SSH login nor an SSHSIG blob is refused before policy is asked: scrim's
agent is not a general signing oracle.

### Which host a login is for

OpenSSH 8.9 and later send `session-bind@openssh.com` before they authenticate: the server's host
key, the session identifier and the host key's signature over it. scrim verifies the signature and
checks that the login it is asked to sign carries that session identifier (and, with the
`publickey-hostbound` method, that host key). A signature made this way only authenticates to the
server holding that host key, so `ssh.host_key` is the server the signature is for.

The host key becomes a name only through `ssh-agent.known-hosts`, a list of known_hosts files you
control:

```yaml
ssh-agent:
  known-hosts: [/etc/scrim/ssh_known_hosts]
```

The first plain host name on the line listing the key is `dest.host` (`[host]:port` is written
`host:port`); hashed and wildcard entries are skipped and a `@revoked` line names nothing. Do not
point this at `~/.ssh/known_hosts`: the agent can write there, and a line it adds would give another
server a trusted name. Without the setting, or for a key no file lists, `dest.host` is empty and
rules can still match `ssh.host_key`.

A client that sends no binding (older OpenSSH, Go's `x/crypto/ssh`, some libraries) gets an empty
`ssh.host_key` and `dest.host`, so rules that name a host do not match it.

### Which keys are listed

When the client lists keys, the user and the kind of signature are not known yet. A key is listed
when some request could be allowed or asked for: rules are evaluated with `ssh.user`, `ssh.kind`
and `ssh.namespace` unknown, an allow or ask rule that depends on them counts as matching, and a
deny rule that depends on them does not. The host is known, since OpenSSH binds before it lists.
Listing decides what to offer, not what to sign: each signature is decided again with everything
known. Break-glass deny-all lists nothing.

### Approvals

An ask rule holds the signature until a human answers (`scrim approve`, a notifier link); ssh waits.
A timeout or a denial fails the signature, and ssh reports `Permission denied (publickey)`.
`scrim approvals list` shows what the signature is for, for example
`ssh login git@github.com`.

Approving creates a grant, as for every ask ([approvals.md](approvals.md)), so later signatures
for the same key and host go through until it expires. To approve each signature on its own, give
the rule `grant: {scope: once}`.

## What the agent side cannot do

- Add, remove or replace keys, or lock and unlock the agent: those requests fail.
- Use a forwarded agent. A connection that binds with `is_forwarding` comes from a remote host
  through `ssh -A`; it is refused, and every list and signature on it after that.
- Read a key. The local API has no route that returns one; errors and audit entries name the
  catalog entry and fingerprints, never key material.
- Sign as another session: the socket presents its own session's token, and the control plane
  checks it belongs to this process tree.

## Audit

Every signature leaves a `decision` entry with `action: ssh.sign`, the key's reference, the rule,
the outcome and `ssh_kind`, `ssh_user`, `ssh_namespace`, `ssh_key` and `ssh_host_key`; its target
is `dest.host` or `ssh`. Requests refused before policy (unparseable data, a binding mismatch, a
forwarded channel, a key scrim does not hold) are recorded with rule `ssh-agent` and the reason.

## Limitations

- An `IdentityAgent` or `IdentityFile` in the user's `~/.ssh/config` takes precedence over
  `SSH_AUTH_SOCK`. The wrapper cannot stop an agent that talks to another agent socket it finds;
  the filesystem view hides key files, not other agents' sockets.
- Keys come from the catalog of the daemon's own selection; catalog variants by agent or namespace
  are not applied to ssh keys yet.
- Parsed RSA and ECDSA keys live in Go big integers for the length of one request and cannot be
  wiped; ed25519 keys are wiped after use.
- Encrypted (passphrase-protected) keys and security keys (`sk-*`) are not supported.
- Agent pods in Kubernetes get the socket from the edge forwarder, which carries each connection to the
  central scrim ([edge-forwarder.md](edge-forwarder.md)); the keyring and policy are the same.

## Tests

- `internal/sshagent`: the protocol against `x/crypto/ssh/agent`'s client, refused add, remove,
  lock and unlock, session bindings that do not verify, forwarded connections, and a login to an
  `x/crypto/ssh` server through the agent; the parser on logins, hostbound logins, SSHSIG blobs and
  malformed data.
- `internal/sshkeys`: listing by policy, signatures allowed, denied and refused, per-signature and
  grant-window approvals, ed25519, ECDSA, RSA with SHA-2 and a certificate, an encrypted key not
  offered, every outcome audited, and no key material in any audit entry or error.
- `internal/run`: `SSH_AUTH_SOCK` in the plan, and the session socket answering as the session.
- `TestSSHAgentGitOverSSH` (`internal/daemon`): a throwaway sshd with a bare repository in rootless
  podman, a daemon whose only copy of the key is an environment store, and real `git` and OpenSSH.
  Clone and push succeed after approval, a denied signature fails the push and the server keeps
  the first commit, and the key appears in no output, log or audit entry. It runs in CI with
  `SCRIM_TEST_PODMAN=1` (job `ssh-agent`) and skips locally without podman.
