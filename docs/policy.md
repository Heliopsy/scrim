# Policy rules

Every time an agent uses, requests, creates or captures a secret, scrim asks the policy whether it
may. The answer is `allow`, `deny` or `ask`. Ask holds the operation until a human approves it (see
[approvals.md](approvals.md)) or a just-in-time grant covers it.

Rules are written in [CEL](https://cel.dev), the Common Expression Language. Redaction is not
governed by policy: provider requests are always redacted, whatever the rules say.

## Where rules live

Rules are in their own file, named by `policy.rules-file` (`SCRIM_POLICY_RULES_FILE`,
`--policy-rules-file`). YAML or JSON; unknown keys are an error, so a misspelt `when` cannot silently
turn a rule into "match everything".

```yaml
default: deny          # optional; falls back to policy.default, which ships as deny
rules:
  - name: github-read
    decision: allow
    when: secret.ref == "bao://kv/agents/github" && dest.method in ["GET", "HEAD"]

  - name: github-write
    decision: ask
    when: secret.ref == "bao://kv/agents/github" && !(dest.method in ["GET", "HEAD"])
    reason: Writes to GitHub need a human
    approval:
      timeout: 5m          # overrides approvals.timeout
      notifiers: [ntfy]    # default: every configured notifier
    grant:
      ttl: 30m             # grant created on approval
      max_ttl: 2h          # an approver cannot ask for more
      uses: 20             # 0 means unlimited within the ttl
      scope: host          # request (default), host or secret
```

Check a file before deploying it:

```sh
scrim policy check policy.yaml
scrim policy eval policy.yaml --agent claude-laptop --op inject \
  --ref bao://kv/agents/github --host api.github.com --method POST
scrim policy snapshot policy.yaml     # the table the data plane receives
```

A configuration whose rules do not compile is refused at start-up. On reload, a broken file keeps
the previous rules in force and the error shows in health status.

## What a rule can see

| Variable | Type | Fields |
| --- | --- | --- |
| `op` | string | `llm.forward`, `inject`, `restore`, `store.read`, `store.write`, `secret.gen`, `grant`, `exec`, `mcp.tool`, `secret.ask`, `ssh.sign`, `database.auth` |
| `agent` | object | `id`, `kind` (`peer`, `session`, `k8s`, `mtls`, empty when unknown), `known` (bool), `session`, `labels` (map) |
| `secret` | object | `ref`, `name` (catalog name), `store`, `class`, `labels` (map) |
| `provider` | string | `anthropic`, `openai`, ... |
| `dest` | object | `host`, `method`, `path` |
| `tool` | object | `name`, `command` |
| `now` | timestamp | request time |

Agent attributes come from the transport (socket peer, session token, service account token,
certificate), never from request content. Identity sources put what they know into `agent.labels`
under these keys: `namespace`, `service_account`, `pod`, `user`, `uid`, `spiffe_id`, `profile`.

Fields that do not apply are empty strings, and an empty `secret.ref` means the request touches no
secret.

### Functions

Everything in CEL's standard library and its strings extension, plus `glob`:

| Pattern | Matches |
| --- | --- |
| `*` | any run of characters except `/` |
| `**` | any run of characters including `/` |
| `?` | one character except `/` |
| `\x` | the literal `x` |

```cel
secret.ref.glob("bao://kv/prod/*")        // bao://kv/prod/db, not bao://kv/prod/eu/db
secret.ref.glob("bao://kv/prod/**")       // anything below prod
dest.host.glob("*.github.com")            // api.github.com, not github.com
```

## How rules combine

1. Every rule is evaluated; a rule without `when` matches everything.
2. Among the rules that match, **deny wins over ask, and ask over allow**.
3. Within the winning decision, the **first rule in the file** is the one reported in audit and
   whose `approval` and `grant` settings apply.
4. When nothing matches, `default` applies; without one, `policy.default` (deny).

Order therefore never lets a later allow override an earlier deny, but it does choose which of
several asks sets the timeout and grant.

A rule that fails on a request, typically by reading a label the agent does not have, counts as
matching if it denies or asks, and as not matching if it allows. Errors can only make a decision
stricter. Use `has()` or `in` when a label is optional:

```cel
has(agent.labels.team) && agent.labels.team == "infra"
"team" in agent.labels && agent.labels.team == "infra"
agent.labels.?team.orValue("") == "infra"
```

Break-glass deny-all (`scrim deny-all on`, or `policy.deny-all: true`) overrides every rule. See
[approvals.md](approvals.md#break-glass-deny-all).

## Examples

Only the deploy namespace may touch production:

```yaml
- name: prod-only-deploy
  decision: deny
  when: secret.ref.glob("bao://kv/prod/**") && agent.labels.namespace != "deploy"
```

Unknown callers get nothing but redaction:

```yaml
- name: no-unknown
  decision: deny
  when: "!agent.known"
```

Read-only Hetzner for one agent, writes need a human and leave a 30 minute grant:

```yaml
- name: hetzner-read
  decision: allow
  when: agent.id == "codex" && secret.ref == "bao://kv/agents/hetzner" && dest.method == "GET"
- name: hetzner-write
  decision: ask
  when: agent.id == "codex" && secret.ref == "bao://kv/agents/hetzner" && dest.method != "GET"
  grant: {ttl: 30m, scope: host}
```

Agents may create secrets, but only under their own prefix, and never at night:

```yaml
- name: own-prefix
  decision: allow
  when: op in ["store.write", "secret.gen"] && secret.ref.startsWith("bao://kv/agents/" + agent.id + "/")
- name: no-night-writes
  decision: deny
  when: op == "store.write" && now.getHours("Europe/Berlin") < 6
```

Allow with a duration: the first allowed read leaves a grant behind, visible in `scrim grants list`
and revocable like any other:

```yaml
- name: catalog-reads
  decision: allow
  when: op == "store.read" && secret.class == "display"
  grant: {ttl: 1h}
```

## How the data plane decides

The data plane handles every byte of agent traffic and does not run CEL (design D7). The control
plane compiles each rule into a decision table: alternatives (`||`) of conjunctions (`&&`) of simple
conditions on the fields above, with negation pushed down. A condition is one of equality or `in`,
`startsWith`, `endsWith`, `contains`, `glob`, and `has()` or `in` on a label map, against a literal.

Anything else is **residual**: `now`, `matches` (regular expressions), string functions such as
`lowerAscii`, comparing two fields, optional values, list macros, and rules that would expand past
64 alternatives. A residual part does not make the whole rule slow. The data plane evaluates the
parts it can; when they already rule the rule out, the residual part is never needed.

The data plane decides on its own only when its answer is certain to be the control plane's, same
decision and same rule. Otherwise it asks the control plane, which evaluates the full rules:

| Data plane outcome | When |
| --- | --- |
| deny | the first deny rule that could match does match, or deny-all is set |
| allow | no deny or ask rule can match, the first allow rule that could match does, and it has no grant ttl |
| ask the control plane | an ask rule matches, a residual rule could decide, or an allow rule with a grant ttl decides |

`scrim policy check` reports how many rules the data plane decides entirely on its own, and
`scrim policy eval` shows both answers. If a residual rule sits high in the precedence order (a
residual deny rule that matches broadly), every request it could match pays a control-plane round
trip; narrow it with a simple condition first, as in `op == "store.write" && now.getHours() < 6`.

The table format is versioned (`Policy.table_format` in `proto/scrim/dataplane/v1`). The Go
reference evaluator is `internal/policy` (`Snapshot.Evaluate`), and
`internal/policy/testdata/conformance.json` holds vectors any data plane implementation must
reproduce.
