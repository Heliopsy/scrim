# scrim

Keeps your secrets away from LLM providers while your AI agents keep working.

> **Status: early development.** The skeleton builds and runs, but scrim does not protect
> anything yet. The behaviour contract is the [OpenSpec](https://openspec.dev) change in
> [`openspec/changes/scrim-v1`](openspec/changes/scrim-v1/). A Go control plane runs a Rust data
> plane as a child process, chosen by the benchmark in [`bench/redact-bench`](bench/redact-bench/).

A scrim is a theatre curtain that looks solid from one side and lets you see through it from the
other. scrim does the same for secrets: the model provider sees placeholders, your agent and your
tools keep working with the real thing.

## What it does

- **Redacts LLM traffic.** Every request an agent (Claude Code, Codex, any OpenAI or Anthropic API
  client) sends to a model provider passes through scrim. Known secret values, and their encoded
  forms, are replaced with deterministic placeholders before the request leaves the machine.
  Placeholders in the reply are resolved locally under a per-tool policy.
- **Injects credentials at the network edge, never into commands.** A credential stays a
  placeholder inside the agent's commands. scrim swaps in the real value only on outbound
  connections to the hosts that credential is bound to, so a prompt-injected agent cannot send it
  anywhere else.
- **Brokers secrets from the stores you already run.** Vaultwarden, Infisical and OpenBao first,
  more through plugins. Each store keeps its secrets; scrim reads them to know what to redact and
  writes new ones on the agent's behalf.
- **Lets agents ask, create and capture without seeing values.** An MCP server and a CLI give
  agents `secrets_list`, `secret_request`, `secret_gen`, `secret_capture` and `secret_ask_human`.
  None of them returns a value.
- **Puts a human in the loop when it matters.** Policy decides allow, deny or ask. Ask sends a push
  with Approve and Deny buttons (ntfy, Telegram, webhook, ...), and just-in-time grants expire on
  their own.
- **Fails closed.** If scrim cannot redact a request, the request does not leave.

## Where it runs

The same binary and the same configuration on a laptop, a VM, a container or a Kubernetes cluster.
Agents reach it through a wrapper (`scrim run -- claude`), a base URL, a forward proxy, transparent
interception (nftables or eBPF), Kubernetes injection, or agent hooks.

## Building from source

You need Go (version in `go.mod`), Rust (version in `dataplane/rust-toolchain.toml`),
[just](https://github.com/casey/just) and, to change the protocol, `protoc`.

```sh
just build        # bin/scrim with the data plane embedded
./bin/scrim version
just test         # Rust and Go tests, including a launch of the real data plane
just check        # everything CI checks
```

`just build-dev` skips the release build of the data plane; point the binary at the debug one
with `SCRIM_DATAPLANE_PATH=dataplane/target/debug/scrim-dataplane`.

## Licence

[GNU Affero General Public License v3.0](LICENSE). Contributions are accepted under the
[Contributor License Agreement](CLA.md).
