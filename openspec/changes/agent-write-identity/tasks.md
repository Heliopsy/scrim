# Tasks

## 1. Check

- [x] 1.1 `stores.DeclareAgentWriteCheck` declared by `openbao`, `vault`, `gcpsm`, `bws`, `vaultwarden`; verify: `TestAgentWriteCheckDeclared` in each of the ten adapters with per-agent identity
- [x] 1.2 `agentstore.Checker.CheckWrite` with `identity.skip-agent-write-checks` and `identity.refuse-unchecked-writes`; verify: `TestCheckWrite`, `TestCheckWriteSkipped`, `TestRefuseUncheckedWrites`, `TestWritePolicy`

## 2. Wiring

- [x] 2.1 agent tools ask `WriteAccess` after policy for `secret_gen`, `secret_capture`, `secret_ask_human`, `scrim secret put` and the capture pre-check, audit `store_identity` and `store_write_check`; verify: `TestWritesAskTheAgentsStoreIdentity`, `TestCheckAsksTheAgentsStoreIdentity`
- [x] 2.2 `agentapi.Writes` wired from the gate's checker; verify: `TestWritesAdapter`, `TestRuntimeWritesAskStoreIdentity`
- [x] 2.3 the pod's service account token kept for the request on the local API and edge listener; verify: `TestKubernetesTokenReachesTheWriteCheck`, `TestAPIRequestCarriesThePodsToken`
- [x] 2.4 end to end: Vaultwarden 1.37.5 in podman, an agent whose own account has read-only access to a collection cannot `secret_gen` into it, scrim's own account can; verify: `TestVaultwarden/AgentWriteIdentity`
- [x] 2.5 `scrim doctor` reports writes per governed store; verify: `TestDoctorReportsAgentWriteChecks`

## 3. Docs

- [x] 3.1 docs/identity.md, docs/agent-tools.md, docs/limitations.md, `just config-docs`
