# Changelog

## [0.2.0](https://github.com/Heliopsy/scrim/compare/v0.1.0...v0.2.0) (2026-11-20)


### Features

* **deploy:** Helm chart with Kyverno injection, NetworkPolicy and sidecar mode ([#46](https://github.com/Heliopsy/scrim/issues/46)) ([0389df2](https://github.com/Heliopsy/scrim/commit/0389df29e1bc66968f8536f3b53e2581a5968acf))
* **install:** scrim install and uninstall as a user, system or Quadlet service ([#45](https://github.com/Heliopsy/scrim/issues/45)) ([536fe6c](https://github.com/Heliopsy/scrim/commit/536fe6c79d5df37d248eec0adb23efc47a3baed8))
* Kubernetes service account identity, per-agent store identity and shared state across replicas ([#47](https://github.com/Heliopsy/scrim/issues/47)) ([e3a52d6](https://github.com/Heliopsy/scrim/commit/e3a52d647aca732fe5bd71a1ca7dbff93d59dfab))
* **metrics:** Prometheus monitoring behind metrics.enabled ([#44](https://github.com/Heliopsy/scrim/issues/44)) ([d4b5526](https://github.com/Heliopsy/scrim/commit/d4b55268374dbcc0152b1648caaea624e5975bdf))


### Bug Fixes

* CA rotation, git identity and snapshot bugs found running scrim against real tools ([#43](https://github.com/Heliopsy/scrim/issues/43)) ([885f36f](https://github.com/Heliopsy/scrim/commit/885f36fb559dd8586da439d3842637104ac57268))
* fail closed on empty redact targets, service-account tokens and unresolved placeholders ([#51](https://github.com/Heliopsy/scrim/issues/51)) ([2305f34](https://github.com/Heliopsy/scrim/commit/2305f34ccf5b6bee470b4215573182ed5a819b02))

## 0.1.0 (2026-11-20)


### Features

* **agent:** agent identity, local API, MCP server, CLI and entry page ([#12](https://github.com/Heliopsy/scrim/issues/12)) ([a59fd5d](https://github.com/Heliopsy/scrim/commit/a59fd5d1b7074824fab72aa163cd8019532c8798))
* **catalog:** secret catalog with profiles, bulk mapping, store metadata and hot reload ([#11](https://github.com/Heliopsy/scrim/issues/11)) ([dbcff98](https://github.com/Heliopsy/scrim/commit/dbcff98c568e69d43e25b77c7998a907751fb94a))
* **config:** config files, secret references, provenance and hot reload ([#6](https://github.com/Heliopsy/scrim/issues/6)) ([1514a25](https://github.com/Heliopsy/scrim/commit/1514a255e89ca167de109745e5b6f3b600aa1ef1))
* **daemon:** scrim proxy runs control plane, data plane and every socket ([#28](https://github.com/Heliopsy/scrim/issues/28)) ([375e278](https://github.com/Heliopsy/scrim/commit/375e27897ca6f1c7776eab97937ff505fbc38892))
* **dataplane:** decide with scrim-policy, ask the control plane, identify callers ([#32](https://github.com/Heliopsy/scrim/issues/32)) ([6d28dfb](https://github.com/Heliopsy/scrim/commit/6d28dfbd7c5ed20294f3bce9a87c8ba7fd2a52ba))
* **dataplane:** wire redaction core, LLM proxy and tool proxy into the data plane ([#24](https://github.com/Heliopsy/scrim/issues/24)) ([8182698](https://github.com/Heliopsy/scrim/commit/81826984ab858ba21df390432d0de10d09d2426a))
* **gate:** verify data-plane callers, decide asks with their identity, inject toward bound hosts by default ([#35](https://github.com/Heliopsy/scrim/issues/35)) ([d717204](https://github.com/Heliopsy/scrim/commit/d717204137032c896459630e3d143ba24c7e8cad))
* **llm:** fail-closed LLM proxy with Anthropic and OpenAI codecs ([#14](https://github.com/Heliopsy/scrim/issues/14)) ([d7a762f](https://github.com/Heliopsy/scrim/commit/d7a762fdff3f866896c7732d650799fc341612e6))
* **policy:** CEL rules, approvals with signed links, notifiers, JIT grants and break-glass ([#15](https://github.com/Heliopsy/scrim/issues/15)) ([5731f9b](https://github.com/Heliopsy/scrim/commit/5731f9b994a17d7d082fa10c614e50c647d2adc1))
* **policy:** data-plane decision table, restore policy and escaping ([#29](https://github.com/Heliopsy/scrim/issues/29)) ([2c57119](https://github.com/Heliopsy/scrim/commit/2c57119364b0c2cfc8db2363d8f6fd493b309bc0))
* **redact:** redaction core with dual matchers, guard and stream restorer ([#17](https://github.com/Heliopsy/scrim/issues/17)) ([639ba2a](https://github.com/Heliopsy/scrim/commit/639ba2a5f4ac17dc63a8608b91f0f0e0e77955cf))
* repository skeleton, data plane boundary and shared contracts ([#9](https://github.com/Heliopsy/scrim/issues/9)) ([eb59e01](https://github.com/Heliopsy/scrim/commit/eb59e018af31bb17f535cc0fe33f6afe5011e5af))
* **run:** scrim run wrapper for Claude Code, Codex and other agents ([#25](https://github.com/Heliopsy/scrim/issues/25)) ([4e6e550](https://github.com/Heliopsy/scrim/commit/4e6e5501aa817ba0da666b34cf796fbdb397dfbc))
* shared contracts ([#3](https://github.com/Heliopsy/scrim/issues/3)) ([bbb28f2](https://github.com/Heliopsy/scrim/commit/bbb28f243e6f29bfa777aa03de1d503463c33ae1))
* **state:** SQL state backends, transactional audit, observability, status and doctor ([#7](https://github.com/Heliopsy/scrim/issues/7)) ([136b688](https://github.com/Heliopsy/scrim/commit/136b6886c9affb551043d493dc36c778af367d9b))
* **stores:** OpenBao, Infisical, env and file adapters, conformance suite and outage handling ([#10](https://github.com/Heliopsy/scrim/issues/10)) ([b81bc94](https://github.com/Heliopsy/scrim/commit/b81bc948ec43d61fdb35308fd1cd09e3ef6f19b6))
* **stores:** Vaultwarden adapter with client-side decryption ([#5](https://github.com/Heliopsy/scrim/issues/5)) ([2130873](https://github.com/Heliopsy/scrim/commit/21308739c72650fc28dc311ad3f89146146b9fc0))
* **toolproxy:** HTTPS tool proxy with credential injection and response redaction ([#8](https://github.com/Heliopsy/scrim/issues/8)) ([ebfe225](https://github.com/Heliopsy/scrim/commit/ebfe2256216dfef78f58f8093e5d4df7cc1d6528))


### Bug Fixes

* **dataplane:** build on macOS ([#40](https://github.com/Heliopsy/scrim/issues/40)) ([8c88610](https://github.com/Heliopsy/scrim/commit/8c8861093b787862537c94f735ddb60507c72b9a))
* **llm:** ASCII header placeholders, fast WebSocket refusal, ChatGPT hosts ([#36](https://github.com/Heliopsy/scrim/issues/36)) ([2eb778a](https://github.com/Heliopsy/scrim/commit/2eb778a4ad6fb4c05b4146e762bb451117cd9fd7))
* **llm:** redact and guard request headers, path and query ([#33](https://github.com/Heliopsy/scrim/issues/33)) ([c66d5d1](https://github.com/Heliopsy/scrim/commit/c66d5d1dd5a08188d8c2de6de72e1e4f26d5da49))
* README table lint and just recipe groups CI cannot parse ([#22](https://github.com/Heliopsy/scrim/issues/22)) ([77d80b4](https://github.com/Heliopsy/scrim/commit/77d80b431a6f23f9ced2347ec22ce2a3e8af0aaf))
* **redact:** guard decodes the transforms agents' tools apply ([#37](https://github.com/Heliopsy/scrim/issues/37)) ([6f2f86f](https://github.com/Heliopsy/scrim/commit/6f2f86ff45d724bea98981062eae1a0e0d0fbf43))
* **redact:** guard fragments guess no token prefix ([#38](https://github.com/Heliopsy/scrim/issues/38)) ([54dc805](https://github.com/Heliopsy/scrim/commit/54dc80574fd7698a3ba6ed6be8e24cc4e5b018ab))
* **redact:** match values in JSON nested in JSON strings ([#30](https://github.com/Heliopsy/scrim/issues/30)) ([c22d32b](https://github.com/Heliopsy/scrim/commit/c22d32b01fa7f1985b9bf102c346a29d1d43c9df))


### Performance Improvements

* **redact:** single-decode guard, strided hash-window probes, parallel protect ([#31](https://github.com/Heliopsy/scrim/issues/31)) ([4b1a156](https://github.com/Heliopsy/scrim/commit/4b1a156f06b6f47aab0c543754ecf2ccdd54a0e8))
