# Changelog

## [1.1.0](https://github.com/Heliopsy/scrim/compare/v1.0.0...v1.1.0) (2026-11-24)


### Features

* **edge:** give the edge listener its own CA ([#151](https://github.com/Heliopsy/scrim/issues/151)) ([0fd666b](https://github.com/Heliopsy/scrim/commit/0fd666bda1a540083422cd7775da6036ce9e3f34))
* **identity:** identify agents by client certificate ([#155](https://github.com/Heliopsy/scrim/issues/155)) ([9768457](https://github.com/Heliopsy/scrim/commit/9768457cec16cd743c6024da92d8cc6aec4bc71a))
* **interception:** chain scrim's outbound connections through an upstream proxy ([#157](https://github.com/Heliopsy/scrim/issues/157)) ([213f94e](https://github.com/Heliopsy/scrim/commit/213f94e23506be243a12049be79d0cea55a05880))
* **llm:** redact WebSocket connections to provider routes ([#156](https://github.com/Heliopsy/scrim/issues/156)) ([39b5821](https://github.com/Heliopsy/scrim/commit/39b58214266708ac07d0af910a9ca49f94aec735))
* **llm:** scan images, PDFs and other binary parts for secrets ([#159](https://github.com/Heliopsy/scrim/issues/159)) ([18235e8](https://github.com/Heliopsy/scrim/commit/18235e80d0042c8ad03b06e1ad3661814b26bfff))
* **redaction:** detect secrets in 37 known formats that no store holds ([#158](https://github.com/Heliopsy/scrim/issues/158)) ([8b84573](https://github.com/Heliopsy/scrim/commit/8b84573d984f356ced705a6abccd865a451d8890))
* **state:** redact every replica's session and service account tokens on every replica ([#154](https://github.com/Heliopsy/scrim/issues/154)) ([a7bbb15](https://github.com/Heliopsy/scrim/commit/a7bbb15d6ce2529d2e047cf10aba3401ae82df8e))
* Windows release and notarised macOS binaries ([#150](https://github.com/Heliopsy/scrim/issues/150)) ([d8f2500](https://github.com/Heliopsy/scrim/commit/d8f25004987418045ff78993aa35edb5df385d6d))


### Bug Fixes

* **interception:** send block_unrouted to the data plane ([#152](https://github.com/Heliopsy/scrim/issues/152)) ([39bf945](https://github.com/Heliopsy/scrim/commit/39bf945ca603ccee910300456a777d11b7600281))
* **llm:** wait for the agent's close after refusing a WebSocket message ([#161](https://github.com/Heliopsy/scrim/issues/161)) ([33f1637](https://github.com/Heliopsy/scrim/commit/33f1637f7d67c5619e4a88600e6ba6b8ba66efa2))

## [1.0.0](https://github.com/Heliopsy/scrim/compare/v0.6.0...v1.0.0) (2026-11-24)


### Features

* **chart:** expose the identity issuer ([#137](https://github.com/Heliopsy/scrim/issues/137)) ([9b792a0](https://github.com/Heliopsy/scrim/commit/9b792a0ffbcf2e926005b58fc35e92e5cac1cdbf))
* **identity:** per-agent store identity by token exchange ([#128](https://github.com/Heliopsy/scrim/issues/128)) ([6ec395b](https://github.com/Heliopsy/scrim/commit/6ec395bdb21c2646300173314f5c70438e97d976))
* **identity:** scrim as an identity provider for agents ([#123](https://github.com/Heliopsy/scrim/issues/123)) ([35b225d](https://github.com/Heliopsy/scrim/commit/35b225da556979324f32810ce22e2b5c05ee9ac4))
* **identity:** separate redaction identity and opt-in per-agent redaction ([#126](https://github.com/Heliopsy/scrim/issues/126)) ([17de7f7](https://github.com/Heliopsy/scrim/commit/17de7f76f5b053e9a2c180626a26cbd4c36ceeb1))
* **plugins:** store and notifier plugins with a versioned contract ([#125](https://github.com/Heliopsy/scrim/issues/125)) ([7ae1d4b](https://github.com/Heliopsy/scrim/commit/7ae1d4bd0c93972574430db0a06668ab57e4d0c4))


### Bug Fixes

* **config:** resolve store references in every secret setting ([#124](https://github.com/Heliopsy/scrim/issues/124)) ([d41fd89](https://github.com/Heliopsy/scrim/commit/d41fd89993b5c32196dfc9115eaef830c581af2d))
* **redaction:** keep unescaping JSON when a decoded backslash can start the next escape ([#142](https://github.com/Heliopsy/scrim/issues/142)) ([6c21a26](https://github.com/Heliopsy/scrim/commit/6c21a266a3d9cc71718f03772f40ffa4c74b9d73))
* **redaction:** redact scrim's own credentials from provider requests ([#140](https://github.com/Heliopsy/scrim/issues/140)) ([61f9fce](https://github.com/Heliopsy/scrim/commit/61f9fcebb0d007248545e5083dbd405d4e6b0cf6))
* **redaction:** replace a longer value whole around a value nested in it ([#135](https://github.com/Heliopsy/scrim/issues/135)) ([92aaba3](https://github.com/Heliopsy/scrim/commit/92aaba3da192f32490a8438848d7c00efbf82a60))
* **stores:** keep catalog secrets loaded across refreshes ([#130](https://github.com/Heliopsy/scrim/issues/130)) ([c67f0b8](https://github.com/Heliopsy/scrim/commit/c67f0b804ec178fa991ab95d78290781c1aa968e))
* **stores:** push values a store watch reports to the data plane ([#133](https://github.com/Heliopsy/scrim/issues/133)) ([48ff0b2](https://github.com/Heliopsy/scrim/commit/48ff0b2a53abc96b93c6e091297ff07fbb3ba948))


### Miscellaneous Chores

* **release:** release 1.0.0 ([#145](https://github.com/Heliopsy/scrim/issues/145)) ([becf3e7](https://github.com/Heliopsy/scrim/commit/becf3e7adb108a30e892d3f37cb4518753f27e43))

## [0.6.0](https://github.com/Heliopsy/scrim/compare/v0.5.0...v0.6.0) (2026-11-23)


### Features

* **database:** PostgreSQL and MySQL auth proxies and a read-only database tool ([#114](https://github.com/Heliopsy/scrim/issues/114)) ([a41a5a2](https://github.com/Heliopsy/scrim/commit/a41a5a2fa0904b2bb199e7689afc6ad66ce80f16))
* **edge:** edge forwarder for ssh-agent, database ports and the agent API in agent pods ([#121](https://github.com/Heliopsy/scrim/issues/121)) ([ce986f9](https://github.com/Heliopsy/scrim/commit/ce986f9cac3ff319228ed10ba8ccbf9c0629a74d))
* **exec:** run allow-listed commands with secrets as another user ([#108](https://github.com/Heliopsy/scrim/issues/108)) ([d51eb3a](https://github.com/Heliopsy/scrim/commit/d51eb3ace5ef8088b8c4ddc25e7132b46fbf20bd))
* **llm:** Bedrock, Claude Platform on AWS and Foundry routes signed after redaction ([#116](https://github.com/Heliopsy/scrim/issues/116)) ([349723e](https://github.com/Heliopsy/scrim/commit/349723e4925035712f7419c1cf2b13cd075a97da))
* **llm:** Gemini generateContent codec and route ([#107](https://github.com/Heliopsy/scrim/issues/107)) ([a6b50fb](https://github.com/Heliopsy/scrim/commit/a6b50fba34107cd7d933749a52a693666b906326))
* **llm:** Vertex AI and Foundry Entra ID routes with minted tokens ([#117](https://github.com/Heliopsy/scrim/issues/117)) ([48473a2](https://github.com/Heliopsy/scrim/commit/48473a2b08379186c9df30066f5b6a7ae5ac6739))
* **sshagent:** ssh-agent with keys from stores and a policy decision per signature ([#112](https://github.com/Heliopsy/scrim/issues/112)) ([3bfc553](https://github.com/Heliopsy/scrim/commit/3bfc553066e2a7c501d7e8e4a2ec9c5bc40c3556))
* **stores:** Bitwarden Secrets Manager adapter ([#104](https://github.com/Heliopsy/scrim/issues/104)) ([dce71b0](https://github.com/Heliopsy/scrim/commit/dce71b08a4c469aed07fe3cd3ee4b96b4653e14c))
* **stores:** Doppler, 1Password, AWS, OS keyring and Kubernetes Secrets adapters ([#119](https://github.com/Heliopsy/scrim/issues/119)) ([ea97293](https://github.com/Heliopsy/scrim/commit/ea97293b2192224a058b85f1692096f800a8d88a))
* **stores:** Google Secret Manager and Azure Key Vault adapters ([#109](https://github.com/Heliopsy/scrim/issues/109)) ([275e9fe](https://github.com/Heliopsy/scrim/commit/275e9fea4dfd9ade99839d27ec299f816baccc71))
* **stores:** HashiCorp Vault adapter with leases held per grant ([#113](https://github.com/Heliopsy/scrim/issues/113)) ([5cdb3ab](https://github.com/Heliopsy/scrim/commit/5cdb3aba863432f736d30b82a377dcb14eab39f8))
* **stores:** SOPS file source ([#111](https://github.com/Heliopsy/scrim/issues/111)) ([3273c3e](https://github.com/Heliopsy/scrim/commit/3273c3ef2aef02fac9d89443e51c214e85f82145))


### Bug Fixes

* **database:** resolve store references in database passwords ([#122](https://github.com/Heliopsy/scrim/issues/122)) ([b762003](https://github.com/Heliopsy/scrim/commit/b762003aa126a4b261956f250b18ecbde3811f48))

## [0.5.0](https://github.com/Heliopsy/scrim/compare/v0.4.0...v0.5.0) (2026-11-22)


### Features

* **interception:** original destination for eBPF-redirected connections ([#97](https://github.com/Heliopsy/scrim/issues/97)) ([11e8838](https://github.com/Heliopsy/scrim/commit/11e88380df12f1e2b827779e22528399fbd6c493))
* **interception:** reattach eBPF programs when scrim is upgraded ([#101](https://github.com/Heliopsy/scrim/issues/101)) ([965921d](https://github.com/Heliopsy/scrim/commit/965921d19ec81dd0794543470dda50a818292f5c))
* **interception:** scrim install --ebpf attaches at boot and uninstall detaches ([#93](https://github.com/Heliopsy/scrim/issues/93)) ([73a401f](https://github.com/Heliopsy/scrim/commit/73a401f6fc3b4f17e8b498f1dee47883b29ceafe))
* **stores:** read Vaultwarden and Infisical labels without values ([#92](https://github.com/Heliopsy/scrim/issues/92)) ([37d9ecc](https://github.com/Heliopsy/scrim/commit/37d9ecc78a9e8510d67fb52372be914fa4b44efc))


### Bug Fixes

* **interception:** take the eBPF port from the installed unit ([#98](https://github.com/Heliopsy/scrim/issues/98)) ([660fa91](https://github.com/Heliopsy/scrim/commit/660fa91b5e58cfc30f04435ca016ca713525fe6d))
* **status:** open PostgreSQL state read-only and never migrate it ([#100](https://github.com/Heliopsy/scrim/issues/100)) ([9141a27](https://github.com/Heliopsy/scrim/commit/9141a270f4a093ec07c64d1f05fa0eb6700f92cf))
* **status:** open SQLite state read-only without the process lock ([#95](https://github.com/Heliopsy/scrim/issues/95)) ([0ad799e](https://github.com/Heliopsy/scrim/commit/0ad799e2b3d74c06be119645b9f2b505137fe34e))
* **stores:** escape OpenBao paths once, read labels without the value ([#91](https://github.com/Heliopsy/scrim/issues/91)) ([6f2a7e0](https://github.com/Heliopsy/scrim/commit/6f2a7e061c2a19564fadc14b59ab51c0148c8c7d))
* **stores:** refuse an Infisical read whose value is hidden ([#96](https://github.com/Heliopsy/scrim/issues/96)) ([346acaf](https://github.com/Heliopsy/scrim/commit/346acaf79cf14916981dc011cd51040551173560))

## [0.4.0](https://github.com/Heliopsy/scrim/compare/v0.3.0...v0.4.0) (2026-11-22)


### Features

* **cli-tools:** credential helpers and secrets in project files ([#76](https://github.com/Heliopsy/scrim/issues/76)) ([b1fe2e3](https://github.com/Heliopsy/scrim/commit/b1fe2e3d3250a3a9074f2711e339a52941b864e0))
* **install:** managed agent settings and agent hooks interception modes ([#68](https://github.com/Heliopsy/scrim/issues/68)) ([e07ddc8](https://github.com/Heliopsy/scrim/commit/e07ddc82fa0da66979f6e1dcfb50c2a3cb3eca70))
* **interception:** eBPF cgroup transparent mode with a privileged loader ([#72](https://github.com/Heliopsy/scrim/issues/72)) ([d6b1784](https://github.com/Heliopsy/scrim/commit/d6b1784a37411086fc92abb0e36f793329344e58))
* **interception:** transparent mode, DNS override and Java trust ([#70](https://github.com/Heliopsy/scrim/issues/70)) ([3dafad6](https://github.com/Heliopsy/scrim/commit/3dafad68c19c8b557ded34c08f2809f0378eaac6))
* **profiles:** tool profiles for command-line tools with placeholder credentials ([#69](https://github.com/Heliopsy/scrim/issues/69)) ([7e91236](https://github.com/Heliopsy/scrim/commit/7e912364e5df25b21dd71324df318a386c5a7f0e))
* **run:** session filesystem view for credential files at fixed home paths ([#75](https://github.com/Heliopsy/scrim/issues/75)) ([5b62ad1](https://github.com/Heliopsy/scrim/commit/5b62ad1b83aea1d2b3d53b2e067c5580382acfe4))
* **state:** Valkey and NATS events, shared rate limits and external audit sinks ([#71](https://github.com/Heliopsy/scrim/issues/71)) ([0e82c5b](https://github.com/Heliopsy/scrim/commit/0e82c5ba0b634b86d217a406e61a08f1065065a9))
* store-native metadata as policy labels ([#84](https://github.com/Heliopsy/scrim/issues/84)) ([6b3c82b](https://github.com/Heliopsy/scrim/commit/6b3c82bb80a424e5da184dd8a1edd6b2352c9e03))
* **stores:** native OpenBao labels for policy rules ([#81](https://github.com/Heliopsy/scrim/issues/81)) ([fd3182d](https://github.com/Heliopsy/scrim/commit/fd3182d0b58398c9be38e1a5f2a83775bb2542bb))
* **stores:** native policy labels for Infisical secrets ([#83](https://github.com/Heliopsy/scrim/issues/83)) ([37a2a05](https://github.com/Heliopsy/scrim/commit/37a2a0519c02d9e1ff355faa0c717401a3867720))
* **stores:** native vaultwarden.* labels for policy rules ([#82](https://github.com/Heliopsy/scrim/issues/82)) ([bf5ae19](https://github.com/Heliopsy/scrim/commit/bf5ae1903fdaef4108779a6c5d20c76265e1cbfa))
* **toolproxy:** re-sign AWS SigV4, shape placeholders, present client certificates upstream ([#73](https://github.com/Heliopsy/scrim/issues/73)) ([f974f4a](https://github.com/Heliopsy/scrim/commit/f974f4a37f0b67d5c7da6bb56e1fdb41ddf5ddb6))


### Bug Fixes

* **helm:** size the scrim container's default requests from the load test ([#86](https://github.com/Heliopsy/scrim/issues/86)) ([8995e25](https://github.com/Heliopsy/scrim/commit/8995e25de6535cf0b19b841d761cdb6d24099ad0))
* **interception:** move the transparent listener off the metrics port ([#88](https://github.com/Heliopsy/scrim/issues/88)) ([60b1c94](https://github.com/Heliopsy/scrim/commit/60b1c94da4defb9433fbdc423c3d7858fd0bcc5f))
* **stores:** no size arithmetic in the label map allocation ([#90](https://github.com/Heliopsy/scrim/issues/90)) ([4573602](https://github.com/Heliopsy/scrim/commit/45736025ee5e95ff4fff5dbde4679ea06974cb43))

## [0.3.0](https://github.com/Heliopsy/scrim/compare/v0.2.0...v0.3.0) (2026-11-21)


### ⚠ BREAKING CHANGES

* **deploy:** kyverno.enabled needs Kyverno 1.17 or later. Upgrade the chart while Kyverno is still on 1.17 to 1.19, then Kyverno to 1.20 (docs/kubernetes.md, Kyverno versions).

### Features

* **deploy:** port the Kyverno policies to policies.kyverno.io/v1 ([#63](https://github.com/Heliopsy/scrim/issues/63)) ([664f9b4](https://github.com/Heliopsy/scrim/commit/664f9b4741dac63b0080c0f02f4454a727e2ace9))


### Bug Fixes

* **ci:** treat an empty 200 from the module proxy as not found ([#65](https://github.com/Heliopsy/scrim/issues/65)) ([69a6393](https://github.com/Heliopsy/scrim/commit/69a6393b46bf4d78eea7f1154a2a0b09346648ce))

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
