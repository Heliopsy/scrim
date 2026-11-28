## 1. Namespace helper

- [x] 1.1 Network namespace in the helper: loopback up, listeners bound and handed over with SCM_RIGHTS, launcher sockets masked (file by /dev/null, directory by an empty read-only tmpfs)
- [x] 1.2 `ProbeNetwork`; `TestNetworkNamespace` and `TestNetworkListenFailsClosed` in internal/fsview

## 2. scrim run

- [x] 2.1 `run.network` setting (open, proxy-only) and `--run-network`
- [x] 2.2 Plan the bridges and masks, refuse on unavailable namespace, non-loopback listener, other platforms and unavailable scrim
- [x] 2.3 Serve the handed-over listeners by splicing to scrim's listeners
- [x] 2.4 `--print-env`, `scrim status` and `scrim doctor` report the mode
- [x] 2.6 Mask the host's name resolvers (system bus, resolved, nscd, avahi) and displays (X11, Wayland), drop `DISPLAY` and `WAYLAND_DISPLAY`; `TestRunNetworkMasksResolversAndDisplays`, `TestLauncherSocketsList`
- [x] 2.5 Tests: `TestRunNetworkProxyOnly` (open as control), `TestRunNetworkRefusals`, `TestRunNetworkPrintEnv`, `TestStatusRunNetwork`; agent CLI tests under `SCRIM_TEST_RUN_NETWORK=proxy-only`

## 3. End to end and CI

- [x] 3.1 `TestProxyOnlyNetwork` in test/e2e/tools with real curl
- [x] 3.2 e2e-agents job runs the Claude Code, Codex and OpenCode sessions again with `SCRIM_E2E_RUN_NETWORK=proxy-only`; the namespace tests run with `SCRIM_TEST_REQUIRE_USERNS=1`

## 4. Docs

- [x] 4.1 run.md (Agent network), interception.md (mode table, proxy-only section), limitations.md, configuration.md
