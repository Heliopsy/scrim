# scrim: Go control plane at the repository root, Rust data plane in dataplane/.
#
# `just check` is the pre-push gate: the fast checks CI runs. The container,
# cluster, VM, platform and latency jobs run only in CI or through their own
# recipes (CONTRIBUTING.md). `just build` produces bin/scrim with the data
# plane embedded.

module  := "github.com/heliopsy/scrim"
binary  := "scrim"
version := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
commit  := `git rev-parse --short HEAD 2>/dev/null || echo "none"`
date    := `date -u +%Y-%m-%dT%H:%M:%SZ`
ldflags := "-s -w -X " + module + "/internal/version.Version=" + version + " -X " + module + "/internal/version.Commit=" + commit + " -X " + module + "/internal/version.Date=" + date
embed   := "internal/dataplane/embedded/scrim-dataplane"

# Rust builds stay inside the checkout (and inside a worktree, its own).
export CARGO_TARGET_DIR := env("CARGO_TARGET_DIR", justfile_directory() / "dataplane/target")

default:
    @just --list

# ---------------------------------------------------------------- build

# Release data plane, embedded into bin/scrim.
build:
    cd dataplane && SCRIM_BUILD_VERSION={{version}} cargo build --locked --release -p scrim-dataplane
    install -m 0755 "$CARGO_TARGET_DIR/release/scrim-dataplane" {{embed}}
    mkdir -p bin
    go build -trimpath -tags embed_dataplane -ldflags '{{ldflags}}' -o bin/{{binary}} .

# Debug data plane next to a Go binary without embedding; run it with
# SCRIM_DATAPLANE_PATH=dataplane/target/debug/scrim-dataplane.
build-dev:
    cd dataplane && cargo build --locked -p scrim-dataplane
    mkdir -p bin
    go build -ldflags '{{ldflags}}' -o bin/{{binary}} .

# ---------------------------------------------------------------- test

# Every test: the Rust workspace, then Go with the race detector, including
# the integration test that launches the real data plane.
test:
    cd dataplane && cargo test --locked
    cd dataplane && cargo build --locked -p scrim-dataplane
    SCRIM_TEST_DATAPLANE="$CARGO_TARGET_DIR/debug/scrim-dataplane" go test -race -count=1 -shuffle=on ./...

# Benchmarks, Go and Rust.
bench:
    go test -run='^$' -bench=. -benchmem ./...
    cd dataplane && cargo bench --locked

# Every Go fuzz target for FUZZTIME each (default 30s).
fuzz:
    #!/usr/bin/env bash
    set -euo pipefail
    grep -rlE '^func Fuzz' --include='*_test.go' . | xargs -n1 dirname | sort -u | while read -r dir; do
      for f in $(grep -hoE '^func Fuzz[A-Za-z0-9_]*' "$dir"/*_test.go | cut -d' ' -f2); do
        echo "== $dir $f"
        go test -run='^$' -fuzz="^$f\$" -fuzztime="${FUZZTIME:-30s}" "$dir"
      done
    done

# ---------------------------------------------------------------- gates

# The pre-push gate.
check: fmt-check lint md test spec proto-check ebpf-check vuln deps-fresh monitoring

fmt:
    gofmt -w .
    cd dataplane && cargo fmt --all

fmt-check:
    test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
    cd dataplane && cargo fmt --all --check

lint:
    go vet ./...
    golangci-lint run ./...
    cd dataplane && cargo clippy --locked --all-targets -- -D warnings

# Lint the Markdown .markdownlint-cli2.yaml selects, with the rules in .markdownlint.yaml.
md:
    npx --yes markdownlint-cli2@0.24.2

# Alert rules, their tests, the Prometheus configs and the dashboard (deploy/monitoring).
monitoring:
    scripts/monitoring-check.sh

# Validate every OpenSpec change and spec.
spec:
    npx --yes @fission-ai/openspec@2.1.1 validate --all --strict --no-interactive

# govulncheck, and cargo-deny when it is installed (CI always runs it).
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
    @if command -v cargo-deny >/dev/null; then cd dataplane && cargo deny check; else echo "cargo-deny not installed; skipped (CI runs it)"; fi

# Minor and patch lag is Dependabot's; see scripts/deps-fresh.sh.
#
# Fail when a direct Go or Rust dependency is behind its latest stable major (0.x minor before 1.0).
deps-fresh *args:
    scripts/deps-fresh.sh {{args}}

# Fail when a pinned tool, image or action is behind a release older than 14 days (renovate.json
# pins, SHA-pinned actions). Uses GITHUB_TOKEN, or the gh login, for the GitHub API.
pins-fresh *args:
    GITHUB_TOKEN="${GITHUB_TOKEN:-$(gh auth token 2>/dev/null || true)}" scripts/deps-fresh.sh -pins -go-mod= -cargo-root= {{args}}

# Rewrite every pinned sha256 that does not match its release asset (after Renovate moved a version).
pin-sums:
    scripts/deps-fresh.sh -sums -fix

# Check every pinned sha256 against its release asset; downloads each asset.
pin-sums-check:
    scripts/deps-fresh.sh -sums

# ---------------------------------------------------------------- protocol

# Regenerate the Go and Rust boundary code from proto/.
proto:
    protoc -I proto \
      --plugin=protoc-gen-go="$(go tool -n protoc-gen-go)" \
      --plugin=protoc-gen-go-grpc="$(go tool -n protoc-gen-go-grpc)" \
      --go_out=. --go_opt=module={{module}} \
      --go-grpc_out=. --go-grpc_opt=module={{module}} \
      proto/scrim/dataplane/v1/dataplane.proto proto/scrim/plugin/v1/plugin.proto
    cd dataplane/tools/protogen && cargo run --quiet --locked

import "scripts/release/release.just"

# Fail when the committed generated code differs from what proto/ produces.
proto-check: proto
    git diff --exit-code -- internal/dataplane/dataplanev1 pkg/plugin/pluginv1 dataplane/crates/scrim-proto/src/gen
    test -z "$(git status --porcelain -- internal/dataplane/dataplanev1 pkg/plugin/pluginv1)"

# Regenerate the committed eBPF objects of internal/bpfredirect from bpf/redirect.c. bpf2go runs
# here; clang and llvm-strip run in rootless podman from scripts/bpf/Containerfile.
ebpf:
    BPF2GO_CC="{{justfile_directory()}}/scripts/bpf/clang" BPF2GO_STRIP="{{justfile_directory()}}/scripts/bpf/llvm-strip" \
      go generate ./internal/bpfredirect

# Fail when the committed eBPF objects differ from what bpf/redirect.c produces.
ebpf-check: ebpf
    git diff --exit-code -- internal/bpfredirect

# Per-cgroup redirect and direct-egress denial as root on a throwaway kernel in qemu (tasks.md 15.1);
# SCRIM_VM_KERNEL picks the vmlinuz. Nothing runs against this host's kernel.
ebpf-vm-test *args:
    SCRIM_VM_TEST_ARGS="{{args}}" test/ebpf/vm-test.sh

# `scrim install --system --ebpf` and `scrim uninstall` as root in a qemu VM with systemd, booted twice
# (tasks.md 15.1a, test/ebpf/install-test.sh). SCRIM_VM_KERNEL as for ebpf-vm-test; SCRIM_SVC_BIN names
# a binary with the data plane embedded, without it `just build` runs first.
ebpf-install-vm-test:
    test/ebpf/install-test.sh

# Regenerate the config JSON Schema and the settings reference from the registry.
config-docs:
    go run . config schema > schema/config-v1.json
    go run . config docs --update docs/configuration.md

# The checker, fake provider, matrix and scenarios against the pass-through and naive stand-ins
# (also part of `just test`).
#
# Self-test the leak suite.
leak-selftest:
    go test -race -count=1 ./internal/leak/... ./internal/testing/fakeprovider/...

# SCRIM_LEAK_PROXY is the proxy under test (builtin:naive or builtin:passthrough test the suite
# itself); SCRIM_LEAK_PROXY_CMD starts it. Extra arguments go to `scrim audit run`.
#
# Leak gate: bypass matrix and scenarios through the proxy (release gate).
leak *args: leak-selftest
    #!/usr/bin/env bash
    set -euo pipefail
    proxy="${SCRIM_LEAK_PROXY:-}"
    if [ -z "$proxy" ]; then
      echo "leak: set SCRIM_LEAK_PROXY to the proxy under test (builtin:naive and builtin:passthrough test the suite itself)" >&2
      exit 2
    fi
    cmd=()
    if [ -n "${SCRIM_LEAK_PROXY_CMD:-}" ]; then cmd=(--proxy-cmd "$SCRIM_LEAK_PROXY_CMD"); fi
    go run . audit run --proxy "$proxy" "${cmd[@]}" --report "${SCRIM_LEAK_REPORT:-leak-report.json}" {{args}}

# Leak gate with the real agent CLIs (claude, codex, opencode; default all three): the scenario
# sessions through scrim proxy, inside test/e2e/sandbox.sh. SCRIM_E2E_CLAUDE, SCRIM_E2E_CODEX and
# SCRIM_E2E_OPENCODE name the binaries, else PATH. A missing agent fails.
leak-agents *agents:
    test/leak/agents.sh {{agents}}

# Three replicas on PostgreSQL with Valkey events in memory- and CPU-capped rootless podman
# containers, the release data plane, a fake provider and a fake tool API. Fails on any leak,
# unrestored placeholder, failed injection or approval that did not cross replicas, and on the
# thresholds in test/load/profiles.json. smoke takes a few minutes; full (1,000 streams) wants a whole
# machine, see docs/state-and-observability.md. Extra arguments go to `scrim-load run`, for example
# `just load-test smoke --events nats --out /tmp/load`.
#
# Proxy-level load test (tasks.md 14.3), profile smoke or full.
load-test profile="smoke" *args:
    test/load/run.sh --profile {{profile}} {{args}}

# Standalone fake model provider for testing a proxy by hand or from Rust tests.
fakeprovider *args:
    go run ./internal/testing/fakeprovider/cmd/scrim-fakeprovider {{args}}

# End to end with the real scrim binary inside test/e2e/sandbox.sh: a network namespace with
# loopback only and the test hosts in its own /etc/hosts. Extra arguments go to the test binary,
# for example `-test.run TestTools/git`. See "Tests" in docs/run.md.
#
# Real curl, git, Node.js fetch and Python requests under scrim run (tasks.md 10.2).
e2e-tools *args:
    test/e2e/run.sh tools {{args}}

# scrim chained to caveman, a context compression proxy (tasks.md 3.5); skipped without caveman-proxy.
e2e-chain *args:
    test/e2e/run.sh chain {{args}}

# Realistic Claude Code, Codex and OpenCode sessions under scrim run; each skipped without its agent
# (SCRIM_E2E_CODEX and SCRIM_E2E_OPENCODE name the codex and opencode binaries).
e2e-session *args:
    test/e2e/run.sh session {{args}}

# Every shell block marked ```sh test in the user docs, run as written in the sandbox
# (test/e2e/docs); shell blocks without the mark must say why with a docs-test: skip comment.
docs-test *args:
    test/e2e/run.sh docs {{args}}

# Real CLIs (gh, git, kubectl, helm, podman, npm, terraform, tofu, gcloud, az, pip, twine,
# cargo, hcloud, doctl, aws) with their tool profiles against fakes of their APIs. A CLI that is
# not installed is skipped; SCRIM_E2E_REQUIRE_TOOLS=1 fails instead.
e2e-profiles *args:
    test/e2e/run.sh profiles {{args}}

# Claude Code with scrim's agent hooks only, no scrim run (tasks.md 15.3); skipped without claude.
e2e-agentmodes *args:
    test/e2e/run.sh agentmodes {{args}}

# Claude Code under scrim's managed settings, in a disposable rootless podman container with no
# network (tasks.md 13.4): managed settings live in /etc, never written on the host.
e2e-managed-settings:
    test/e2e/agentmodes/managed-settings.sh

# The end-to-end matrix (tasks.md 16.1): the cells of one store (file, openbao, vault, awssm),
# its server in rootless podman, the cells inside test/e2e/sandbox.sh with an nftables redirect for
# the transparent mode. SCRIM_MATRIX_CELLS picks cells. See "End-to-end matrix" in
# docs/leak-assurance.md.
e2e-matrix store *args:
    test/e2e/matrix/run.sh {{store}} {{args}}

# Every end-to-end run above.
e2e: e2e-tools e2e-chain e2e-session docs-test e2e-profiles e2e-agentmodes e2e-managed-settings

ntfy_image := "docker.io/binwiederhier/ntfy:v2.38.1"

# End-to-end approve and deny through a local ntfy in rootless podman, on a
# free host port unless PORT is given.
e2e-ntfy port="":
    #!/usr/bin/env bash
    set -euo pipefail
    name=scrim-e2e-ntfy-$$
    port="{{port}}"
    if [ -z "$port" ]; then
      port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    fi
    podman run -d --rm --name "$name" -p "127.0.0.1:$port:80" {{ntfy_image}} serve >/dev/null
    trap 'podman rm -f -v "$name" >/dev/null' EXIT
    for _ in $(seq 50); do curl -fsS "http://127.0.0.1:$port/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
    SCRIM_TEST_NTFY_URL="http://127.0.0.1:$port" go test -race -count=1 -run TestEndToEndAgainstNtfy -v ./internal/notify/ntfy/

# VM test of `scrim install` and `scrim uninstall` in a disposable systemd host under rootless
# podman (test/service/vm-test.sh). SCRIM_SVC_BIN names a binary with the data plane embedded;
# without it `just build` runs first.
service-vm-test:
    test/service/vm-test.sh

# Transparent mode, DNS override and Java trust (`scrim install --transparent` and `--dns`) in a
# disposable systemd host under rootless podman with its own network namespace
# (test/service/transparent-test.sh). SCRIM_SVC_BIN as for service-vm-test.
service-transparent-test:
    test/service/transparent-test.sh

# The exec broker running commands as exec.user, as root in a throwaway rootless podman container
# (test/exec/separate-user.sh): the agent's user cannot read the command's environment.
exec-user-test:
    test/exec/separate-user.sh

clean:
    rm -rf bin/ dist/ {{embed}}
    cd dataplane && cargo clean

# ---------------------------------------------------------------- kubernetes

# Generated files, lint, kubeconform, Pod Security, promtool, helm-unittest, golden renders,
# upgrade check and package. Needs the tools of `just helm-tools`.
# Helm chart gate (deploy/helm/scrim/ci/verify.sh).
helm-test:
    deploy/helm/scrim/ci/verify.sh

# Regenerate the schema, the values reference, the image list and the monitoring copies, then check.
helm-generate:
    deploy/helm/scrim/ci/verify.sh --generate

# Install the chart's test tools into bin/helm-tools; eval the line it prints.
helm-tools:
    deploy/helm/scrim/ci/tools.sh bin/helm-tools | tail -n1

# Rewrite the golden output after checking the diff of `just helm-test`.
helm-golden-update:
    test/k8s/golden.sh --update

# What an existing install would see change against a git ref (default origin/main).
helm-render-diff ref="origin/main":
    deploy/helm/scrim/ci/render-diff.sh {{ref}}

# Creates and deletes its own kind cluster, images and network (test/k8s/e2e.sh).
#
# End-to-end test of the chart in kind on rootless podman with Calico, Kyverno and OpenBao.
k8s-e2e:
    test/k8s/e2e.sh

# Creates and deletes its own kind cluster, images and network (test/k8s/edge-e2e.sh).
#
# Edge forwarder end to end in kind on rootless podman: git push over SSH, psql and exec from an agent pod.
edge-e2e:
    test/k8s/edge-e2e.sh

# ---------------------------------------------------------------- deployment examples

deploy_tools := justfile_directory() / ".tools/deploy-examples"

# Check every file under deploy/examples with pinned tools (scripts/deploy-examples/check.sh).
deploy-examples-check:
    scripts/deploy-examples/tools.sh {{deploy_tools}}
    scripts/deploy-examples/check.sh {{deploy_tools}}

# Run the container examples for real under rootless podman and send each a canary request.
deploy-examples-smoke:
    scripts/deploy-examples/tools.sh {{deploy_tools}}
    scripts/deploy-examples/smoke.sh {{deploy_tools}}
