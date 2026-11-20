# scrim: Go control plane at the repository root, Rust data plane in dataplane/.
#
# `just check` is the pre-push gate and runs what CI runs, minus CodeQL and
# Scorecard. `just build` produces bin/scrim with the data plane embedded.

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
check: fmt-check lint md test spec proto-check vuln monitoring

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
    npx --yes markdownlint-cli2@0.24.1

# Alert rules, their tests, the Prometheus configs and the dashboard (deploy/monitoring).
monitoring:
    scripts/monitoring-check.sh

# Validate every OpenSpec change and spec.
spec:
    npx --yes @fission-ai/openspec@1.15.0 validate --all --strict --no-interactive

# govulncheck, and cargo-deny when it is installed (CI always runs it).
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
    @if command -v cargo-deny >/dev/null; then cd dataplane && cargo deny check; else echo "cargo-deny not installed; skipped (CI runs it)"; fi

# ---------------------------------------------------------------- protocol

# Regenerate the Go and Rust boundary code from proto/.
proto:
    protoc -I proto \
      --plugin=protoc-gen-go="$(go tool -n protoc-gen-go)" \
      --plugin=protoc-gen-go-grpc="$(go tool -n protoc-gen-go-grpc)" \
      --go_out=. --go_opt=module={{module}} \
      --go-grpc_out=. --go-grpc_opt=module={{module}} \
      proto/scrim/dataplane/v1/dataplane.proto
    cd dataplane/tools/protogen && cargo run --quiet --locked

import "scripts/release/release.just"

# Fail when the committed generated code differs from what proto/ produces.
proto-check: proto
    git diff --exit-code -- internal/dataplane/dataplanev1 dataplane/crates/scrim-proto/src/gen

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

# A realistic Claude Code session under scrim run; skipped without claude.
e2e-session *args:
    test/e2e/run.sh session {{args}}

# Every end-to-end run above.
e2e: e2e-tools e2e-chain e2e-session

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

clean:
    rm -rf bin/ dist/ {{embed}}
    cd dataplane && cargo clean
