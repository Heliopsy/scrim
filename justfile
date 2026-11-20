# scrim: Go control plane at the repository root, Rust data plane in dataplane/.
#
# `just check` is the pre-push gate. CI runs the same recipes.

module  := "github.com/heliopsy/scrim"
version := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
commit  := `git rev-parse --short HEAD 2>/dev/null || echo "none"`
date    := `date -u +%Y-%m-%dT%H:%M:%SZ`
ldflags := "-s -w -X " + module + "/internal/version.Version=" + version + " -X " + module + "/internal/version.Commit=" + commit + " -X " + module + "/internal/version.Date=" + date

export CARGO_TARGET_DIR := env("CARGO_TARGET_DIR", justfile_directory() / "dataplane/target")

default:
    @just --list

# Run every test: Go with the race detector, then the Rust workspace.
test:
    go test -race -count=1 ./...
    cd dataplane && cargo test --locked

# Regenerate the Go and Rust boundary code from proto/.
proto:
    protoc -I proto \
      --plugin=protoc-gen-go="$(go tool -n protoc-gen-go)" \
      --plugin=protoc-gen-go-grpc="$(go tool -n protoc-gen-go-grpc)" \
      --go_out=. --go_opt=module={{module}} \
      --go-grpc_out=. --go-grpc_opt=module={{module}} \
      proto/scrim/dataplane/v1/dataplane.proto
    cd dataplane/tools/protogen && cargo run --quiet --locked

# Regenerate the config JSON Schema and the settings reference from the registry.
config-docs:
    go run . config schema > schema/config-v1.json
    go run . config docs --update docs/configuration.md

ntfy_image := "docker.io/binwiederhier/ntfy:v2.14.0"

# End-to-end approve and deny through a local ntfy in rootless podman.
e2e-ntfy port="18765":
    #!/usr/bin/env bash
    set -euo pipefail
    name=scrim-e2e-ntfy-$$
    podman run -d --rm --name "$name" -p 127.0.0.1:{{port}}:80 {{ntfy_image}} serve >/dev/null
    trap 'podman rm -f -v "$name" >/dev/null' EXIT
    for _ in $(seq 50); do curl -fsS http://127.0.0.1:{{port}}/v1/health >/dev/null 2>&1 && break; sleep 0.2; done
    SCRIM_TEST_NTFY_URL=http://127.0.0.1:{{port}} go test -race -count=1 -run TestEndToEndAgainstNtfy -v ./internal/notify/ntfy/
