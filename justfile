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
