#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Starts `scrim proxy` for `scrim audit run --proxy-cmd`: the seeds become
# files of a file store whose values are loaded into the redaction set, both
# provider routes point at the fake provider, and every file scrim writes
# (state, keys, CA, sockets) lives in a temporary directory removed on exit.
#
# Environment from the suite: SCRIM_LEAK_SEEDS (seed file), SCRIM_LEAK_UPSTREAM
# (fake provider URL), SCRIM_LEAK_LISTEN (the proxy URL to listen on).
# SCRIM_DATAPLANE_PATH names the data plane binary; without it the debug data
# plane is built. SCRIM_LEAK_SCRIM names the scrim binary; without it scrim is
# built from this tree (the release runs the binaries it ships).
set -euo pipefail

: "${SCRIM_LEAK_SEEDS:?}" "${SCRIM_LEAK_UPSTREAM:?}" "${SCRIM_LEAK_LISTEN:?}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
dir="$(mktemp -d "${TMPDIR:-/tmp}/scrim-leak.XXXXXX")"
pid=""
cleanup() {
  if [ -n "$pid" ]; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$dir"
}
trap cleanup EXIT
trap 'exit 0' TERM INT

if [ -z "${SCRIM_DATAPLANE_PATH:-}" ]; then
  (cd "$root/dataplane" && cargo build --locked --quiet -p scrim-dataplane)
  export SCRIM_DATAPLANE_PATH="${CARGO_TARGET_DIR:-$root/dataplane/target}/debug/scrim-dataplane"
fi

# One file per seed, byte for byte (no trailing newline added or trimmed).
mkdir -m 0700 -p "$dir/seeds/leak"
n="$(jq '.seeds | length' "$SCRIM_LEAK_SEEDS")"
for ((i = 0; i < n; i++)); do
  jq -j ".seeds[$i].value" "$SCRIM_LEAK_SEEDS" > "$dir/seeds/leak/seed-$i"
done
# A short value inside a seed: scrim redacts a store's own credentials, and
# LocalStack's are test/test, which sits inside the api-key seed (sk-test-...).
# Replacing it must not cut the seed apart in the forms only the guard decodes
# (wrapped hex, xxd, hexdump -C). It is not a seed: the gate checks the seeds.
printf 'test' > "$dir/seeds/leak/nested-credential"
chmod 0600 "$dir"/seeds/leak/*

listen="${SCRIM_LEAK_LISTEN#http://}"
listen="${listen%%/*}"
cat > "$dir/config.yaml" <<YAML
apiVersion: scrim.dev/v1
kind: Config
state: {backend: memory}
stores:
  leak:
    kind: file
    root: $dir/seeds
    format: raw
    trim-newline: false
    redact: ["leak://leak/*"]
proxy:
  listen: $listen
  forward-listen: ""
  upstream: {anthropic: "$SCRIM_LEAK_UPSTREAM", openai: "$SCRIM_LEAK_UPSTREAM", gemini: "$SCRIM_LEAK_UPSTREAM"}
api: {socket: $dir/api.sock}
admin: {url: "unix:$dir/admin.sock"}
redaction: {placeholder-key-dir: $dir/keys}
tool-proxy: {ca: {dir: $dir/ca}}
notify: {terminal: {enabled: false}}
YAML

scrim="${SCRIM_LEAK_SCRIM:-}"
if [ -z "$scrim" ]; then
  go build -o "$dir/scrim" "$root"
  scrim="$dir/scrim"
fi
env -i PATH="$PATH" HOME="$dir" XDG_STATE_HOME="$dir" XDG_CONFIG_HOME="$dir" XDG_RUNTIME_DIR="$dir" \
  SCRIM_DATAPLANE_PATH="$SCRIM_DATAPLANE_PATH" \
  "$scrim" --config "$dir/config.yaml" proxy &
pid=$!
wait "$pid"
