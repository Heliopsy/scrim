#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Managed agent settings with the real Claude Code CLI (tasks.md 13.4).
# Managed settings live in system directories (/etc/claude-code), so this
# never runs them on the host: it starts a disposable rootless podman
# container with no network, mounts the scrim binaries and the host's
# Claude Code binary read-only, and inside it, as the container's root:
#
#   1. starts two fake providers: "upstream" (scrim's Anthropic upstream)
#      and "bypass" (where the user tries to point Claude Code), and
#      `scrim proxy` with a file store holding a generated value;
#   2. control: without managed settings, ANTHROPIC_BASE_URL pointing at the
#      bypass provider reaches it;
#   3. `scrim install --managed-settings --agent claude`, then tries to point
#      Claude Code elsewhere through the shell environment, the user settings
#      file and --settings: every request goes to scrim (the bypass provider
#      sees none, the upstream sees placeholders and never the value), and a
#      Bedrock session is refused;
#   4. `scrim status` reports the mode; `scrim uninstall --managed-settings`
#      removes the drop-in, and the bypass works again.
#
#   test/e2e/agentmodes/managed-settings.sh            (just e2e-managed-settings)
#
# CLAUDE names the Claude Code binary (default: the one on PATH, resolved).
set -euo pipefail

if [ "${1:-}" = "--inner" ]; then
  export HOME=/root PATH=/opt/scrim:/usr/local/bin:/usr/bin:/bin
  export DISABLE_AUTOUPDATER=1 DISABLE_TELEMETRY=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
  export ANTHROPIC_API_KEY=fake-provider-key-not-a-seed
  w=/work
  mkdir -p "$w/secrets/tools" "$w/up" "$w/bypass" "$HOME"
  value="sk-ant-api03-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
  printf '%s' "$value" >"$w/secrets/tools/api-key"
  cat >"$w/config.yaml" <<EOF
apiVersion: scrim.dev/v1
kind: Config
state: {backend: memory}
stores:
  e2e:
    kind: file
    root: $w/secrets
    format: raw
    trim-newline: false
    redact: ["e2e://tools/*"]
proxy:
  listen: 127.0.0.1:9790
  forward-listen: ""
  upstream: {anthropic: "http://127.0.0.1:18089", openai: "http://127.0.0.1:18089"}
api: {socket: $w/api.sock}
admin: {url: "unix:$w/admin.sock"}
redaction: {placeholder-key-dir: $w/keys}
tool-proxy: {ca: {dir: $w/ca}}
notify: {terminal: {enabled: false}}
dataplane: {path: /opt/scrim/scrim-dataplane}
EOF
  export SCRIM_CONFIG=$w/config.yaml
  scrim-fakeprovider -listen 127.0.0.1:18089 -capture-dir "$w/up" >/dev/null &
  scrim-fakeprovider -listen 127.0.0.1:18090 -capture-dir "$w/bypass" >/dev/null &
  scrim proxy >"$w/proxy.log" 2>&1 &
  for _ in $(seq 150); do
    [ -S "$w/api.sock" ] && (exec 3<>/dev/tcp/127.0.0.1/9790) 2>/dev/null && break
    sleep 0.2
  done
  sleep 1

  fail() { echo "FAIL: $*" >&2; echo "--- scrim proxy log" >&2; cat "$w/proxy.log" >&2; exit 1; }
  count() { find "$1" -name '*.json' | wc -l; }
  # ask PROMPT [claude args...]: one Claude Code session; stdout+stderr in $w/out, exit code in $rc.
  ask() {
    local prompt="$1"; shift
    set +e
    (cd "$w" && timeout 120 claude -p "$prompt" --model claude-sonnet-4-5 "$@") >"$w/out" 2>&1
    rc=$?
    set -e
  }

  echo "== control: no managed settings, ANTHROPIC_BASE_URL points at the bypass provider"
  ANTHROPIC_BASE_URL=http://127.0.0.1:18090 ask "hello"
  [ "$rc" = 0 ] || fail "control session failed: $(cat "$w/out")"
  [ "$(count "$w/bypass")" -gt 0 ] || fail "control: the bypass provider got nothing, so the test cannot see a bypass"
  rm -f "$w/bypass"/*.json "$w/up"/*.json

  echo "== scrim install --managed-settings --agent claude"
  scrim install --managed-settings --agent claude
  cat /etc/claude-code/managed-settings.d/90-scrim.json

  echo "== attempt 1: ANTHROPIC_BASE_URL in the shell"
  ANTHROPIC_BASE_URL=http://127.0.0.1:18090 ask "deploy with $value"
  [ "$rc" = 0 ] || fail "managed session failed: $(cat "$w/out")"
  echo "== attempt 2: ANTHROPIC_BASE_URL in the user settings"
  mkdir -p "$HOME/.claude"
  printf '{"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:18090"}}\n' >"$HOME/.claude/settings.json"
  ask "deploy with $value"
  [ "$rc" = 0 ] || fail "managed session with user settings failed: $(cat "$w/out")"
  rm "$HOME/.claude/settings.json"
  echo "== attempt 3: ANTHROPIC_BASE_URL through --settings"
  ask "deploy with $value" --settings '{"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:18090"}}'
  [ "$rc" = 0 ] || fail "managed session with --settings failed: $(cat "$w/out")"

  [ "$(count "$w/bypass")" = 0 ] || fail "the bypass provider received $(count "$w/bypass") requests under managed settings"
  [ "$(count "$w/up")" -gt 0 ] || fail "no request reached scrim's upstream"
  if grep -rqF "$value" "$w/up"; then fail "the upstream received the value"; fi
  grep -rq '⟦scrim:' "$w/up" || fail "no placeholder in what the upstream received"
  echo "   bypass provider: 0 requests; scrim's upstream: $(count "$w/up") requests, placeholders only"

  echo "== attempt 4: a Bedrock session"
  CLAUDE_CODE_USE_BEDROCK=1 AWS_REGION=us-east-1 ask "hello"
  [ "$rc" != 0 ] || fail "a Bedrock session started under allowedProviders [customEndpoint]: $(cat "$w/out")"
  echo "   refused (exit $rc): $(tr '\n' ' ' <"$w/out" | cut -c1-200)"
  [ "$(count "$w/bypass")" = 0 ] || fail "bypass provider reached"

  echo "== scrim status"
  scrim status | sed -n '/^Interception/,/^Protections/p'
  scrim status --json | grep -q '"mode": "managed-settings"' || fail "status does not report managed settings"

  echo "== scrim uninstall --managed-settings"
  scrim uninstall --managed-settings
  [ ! -e /etc/claude-code ] || fail "/etc/claude-code left behind"
  ANTHROPIC_BASE_URL=http://127.0.0.1:18090 ask "hello"
  [ "$rc" = 0 ] && [ "$(count "$w/bypass")" -gt 0 ] || fail "after uninstall the shell's ANTHROPIC_BASE_URL is still overridden"
  if grep -qF "$value" "$w/proxy.log"; then fail "the value reached scrim's log"; fi
  echo "PASS"
  exit 0
fi

root="$(cd "$(dirname "$0")/../../.." && pwd)"
claude="${CLAUDE:-$(command -v claude || true)}"
if [ -z "$claude" ]; then
  echo "managed-settings: Claude Code is not installed; skipped" >&2
  exit 0
fi
claude="$(readlink -f "$claude")"
out="$(mktemp -d "${TMPDIR:-/tmp}/scrim-am-bin.XXXXXX")"
name="scrim-am-managed-$$"
trap 'podman rm -f -v "$name" >/dev/null 2>&1 || true; rm -rf "$out"' EXIT

if [ -z "${SCRIM_DATAPLANE_PATH:-}" ]; then
  (cd "$root/dataplane" && cargo build --locked --quiet -p scrim-dataplane)
  SCRIM_DATAPLANE_PATH="${CARGO_TARGET_DIR:-$root/dataplane/target}/debug/scrim-dataplane"
fi
(cd "$root" && CGO_ENABLED=0 go build -o "$out/scrim" . && CGO_ENABLED=0 go build -o "$out/scrim-fakeprovider" ./internal/testing/fakeprovider/cmd/scrim-fakeprovider)
install -m 0755 "$SCRIM_DATAPLANE_PATH" "$out/scrim-dataplane"
install -m 0755 "$0" "$out/managed-settings.sh"

podman run --rm --name "$name" --network none \
  -v "$out:/opt/scrim:ro,Z" -v "$claude:/usr/local/bin/claude:ro" \
  docker.io/library/debian:trixie-slim /opt/scrim/managed-settings.sh --inner
