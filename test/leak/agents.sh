#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The leak gate with real agent CLIs: `scrim audit run --suite scenarios
# --driver <agent>` against `scrim proxy` (test/leak/start-proxy.sh), once per
# agent, inside test/e2e/sandbox.sh so nothing an agent sends can leave the
# machine. A missing agent fails its run.
#
#   test/leak/agents.sh [claude] [codex] [opencode]    (default: all three)
#
# SCRIM_E2E_CLAUDE, SCRIM_E2E_CODEX and SCRIM_E2E_OPENCODE name the agent
# binaries; otherwise each is looked up on PATH. SCRIM_DATAPLANE_PATH names the
# data plane; without it the debug one is built. Reports are written to
# SCRIM_LEAK_REPORT_DIR (default: the current directory) as
# agent-<agent>-report.json.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
agents=("$@")
if [ "${#agents[@]}" -eq 0 ]; then
  agents=(claude codex opencode)
fi
reports="$(cd "${SCRIM_LEAK_REPORT_DIR:-.}" && pwd)"
out="$(mktemp -d "${TMPDIR:-/tmp}/scrim-leak-agents.XXXXXX")"
trap 'rm -rf "$out"' EXIT

if [ -z "${SCRIM_DATAPLANE_PATH:-}" ]; then
  (cd "$root/dataplane" && cargo build --locked --quiet -p scrim-dataplane)
  SCRIM_DATAPLANE_PATH="${CARGO_TARGET_DIR:-$root/dataplane/target}/debug/scrim-dataplane"
fi
# Built outside the sandbox, which has no network for module downloads.
(cd "$root" && go build -o "$out/scrim" .)
export SCRIM_DATAPLANE_PATH SCRIM_LEAK_SCRIM="$out/scrim"

status=0
for agent in "${agents[@]}"; do
  var="SCRIM_E2E_$(printf '%s' "$agent" | tr '[:lower:]' '[:upper:]')"
  bin="${!var:-$agent}"
  echo "== $agent ($bin)"
  if ! (cd "$root" && "$root/test/e2e/sandbox.sh" "$out/scrim" audit run --suite scenarios \
    --driver "$agent" --agent-bin "$bin" \
    --proxy http://127.0.0.1:18484 --proxy-cmd test/leak/start-proxy.sh \
    --route anthropic-messages=/anthropic --route openai-chat=/openai --route openai-responses=/openai --route gemini=/gemini \
    --upstream-listen 127.0.0.1:18089 --report "$reports/agent-$agent-report.json"); then
    status=1
  fi
done
exit "$status"
