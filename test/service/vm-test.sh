#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# VM test of `scrim install` and `scrim uninstall` (task 13.1): a disposable
# systemd host in rootless podman stands in for a VM. For each mode it takes
# a snapshot of the file system, installs, checks the service is active, runs
# a test agent through scrim against the fake provider, checks `scrim status`
# reports the service, uninstalls with --purge and compares the file system
# with the snapshot. Nothing runs against this host's systemd.
#
#   test/service/vm-test.sh                 # builds bin/scrim with `just build`
#   SCRIM_SVC_BIN=path/to/scrim test/service/vm-test.sh
#
# SCRIM_SVC_BIN is a scrim binary with the data plane embedded, built for
# linux-amd64 against a libc the image has (the release build is static).
# SCRIM_SVC_MODES picks modes (default "system user"). SCRIM_SVC_KEEP_IMAGE=1
# keeps the test image. The container gets CAP_SYS_ADMIN inside its user
# namespace so systemd can set up the unit's mount namespaces, as on a VM.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
image=localhost/scrim-svc-debian:test
name="scrim-svc-$$"
modes="${SCRIM_SVC_MODES:-system user}"
work="$(mktemp -d "${TMPDIR:-/tmp}/scrim-svc.XXXXXX")"
chmod 0755 "$work" # the agent users in the container run files from it
built_image=0

cleanup() {
  podman rm -f -v "$name" >/dev/null 2>&1 || true
  if [ "$built_image" = 1 ] && [ -z "${SCRIM_SVC_KEEP_IMAGE:-}" ]; then
    podman rmi -f "$image" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

if [ -z "${SCRIM_SVC_BIN:-}" ]; then
  (cd "$root" && just build)
  SCRIM_SVC_BIN="$root/bin/scrim"
fi
install -m 0755 "$SCRIM_SVC_BIN" "$work/scrim"
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$work/scrim-fakeprovider" ./internal/testing/fakeprovider/cmd/scrim-fakeprovider)
install -m 0755 "$here/snapshot.sh" "$work/snapshot.sh"

if ! podman image exists "$image"; then
  podman build -q -t "$image" -f "$here/Containerfile.debian" "$here" >/dev/null
  built_image=1
fi

podman run -d --name "$name" --systemd=always --cap-add SYS_ADMIN \
  -v "$work:/opt/scrim-test:ro" "$image" >/dev/null
vm() { podman exec "$name" "$@"; }
as_alice() { podman exec -u alice -e HOME=/home/alice -e XDG_RUNTIME_DIR=/run/user/1000 \
  -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus -w /home/alice "$name" "$@"; }

for _ in $(seq 60); do
  s="$(vm systemctl is-system-running 2>/dev/null || true)"
  case "$s" in running | degraded) break ;; esac
  sleep 0.5
done
vm systemctl is-system-running --wait >/dev/null 2>&1 || true

# The fake provider and the test agent are the test's own; they live outside
# the snapshot (/run, /tmp) or are removed before the comparison.
vm systemd-run --quiet --unit scrim-svc-fake /opt/scrim-test/scrim-fakeprovider -listen 127.0.0.1:18089
secret="svc-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat > "$work/agent.sh" <<'EOF'
#!/bin/sh
# Test agent: one Anthropic request with the secret, to the base URL scrim run set.
curl -fsS -o /dev/null "$ANTHROPIC_BASE_URL/v1/messages" -H 'content-type: application/json' \
  -H 'x-api-key: test' -H 'anthropic-version: 2023-06-01' \
  -d "{\"model\":\"m\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"the token is $1\"}]}"
EOF
chmod 0755 "$work/agent.sh"

# check_provider: the fake provider got exactly the requests since the last
# reset, none carrying the secret, each carrying a placeholder.
check_provider() {
  local want="$1" ex n
  ex="$(vm curl -fsS http://127.0.0.1:18089/_fake/exchanges)"
  n="$(jq length <<<"$ex")"
  [ "$n" = "$want" ] || fail "the fake provider saw $n requests, want $want"
  if grep -qF "$secret" <<<"$ex"; then fail "the secret reached the provider"; fi
  grep -q '⟦scrim:' <<<"$ex" || fail "no placeholder reached the provider"
  vm curl -fsS -X POST http://127.0.0.1:18089/_fake/reset >/dev/null
  echo "provider: $n request(s), secret absent, placeholder present"
}

compare() {
  vm sh -c '/opt/scrim-test/snapshot.sh > /tmp/after.txt'
  if ! vm diff /tmp/before.txt /tmp/after.txt; then
    fail "$1: uninstall left traces (lines above: < before, > after)"
  fi
  vm sh -c 'test ! -e /run/scrim' || fail "$1: /run/scrim is left"
  echo "$1: file system identical to the snapshot taken before install"
}

test_system() {
  log "system: snapshot"
  vm sh -c '/opt/scrim-test/snapshot.sh > /tmp/before.txt'

  log "system: install --dry-run changes nothing"
  vm /opt/scrim-test/scrim install --system --agent-user alice --dry-run
  vm sh -c '/opt/scrim-test/snapshot.sh > /tmp/after.txt; diff -q /tmp/before.txt /tmp/after.txt' || fail "dry run changed the file system"

  log "system: install"
  vm /opt/scrim-test/scrim install --system --agent-user alice
  [ "$(vm systemctl is-active scrim.service)" = active ] || fail "scrim.service is not active"
  vm stat -c '%n %U:%G %a' /run/scrim/api.sock /run/scrim/admin.sock /etc/scrim/config.yaml /var/lib/scrim
  vm sh -c 'stat -c %U:%G:%a /run/scrim/api.sock | grep -qx scrim:scrim-agents:660' || fail "api.sock ownership"
  vm sh -c 'stat -c %U:%a /run/scrim/admin.sock | grep -qx scrim:600' || fail "admin.sock ownership"
  vm sh -c 'ps -o user= -C scrim | sort -u | grep -qx scrim' || fail "scrim does not run as the scrim user"
  vm systemd-analyze security scrim.service --no-pager | tail -1 || true

  log "system: test configuration in conf.d (the generated config.yaml stays as written)"
  vm sh -c "install -d -m 0700 -o scrim -g scrim /var/lib/scrim-test/vm &&
    printf %s '$secret' > /var/lib/scrim-test/vm/token && chown scrim:scrim /var/lib/scrim-test/vm/token &&
    chmod 0600 /var/lib/scrim-test/vm/token && mkdir -p /etc/scrim/conf.d &&
    cat > /etc/scrim/conf.d/test.yaml <<'EOF'
apiVersion: scrim.dev/v1
kind: Config
stores:
  vm: {kind: file, root: /var/lib/scrim-test, format: raw, redact: ['vm://vm/*']}
proxy:
  upstream: {anthropic: 'http://127.0.0.1:18089', openai: 'http://127.0.0.1:18089'}
EOF
    systemctl restart scrim.service"
  for _ in $(seq 60); do vm /usr/local/bin/scrim status --json 2>/dev/null | jq -e '.data_plane.running' >/dev/null && break; sleep 0.5; done

  log "system: test agent as alice (scrim-agents) through scrim run"
  vm runuser -u alice -- /usr/local/bin/scrim run -- /opt/scrim-test/agent.sh "$secret"
  check_provider 1

  log "system: a client trusting only the system store, through the forward proxy"
  vm runuser -u alice -- curl -fsS -o /dev/null --proxy http://127.0.0.1:9791 https://api.anthropic.com/v1/messages \
    -H 'content-type: application/json' -H 'x-api-key: test' -H 'anthropic-version: 2023-06-01' \
    -d "{\"model\":\"m\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"forward $secret\"}]}"
  check_provider 1

  log "system: bob (not in scrim-agents) is refused"
  if vm runuser -u bob -- /usr/local/bin/scrim run -- /bin/true 2>"$work/bob.err"; then
    fail "bob was served"
  fi
  cat "$work/bob.err"

  log "system: scrim status reports the service"
  vm /usr/local/bin/scrim status | sed -n '/^Service/,/^$/p'
  vm /usr/local/bin/scrim status --json | jq -e '.service.active == "active" and .service.system' >/dev/null ||
    fail "status does not report the active system service"

  log "system: the test removes its own configuration"
  vm sh -c 'rm -rf /etc/scrim/conf.d /var/lib/scrim-test'

  log "system: uninstall --purge"
  vm /usr/local/bin/scrim uninstall --system --purge
  vm sh -c '! getent passwd scrim && ! getent group scrim && ! getent group scrim-agents' || fail "accounts left"
  compare system
}

test_user() {
  log "user: lingering session for alice"
  # What `loginctl enable-linger alice` does; logind's D-Bus call fails in a
  # container (ENOLINK), the linger file and the user manager do not.
  vm sh -c 'mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/alice && systemctl start user@1000.service'
  for _ in $(seq 60); do vm test -S /run/user/1000/systemd/private && break; sleep 0.5; done
  vm sh -c "mkdir -p /home/alice/.config/scrim/secrets/vm && printf %s '$secret' > /home/alice/.config/scrim/secrets/vm/token &&
    chmod -R go-rwx /home/alice/.config/scrim && cat > /home/alice/.config/scrim/config.yaml <<'EOF'
apiVersion: scrim.dev/v1
kind: Config
stores:
  vm: {kind: file, root: /home/alice/.config/scrim/secrets, format: raw, redact: ['vm://vm/*']}
proxy:
  upstream: {anthropic: 'http://127.0.0.1:18089', openai: 'http://127.0.0.1:18089'}
EOF
    chown -R alice:alice /home/alice/.config"

  log "user: snapshot"
  vm sh -c '/opt/scrim-test/snapshot.sh > /tmp/before.txt'

  log "user: install"
  as_alice /opt/scrim-test/scrim install --user
  [ "$(as_alice systemctl --user is-active scrim.service)" = active ] || fail "the user unit is not active"

  log "user: test agent through scrim run"
  as_alice /home/alice/.local/bin/scrim run -- /opt/scrim-test/agent.sh "$secret"
  check_provider 1

  log "user: scrim status reports the service"
  as_alice /home/alice/.local/bin/scrim status | sed -n '/^Service/,/^$/p'
  as_alice /home/alice/.local/bin/scrim status --json | jq -e '.service.active == "active" and (.service.system | not)' >/dev/null ||
    fail "status does not report the active user service"

  log "user: uninstall --purge"
  as_alice /home/alice/.local/bin/scrim uninstall --user --purge
  compare user
}

for m in $modes; do
  "test_$m"
done
log "PASS: $modes"
