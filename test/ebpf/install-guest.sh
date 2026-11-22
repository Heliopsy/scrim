#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Guest side of test/ebpf/install-test.sh, run by scrim-vmtest.service at
# every boot of the throwaway VM: phase 1 on the first boot, phase 2 after
# the reboot. Ends with "SCRIM-VM-RESULT <code>" on the console and powers
# the VM off. Its own files live in /opt/scrim-test, outside the snapshot.
#
# The stand-in provider is a fake provider on 10.99.0.1 (on lo), ports 443
# and 80 in plain HTTP, which curl resolves api.anthropic.com to: whatever reaches
# it went around scrim. scrim's own upstream is a second fake provider on
# 127.0.0.1:18089 (as in test/service/transparent-test.sh), and a generated
# secret in a file store is what must not reach it. An agent in agents.slice
# runs curl against https://api.anthropic.com with no scrim configuration:
# the eBPF programs redirect it to scrim's transparent listener, which reads
# the original destination through the getsockopt program (tasks.md 15.1b),
# intercepts TLS and forwards the request redacted.
set -euo pipefail

t=/opt/scrim-test
st=$t/state
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

finish() {
  code=$?
  if [ "$code" != 0 ]; then
    echo "-- diagnostics: listening sockets, scrim and scrim-ebpf journals"
    ss -ltn || true
    journalctl -b -u scrim.service -u scrim-ebpf.service --no-pager -o short-monotonic | tail -n 60 || true
  fi
  echo "SCRIM-VM-RESULT $code"
  sync
  systemctl --no-block poweroff
}
trap finish EXIT

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

fake() { # fake NAME ADDRESS: a fake provider as a transient unit, once it answers
  systemd-run --quiet --unit "scrim-vmtest-$1" "$t/scrim-fakeprovider" -listen "$2"
  for _ in $(seq 40); do curl -fsS -o /dev/null "http://$2/_fake/exchanges" 2>/dev/null && return 0; sleep 0.25; done
  fail "fake provider $1 on $2 did not come up"
}

setup() {
  ip addr add 10.99.0.1/32 dev lo
  fake direct443 10.99.0.1:443
  fake direct80 10.99.0.1:80
  fake upstream 127.0.0.1:18089
  [ -s "$st/secret" ] || echo "vm-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" >"$st/secret"
  secret="$(cat "$st/secret")"
}

exchanges() { curl -fsS "http://$1/_fake/exchanges" | jq length; }
reset() { curl -fsS -X POST "http://$1/_fake/reset" >/dev/null; }
check() { # check ADDRESS WANT WHAT: the fake provider at ADDRESS saw WANT requests
  local n
  n="$(exchanges "$1")"
  [ "$n" = "$2" ] || fail "$3 saw $n request(s), want $2"
  reset "$1"
  echo "$3: $n request(s)"
}
check_direct() {
  check 10.99.0.1:443 "$1" "stand-in provider, port 443"
  check 10.99.0.1:80 0 "stand-in provider, port 80"
}

# check_redacted WANT: scrim's upstream saw WANT requests, none with the
# secret, each with a placeholder.
check_redacted() {
  local ex n
  ex="$(curl -fsS http://127.0.0.1:18089/_fake/exchanges)"
  n="$(jq length <<<"$ex")"
  [ "$n" = "$1" ] || fail "scrim's upstream saw $n request(s), want $1"
  if grep -qF "$secret" <<<"$ex"; then fail "the secret reached the provider"; fi
  reset 127.0.0.1:18089
  if [ "$n" = 0 ]; then
    echo "scrim's upstream: no request"
    return
  fi
  grep -q '⟦scrim:' <<<"$ex" || fail "no placeholder reached the provider"
  echo "scrim's upstream: $n request(s), secret absent, placeholder present"
}

# in_slice CMD...: CMD as bob in agents.slice, a user with no scrim configuration.
in_slice() { systemd-run --quiet --wait --pipe --slice=agents.slice -p User=bob "$@"; }
post() { # post URL [curl args...]: one provider request carrying the secret
  local url="$1"
  shift
  curl -fsS -o /dev/null --max-time 15 "$url" -H 'content-type: application/json' -H 'x-api-key: test' \
    -H 'anthropic-version: 2023-06-01' \
    -d "{\"model\":\"m\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"hi $secret\"}]}" "$@"
}
# agent URL [curl args...] and outside URL [curl args...]: post as bob, from
# agents.slice or from outside it.
agent() { in_slice /bin/bash -c "secret=$secret; $(declare -f post); post $(printf '%q ' "$@")"; }
outside() { runuser -u bob -- /bin/bash -c "secret=$secret; $(declare -f post); post $(printf '%q ' "$@")"; }

ebpf_state() {
  "$1" ebpf status --json | jq -r '.cgroups[] | select(.cgroup == "agents.slice") | .state'
}

# wait_scrim waits for the transparent listener without running scrim
# status, which opens the SQLite state itself while the daemon is not up yet
# and would make a starting daemon refuse the locked file.
wait_scrim() {
  for _ in $(seq 120); do
    if [ "$(systemctl is-active scrim.service)" = active ] && [ -S /run/scrim/admin.sock ] &&
      [ -n "$(ss -Hltn 'sport = :9793')" ]; then
      return 0
    fi
    sleep 0.5
  done
  fail "scrim's transparent listener did not come up"
}

# configure gives scrim the test store and upstream (removed before the
# uninstall, so outside the snapshot comparison).
configure() {
  install -d -m 0700 -o scrim -g scrim /var/lib/scrim-test/vm
  printf %s "$secret" >/var/lib/scrim-test/vm/token
  chown scrim:scrim /var/lib/scrim-test/vm/token
  chmod 0600 /var/lib/scrim-test/vm/token
  mkdir -p /etc/scrim/conf.d
  printf '%s\n' 'apiVersion: scrim.dev/v1' 'kind: Config' 'stores:' \
    "  vm: {kind: file, root: /var/lib/scrim-test, format: raw, redact: ['vm://vm/*']}" 'proxy:' \
    "  upstream: {anthropic: 'http://127.0.0.1:18089', openai: 'http://127.0.0.1:18089'}" >/etc/scrim/conf.d/test.yaml
  systemctl restart scrim.service
  wait_scrim
}

wait_healthy() {
  for _ in $(seq 60); do
    /usr/local/bin/scrim status --json 2>/dev/null | jq -e '.data_plane.healthy' >/dev/null && return 0
    sleep 0.5
  done
  fail "scrim's data plane did not become healthy"
}

# redirected: an agent in agents.slice reaches the provider by name through
# scrim's own transparent listener, redacted; by address (no route) it is
# refused; a connection to the listener that the programs did not redirect
# has no original destination and is closed; while scrim is stopped the
# agent fails. Nothing ever reaches the stand-in provider directly, and the
# programs stay attached throughout.
redirected() {
  wait_healthy
  agent https://api.anthropic.com/v1/messages --resolve api.anthropic.com:443:10.99.0.1
  check_redacted 1
  check_direct 0
  echo "agents.slice: redirected through scrim, redacted"

  agent http://10.99.0.1:443/v1/messages && fail "plain HTTP to 443 by address got through"
  agent http://10.99.0.1/v1/messages && fail "plain HTTP to 80 by address got through"
  check_redacted 0
  check_direct 0
  echo "agents.slice by address: refused"

  # bob outside the slice dials the listener itself: not redirected, so the
  # programs hold no original destination for the connection.
  outside https://api.anthropic.com:9793/v1/messages --resolve api.anthropic.com:9793:127.0.0.1 &&
    fail "an IPv4 connection to the listener that was not redirected got through"
  outside https://api.anthropic.com:9793/v1/messages --resolve 'api.anthropic.com:9793:[::1]' &&
    fail "an IPv6 connection to the listener that was not redirected got through"
  check_redacted 0
  check_direct 0
  echo "connections to the listener without an original destination: closed"

  systemctl stop scrim.service
  agent https://api.anthropic.com/v1/messages --resolve api.anthropic.com:443:10.99.0.1 &&
    fail "a connection got through with scrim stopped"
  check_redacted 0
  check_direct 0
  [ "$(ebpf_state /usr/local/bin/scrim)" = active ] || fail "the programs went away while scrim was stopped"
  echo "scrim stopped: the connection failed, nothing went direct, the programs stayed attached"
  systemctl start scrim.service
  wait_scrim
}

phase1() {
  log "phase 1: kernel $(uname -r)"
  setup

  log "snapshot"
  "$t/snapshot.sh" >"$st/before.txt"

  log "install --dry-run as an unprivileged user: prints the units, changes nothing"
  runuser -u bob -- env HOME=/home/bob "$t/scrim" install --system --ebpf --cover-cgroup agents.slice --dry-run | tee "$st/dry-run.txt"
  grep -q '^    ExecStart=/usr/local/bin/scrim ebpf attach --cgroup agents.slice --port 9793 --no-listener-check$' "$st/dry-run.txt" ||
    fail "dry run does not print the eBPF unit"
  grep -q '^    Environment=SCRIM_PROXY_TRANSPARENT_LISTEN=127.0.0.1:9793' "$st/dry-run.txt" || fail "dry run does not print the drop-in"
  grep -q 'lacks CAP_BPF and CAP_NET_ADMIN' "$st/dry-run.txt" || fail "dry run does not name the missing privilege"
  "$t/snapshot.sh" >"$st/after.txt"
  diff -q "$st/before.txt" "$st/after.txt" || fail "the dry run changed the file system"

  log "install as an unprivileged user is refused"
  if runuser -u bob -- env HOME=/home/bob "$t/scrim" install --system --ebpf --cover-cgroup agents.slice 2>"$st/refused.txt"; then
    fail "an unprivileged install went ahead"
  fi
  cat "$st/refused.txt"

  log "install --system --ebpf --cover-cgroup agents.slice"
  "$t/scrim" install --system --ebpf --cover-cgroup agents.slice
  [ "$(systemctl is-active scrim-ebpf.service)" = active ] || fail "scrim-ebpf.service is not active"
  [ "$(systemctl is-enabled scrim-ebpf.service)" = enabled ] || fail "scrim-ebpf.service is not enabled"
  [ "$(ebpf_state /usr/local/bin/scrim)" = active ] || fail "agents.slice is not attached (verified with the kernel)"
  ls /sys/fs/bpf/scrim/*/
  wait_scrim
  ss -Hltn 'sport = :9793' | grep -q '127.0.0.1:9793' || fail "the drop-in did not turn on the transparent listener on 127.0.0.1"
  ss -Hltn 'sport = :9793' | grep -q '\[::1\]:9793' || fail "the drop-in did not turn on the transparent listener on ::1"
  /usr/local/bin/scrim status | sed -n '/^Interception/,/^$/p'

  log "agents.slice is redirected through scrim"
  configure
  redirected

  log "a process outside agents.slice is untouched"
  outside http://10.99.0.1:443/v1/messages
  check_direct 1
  check_redacted 0

  echo 2 >"$st/phase"
}

phase2() {
  log "phase 2, after the reboot"
  setup
  [ "$(systemctl is-active scrim-ebpf.service)" = active ] || fail "scrim-ebpf.service did not start at boot"
  journalctl -b -u scrim-ebpf.service --no-pager -o cat | tail -n 5
  [ "$(ebpf_state /usr/local/bin/scrim)" = active ] || fail "agents.slice is not attached after the reboot"
  attached="$(systemctl show -p ExecMainExitTimestampMonotonic --value scrim-ebpf.service)"
  started="$(systemctl show -p ExecMainStartTimestampMonotonic --value scrim.service)"
  echo "attached at ${attached}us, scrim started at ${started}us (monotonic)"
  [ "$attached" -gt 0 ] && [ "$attached" -le "$started" ] || fail "the programs were not attached before scrim started"
  wait_scrim

  log "agents.slice is still redirected through scrim"
  redirected

  log "test configuration removed, uninstall --purge"
  rm -rf /etc/scrim/conf.d /var/lib/scrim-test
  "$t/scrim" uninstall --system --purge
  [ "$(systemctl show -p LoadState --value scrim-ebpf.service)" = not-found ] || fail "scrim-ebpf.service is still loaded"
  [ -z "$(ls -A /sys/fs/bpf/scrim 2>/dev/null)" ] || fail "pins left in /sys/fs/bpf/scrim: $(ls /sys/fs/bpf/scrim)"
  [ -z "$(ebpf_state "$t/scrim")" ] || fail "scrim ebpf status still lists agents.slice"
  echo "detached: no unit, no pins, nothing recorded"

  log "after uninstall agents.slice reaches the stand-in provider directly"
  agent http://10.99.0.1:443/v1/messages
  check_direct 1

  log "file system identical to the snapshot taken before install"
  "$t/snapshot.sh" >"$st/after.txt"
  diff "$st/before.txt" "$st/after.txt" || fail "uninstall left traces (< before, > after)"
  [ ! -e /run/scrim ] || fail "/run/scrim is left"

  log "uninstall again: nothing to do"
  "$t/scrim" uninstall --system | tee "$st/again.txt"
  grep -q 'nothing to uninstall' "$st/again.txt" || fail "a second uninstall did something"
  echo finished >"$st/phase"
}

case "$(cat "$st/phase" 2>/dev/null || echo 1)" in
  1) phase1 ;;
  2) phase2 ;;
  *) fail "unexpected phase $(cat "$st/phase")" ;;
esac
