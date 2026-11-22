#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Guest side of test/ebpf/install-test.sh, run by scrim-vmtest.service at
# every boot of the throwaway VM: phase 1 on the first boot, phase 2 after
# the reboot. Ends with "SCRIM-VM-RESULT <code>" on the console and powers
# the VM off. Its own files live in /opt/scrim-test, outside the snapshot.
#
# The stand-in provider is a fake provider on 10.99.0.1 (on lo), ports 443
# and 80 in plain HTTP: whatever reaches it went around scrim. To see where
# redirected connections land, scrim.service is stopped for a moment and a
# second fake provider takes its transparent listener's port, 127.0.0.1:9793.
# scrim's own listener cannot serve them yet: it routes by the original
# destination nftables leaves (SO_ORIGINAL_DST), which a connect redirect
# does not set (tasks.md 15.1b).
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

# in_slice CMD...: CMD as bob in agents.slice, a user with no scrim configuration.
in_slice() { systemd-run --quiet --wait --pipe --slice=agents.slice -p User=bob "$@"; }
post() { # post URL: one provider request in plain HTTP
  curl -fsS -o /dev/null --max-time 10 "$1" -H 'content-type: application/json' -H 'x-api-key: test' \
    -H 'anthropic-version: 2023-06-01' -d '{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}'
}

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

# redirected: with scrim stopped and a fake provider on its port, connections
# of agents.slice to ports 80 and 443 of the stand-in provider land on
# 127.0.0.1:9793; with nothing there they fail; nothing reaches the
# stand-in; the programs stay attached throughout.
redirected() {
  systemctl stop scrim.service
  fake listener 127.0.0.1:9793
  in_slice /bin/sh -c "$(declare -f post); post http://10.99.0.1/v1/messages && post http://10.99.0.1:443/v1/messages"
  check 127.0.0.1:9793 2 "transparent listener port 127.0.0.1:9793"
  check_direct 0
  systemctl stop scrim-vmtest-listener.service
  if in_slice /bin/sh -c "$(declare -f post); post http://10.99.0.1:443/v1/messages"; then
    fail "a connection got through with nothing listening on 9793"
  fi
  check_direct 0
  [ "$(ebpf_state /usr/local/bin/scrim)" = active ] || fail "the programs went away while scrim was stopped"
  echo "nothing on 9793: the connection failed, nothing went direct, the programs stayed attached"
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

  log "agents.slice is redirected to the transparent listener's port"
  redirected

  log "a process outside agents.slice is untouched"
  runuser -u bob -- /bin/sh -c "$(declare -f post); post http://10.99.0.1:443/v1/messages"
  check_direct 1

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

  log "agents.slice is still redirected"
  redirected

  log "uninstall --purge"
  "$t/scrim" uninstall --system --purge
  [ "$(systemctl show -p LoadState --value scrim-ebpf.service)" = not-found ] || fail "scrim-ebpf.service is still loaded"
  [ -z "$(ls -A /sys/fs/bpf/scrim 2>/dev/null)" ] || fail "pins left in /sys/fs/bpf/scrim: $(ls /sys/fs/bpf/scrim)"
  [ -z "$(ebpf_state "$t/scrim")" ] || fail "scrim ebpf status still lists agents.slice"
  echo "detached: no unit, no pins, nothing recorded"

  log "after uninstall agents.slice reaches the stand-in provider directly"
  in_slice /bin/sh -c "$(declare -f post); post http://10.99.0.1:443/v1/messages"
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
