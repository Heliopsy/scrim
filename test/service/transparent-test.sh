#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Host-level interception test (tasks 13.3, 13.5, 15.2) in a disposable
# systemd host under rootless podman, with its own network namespace and
# NET_ADMIN inside it: the real `scrim install --system --transparent` and
# `--dns`, nftables, an agent user, a user nobody covers, a Java client and
# curl. Nothing touches this host's nftables, /etc, trust store or systemd.
#
# The stand-in "real provider" is a fake provider on 198.51.100.10 (a dummy
# interface), ports 80 and 443 in plain HTTP: whatever reaches it went
# around scrim. scrim's own upstream is a second fake provider on loopback
# (as a local chained upstream would be), and in DNS mode a third one that
# scrim reaches by name through a stand-in name server (dnsmasq on
# 198.51.100.53), past the /etc/hosts override that points the name at scrim.
#
#   test/service/transparent-test.sh                 # builds bin/scrim with `just build`
#   SCRIM_SVC_BIN=path/to/scrim test/service/transparent-test.sh
#
# SCRIM_SVC_KEEP_IMAGE=1 keeps the test image.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
image=localhost/scrim-tp-debian:test
name="scrim-tp-$$"
work="$(mktemp -d "${TMPDIR:-/tmp}/scrim-tp.XXXXXX")"
chmod 0755 "$work"
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
install -m 0644 "$here/Client.java" "$work/Client.java"

if ! podman image exists "$image"; then
  podman build -q -t "$image" -f "$here/Containerfile.transparent" "$here" >/dev/null
  built_image=1
fi

podman run -d --name "$name" --systemd=always --cap-add SYS_ADMIN,NET_ADMIN,NET_RAW \
  -v "$work:/opt/scrim-test:ro" "$image" >/dev/null
vm() { podman exec "$name" "$@"; }

for _ in $(seq 60); do
  s="$(vm systemctl is-system-running 2>/dev/null || true)"
  case "$s" in running | degraded) break ;; esac
  sleep 0.5
done

log "setup: stand-in provider, name server and test configuration (outside the snapshot or removed before it)"
vm sh -c 'ip link add prov0 type dummy && ip addr add 198.51.100.10/32 dev prov0 &&
  ip addr add 198.51.100.53/32 dev prov0 && ip link set prov0 up'
fake() { vm systemd-run --quiet --unit "$1" /opt/scrim-test/scrim-fakeprovider -listen "$2"; }
fake scrim-tp-up 127.0.0.1:18089       # scrim's upstream (loopback, like a chained proxy)
fake scrim-tp-direct443 198.51.100.10:443 # the provider, reached around scrim
fake scrim-tp-direct80 198.51.100.10:80
fake scrim-tp-dnsup 198.51.100.10:18091 # scrim's upstream by name in DNS mode
vm systemd-run --quiet --unit scrim-tp-dns dnsmasq --keep-in-foreground --no-hosts --no-resolv \
  --listen-address=198.51.100.53 --bind-interfaces --address=/api.anthropic.com/198.51.100.10
# The provider name resolves to the stand-in provider, the name server is the stand-in.
vm sh -c 'echo "198.51.100.10 api.anthropic.com" >> /etc/hosts; echo "nameserver 198.51.100.53" > /etc/resolv.conf'
# A JDK whose truststore is its own file, as a vendor JDK in /opt has: a
# copy of the distribution's store, edited only through --java-home.
vm sh -c 'mkdir -p /opt/jdk-extra/lib/security /opt/jdk-extra/bin && cp /etc/ssl/certs/java/cacerts /opt/jdk-extra/lib/security/cacerts &&
  ln -s "$(readlink -f "$(command -v keytool)")" /opt/jdk-extra/bin/keytool'
secret="tp-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
for _ in $(seq 40); do vm curl -fsS -o /dev/null http://198.51.100.10:443/_fake/exchanges 2>/dev/null && break; sleep 0.25; done

exchanges() { vm curl -fsS "http://$1/_fake/exchanges" | jq length; }
reset() { vm curl -fsS -X POST "http://$1/_fake/reset" >/dev/null; }
check_redacted() {
  local addr="$1" want="$2" ex n
  ex="$(vm curl -fsS "http://$addr/_fake/exchanges")"
  n="$(jq length <<<"$ex")"
  [ "$n" = "$want" ] || fail "scrim's upstream $addr saw $n requests, want $want"
  if grep -qF "$secret" <<<"$ex"; then fail "the secret reached the provider"; fi
  grep -q '⟦scrim:' <<<"$ex" || fail "no placeholder reached the provider"
  reset "$addr"
  echo "scrim's upstream: $n request(s), secret absent, placeholder present"
}
check_direct_untouched() {
  local n80 n443
  n443="$(exchanges 198.51.100.10:443)"
  n80="$(exchanges 198.51.100.10:80)"
  [ "$n443" = 0 ] && [ "$n80" = 0 ] || fail "the stand-in provider was reached directly ($n443 on 443, $n80 on 80)"
  echo "stand-in provider: not reached directly"
}
msg() { printf '{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"%s %s"}]}' "$1" "$secret"; }
agent_curl() { # agent_curl USER URL TAG [curl args...]
  local u="$1" url="$2" tag="$3"
  shift 3
  vm runuser -u "$u" -- curl -fsS -o /dev/null --max-time 15 "$url" -H 'content-type: application/json' \
    -H 'x-api-key: test' -H 'anthropic-version: 2023-06-01' -d "$(msg "$tag")" "$@"
}

conf_d() {
  vm sh -c "install -d -m 0700 -o scrim -g scrim /var/lib/scrim-test/vm &&
    printf %s '$secret' > /var/lib/scrim-test/vm/token && chown scrim:scrim /var/lib/scrim-test/vm/token &&
    chmod 0600 /var/lib/scrim-test/vm/token && mkdir -p /etc/scrim/conf.d &&
    cat > /etc/scrim/conf.d/test.yaml <<EOF
apiVersion: scrim.dev/v1
kind: Config
stores:
  vm: {kind: file, root: /var/lib/scrim-test, format: raw, redact: ['vm://vm/*']}
proxy:
  upstream: {anthropic: '$1', openai: 'http://127.0.0.1:18089'}
EOF
    systemctl restart scrim.service"
  for _ in $(seq 60); do vm /usr/local/bin/scrim status --json 2>/dev/null | jq -e '.data_plane.healthy' >/dev/null && break; sleep 0.5; done
}

# Left out of the byte comparison, besides what snapshot.sh leaves out: the
# Java keystores (compared by content in java_trust) and dpkg's backup of its
# status file, which Debian's ca-certificates-java hook rewrites when it runs
# dpkg triggers on every trust store update (the status file itself is
# compared).
snap_skip=' /etc/ssl/certs/java/cacerts$| /opt/jdk-extra/lib/security/cacerts$| /var/lib/dpkg/status-old$'

# java_trust lists the certificates (by fingerprint) of the default Java
# truststore and the extra JDK's. The keystore files are rewritten when the
# trust tool rebuilds them, so they are compared by content, not bytes.
java_trust() {
  vm sh -c "for s in /etc/ssl/certs/java/cacerts /opt/jdk-extra/lib/security/cacerts; do
    keytool -list -keystore \$s -storepass changeit 2>/dev/null | grep 'fingerprint' | sort; done > /tmp/$1.java"
}

compare() {
  java_trust after
  vm diff /tmp/before.java /tmp/after.java || fail "$1: the Java truststores differ (< before, > after)"
  vm sh -c "/opt/scrim-test/snapshot.sh | grep -v -E '$snap_skip' > /tmp/after.txt; nft list ruleset > /tmp/after.nft"
  if ! vm diff /tmp/before.txt /tmp/after.txt; then
    fail "$1: uninstall left traces in the file system (< before, > after)"
  fi
  if ! vm diff /tmp/before.nft /tmp/after.nft; then
    fail "$1: uninstall left nftables rules (< before, > after)"
  fi
  vm sh -c 'test ! -e /run/scrim' || fail "$1: /run/scrim is left"
  echo "$1: file system and nft list ruleset identical to the snapshot taken before install"
}

snapshot_before() {
  vm sh -c "/opt/scrim-test/snapshot.sh | grep -v -E '$snap_skip' > /tmp/before.txt; nft list ruleset > /tmp/before.nft"
  java_trust before
}

# ---------------------------------------------------------------- transparent

log "transparent: snapshot (file system and nft list ruleset)"
snapshot_before
vm nft list ruleset | wc -l | xargs echo "nftables lines before:"

log "transparent: dry run changes nothing"
vm /opt/scrim-test/scrim install --system --transparent --cover-user agent1 --cover-cgroup agents.slice \
  --java-home /opt/jdk-extra --dry-run
vm sh -c "/opt/scrim-test/snapshot.sh | grep -v -E '$snap_skip' > /tmp/after.txt; diff -q /tmp/before.txt /tmp/after.txt" ||
  fail "dry run changed the file system"

log "transparent: install --system --transparent --cover-user agent1 --cover-cgroup agents.slice --java-home /opt/jdk-extra"
vm /opt/scrim-test/scrim install --system --transparent --cover-user agent1 --cover-cgroup agents.slice --java-home /opt/jdk-extra
vm nft list table inet scrim
[ "$(vm systemctl is-active scrim-transparent.service)" = active ] || fail "scrim-transparent.service is not active"
conf_d http://127.0.0.1:18089
vm /usr/local/bin/scrim status | sed -n '/^Interception/,/^$/p;/direct egress/p'

log "transparent: agent1 (covered, no scrim configuration) reaches the provider by name: redacted"
vm runuser -u agent1 -- env | grep -i -E 'proxy|anthropic|ssl_cert' && fail "agent1 has scrim configuration"
agent_curl agent1 https://api.anthropic.com/v1/messages plain
check_redacted 127.0.0.1:18089 1
check_direct_untouched

log "transparent: agent1 by address: TLS without a server name, plain HTTP to 443 and 80: all fail"
agent_curl agent1 https://198.51.100.10/v1/messages byip -k && fail "TLS by address got through"
agent_curl agent1 http://198.51.100.10:443/v1/messages byip-http443 && fail "plain HTTP to 443 by address got through"
agent_curl agent1 http://198.51.100.10/v1/messages byip-http80 && fail "plain HTTP to 80 by address got through"
agent_curl agent1 https://not-a-route.test/v1/messages fronted -k --resolve not-a-route.test:443:198.51.100.10 &&
  fail "a borrowed server name toward the provider address got through"
check_direct_untouched
echo "agent1: every connection by address refused"

log "transparent: a client in agents.slice (user bob) is covered too"
vm systemd-run --quiet --wait --pipe --slice=agents.slice -p User=bob curl -fsS -o /dev/null --max-time 15 \
  https://api.anthropic.com/v1/messages -H 'content-type: application/json' -H 'x-api-key: test' \
  -H 'anthropic-version: 2023-06-01' -d "$(msg cgroup)"
check_redacted 127.0.0.1:18089 1
check_direct_untouched

log "transparent: bob outside the covered user and slice is untouched (reaches the stand-in directly)"
vm runuser -u bob -- curl -fsS -o /dev/null --max-time 10 http://api.anthropic.com:443/_fake/exchanges
vm runuser -u bob -- curl -fsS -o /dev/null --max-time 10 http://198.51.100.10/_fake/exchanges
echo "bob: direct connections work as before"

log "transparent: Java client (distribution JDK, default truststore) as agent1: trusts scrim, redacted"
vm runuser -u agent1 -- java -XX:-UseContainerSupport /opt/scrim-test/Client.java https://api.anthropic.com/v1/messages "$secret"
check_redacted 127.0.0.1:18089 1
check_direct_untouched

log "transparent: Java client with a JDK truststore the system trust tool does not manage (--java-home)"
vm runuser -u agent1 -- java -XX:-UseContainerSupport -Djavax.net.ssl.trustStore=/opt/jdk-extra/lib/security/cacerts \
  -Djavax.net.ssl.trustStorePassword=changeit /opt/scrim-test/Client.java https://api.anthropic.com/v1/messages "$secret"
check_redacted 127.0.0.1:18089 1
check_direct_untouched

log "transparent: fails closed while scrim is stopped"
vm systemctl stop scrim.service
agent_curl agent1 https://api.anthropic.com/v1/messages stopped && fail "agent1 got through with scrim stopped"
check_direct_untouched
vm nft list table inet scrim >/dev/null || fail "the rules went away with scrim"
echo "scrim stopped: agent1's connection failed, rules still loaded"
vm systemctl start scrim.service

log "transparent: test configuration removed, uninstall --purge"
vm sh -c 'rm -rf /etc/scrim/conf.d /var/lib/scrim-test'
vm /usr/local/bin/scrim uninstall --system --purge
compare transparent
log "transparent: after uninstall agent1 is untouched again"
vm runuser -u agent1 -- curl -fsS -o /dev/null --max-time 10 http://api.anthropic.com:443/_fake/exchanges
reset 198.51.100.10:443
reset 198.51.100.10:80

# ---------------------------------------------------------------- DNS override

log "dns: the test's own name mapping is removed; snapshot"
# /etc/hosts is a bind mount in the container: rewritten in place.
vm sh -c 'grep -v "198.51.100.10 api.anthropic.com" /etc/hosts > /tmp/hosts && cat /tmp/hosts > /etc/hosts'
snapshot_before

log "dns: install --system --dns --dns-host api.anthropic.com"
vm /opt/scrim-test/scrim install --system --dns --dns-host api.anthropic.com
vm grep -A2 'BEGIN scrim' /etc/hosts
# scrim reaches its upstream by the same name: through the name servers, not /etc/hosts.
conf_d http://api.anthropic.com:18091
vm /usr/local/bin/scrim status | sed -n '/^Interception/,/^$/p'
vm /usr/local/bin/scrim status --json | jq -e '.interception_modes | any(test("does not stop connections made by address"))' >/dev/null ||
  fail "status does not report the DNS override gap"

log "dns: bob (no configuration) resolves the provider name to scrim: redacted"
agent_curl bob https://api.anthropic.com/v1/messages dns
check_redacted 198.51.100.10:18091 1
check_direct_untouched

log "dns: a connection by address bypasses the override (documented)"
vm runuser -u bob -- curl -fsS -o /dev/null --max-time 10 http://198.51.100.10:443/_fake/exchanges && echo "bob by address: reached the stand-in directly, as documented"
reset 198.51.100.10:443

log "dns: uninstall --purge"
vm sh -c 'rm -rf /etc/scrim/conf.d /var/lib/scrim-test'
vm /usr/local/bin/scrim uninstall --system --purge
compare dns

log "PASS: transparent, Java, DNS override"
