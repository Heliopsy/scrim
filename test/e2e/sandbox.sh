#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs a command in a private network and mount namespace for the end-to-end
# tests under test/e2e:
#
# - the network namespace has loopback only, so nothing can reach a real
#   provider or any other host on the internet;
# - /etc/hosts is replaced (inside the namespace only) so the tests' tool
#   hosts (*.scrim.test) resolve to loopback addresses by name;
# - ports below 1024 can be bound, so the test hosts listen on 443;
# - the command runs as the calling user again (a nested user namespace maps
#   the namespace's root back to the caller's uid and gid).
#
# Nothing outside the namespaces changes. Needs unprivileged user namespaces
# (util-linux unshare 2.38 or later); on Ubuntu 24.04 with AppArmor's
# restriction on, run `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` first.
#
#   test/e2e/sandbox.sh <command> [args...]
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi
if [ "${1:-}" = "--inner" ]; then
  shift
  hosts="$1" uid="$2" gid="$3"
  shift 3
  ip link set lo up
  sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
  mount --bind "$hosts" /etc/hosts
  exec unshare --user --map-user="$uid" --map-group="$gid" -- env SCRIM_E2E_SANDBOX=1 "$@"
fi

if ! unshare --user --map-root-user --net --mount true 2>/dev/null; then
  echo "sandbox: unprivileged user and network namespaces are not available here" >&2
  exit 3
fi
dir="$(mktemp -d "${TMPDIR:-/tmp}/scrim-e2e-sandbox.XXXXXX")"
trap 'rm -rf "$dir"' EXIT
cat > "$dir/hosts" <<HOSTS
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
127.0.0.2 api.scrim.test
127.0.0.3 git.scrim.test
127.0.0.4 other.scrim.test
# Tool profile tests: the hosts real CLIs talk to by default, all served by
# one fake on 127.0.0.10 (test/e2e/profiles). Nothing here is reachable
# outside the namespace.
127.0.0.10 api.github.com github.com uploads.github.com registry.npmjs.org app.terraform.io
127.0.0.10 cloudresourcemanager.googleapis.com login.microsoftonline.com management.azure.com
127.0.0.10 upload.pypi.org crates.io index.crates.io static.crates.io api.hetzner.cloud
127.0.0.10 api.digitalocean.com k8s.scrim.test registry.scrim.test pypi.scrim.test
HOSTS
chmod 0644 "$dir/hosts"
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
unshare --user --map-root-user --net --mount -- "$self" --inner "$dir/hosts" "$(id -u)" "$(id -g)" "$@"
