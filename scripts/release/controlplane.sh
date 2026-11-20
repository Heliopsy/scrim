#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/controlplane.sh PLATFORM DATAPLANE OUT
#
# Builds the `scrim` release binary for PLATFORM with the data plane binary
# DATAPLANE embedded (design D11), and writes it to OUT.
#
# The data plane is copied to SCRIM_DATAPLANE_EMBED for the length of one
# `go build` and whatever was there before is put back afterwards, so builds
# for several platforms run one after another from the same tree and cannot
# pick up each other's data plane. Do not run two of these in parallel in one
# checkout.
#
# Static and reproducible: CGO_ENABLED=0, -trimpath, no VCS stamping (the
# commit is stamped through -X instead, so a replaced embed file cannot mark
# the build "modified"), and the commit time as the only date.
. "$(dirname "$0")/lib.sh"

[ $# -eq 3 ] || die "usage: $0 PLATFORM DATAPLANE OUT"
platform=$1 dataplane=$2 out=$3
rust_target "$platform" >/dev/null
[ -f "$dataplane" ] || die "no data plane binary at $dataplane"
check_binary "$dataplane" "$platform"

embed="$ROOT/$SCRIM_DATAPLANE_EMBED"
mkdir -p "$(dirname "$embed")"
backup=""
if [ -e "$embed" ]; then
  backup=$(mktemp)
  cp -p "$embed" "$backup"
fi
restore() {
  if [ -n "$backup" ]; then
    mv -f "$backup" "$embed"
  else
    rm -f "$embed"
  fi
}
trap restore EXIT
install -m 0755 "$dataplane" "$embed"

pkg=$SCRIM_GO_VERSION_PKG
ldflags="-s -w -X $pkg.Version=$SCRIM_VERSION -X $pkg.Commit=$SCRIM_COMMIT -X $pkg.Date=$SCRIM_DATE"

log "control plane $SCRIM_VERSION for $platform"
mkdir -p "$(dirname "$out")"
(
  cd "$ROOT"
  CGO_ENABLED=0 GOOS=${platform%-*} GOARCH=${platform#*-} GOFLAGS=-mod=readonly \
    go build -trimpath -buildvcs=false \
    -tags "$SCRIM_GO_TAGS" \
    -ldflags "$ldflags" \
    -o "$out" "$SCRIM_GO_MAIN"
)
chmod 0755 "$out"
check_binary "$out" "$platform"

# The embedded copy must be byte-for-byte the data plane that ships beside it.
# A build that embedded a stale or wrong-architecture file would otherwise pass
# every other check here.
python3 -I - "$out" "$dataplane" <<'EOF' || die "$out does not contain $dataplane byte for byte"
import sys
outer = open(sys.argv[1], "rb").read()
inner = open(sys.argv[2], "rb").read()
sys.exit(0 if inner and outer.find(inner) >= 0 else 1)
EOF
log "$out $(sha256 "$out")"
