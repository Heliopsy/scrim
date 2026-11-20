#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/chart.sh package OUTDIR   package the chart at SCRIM_VERSION, print the .tgz
# scripts/release/chart.sh push TGZ         push it to oci://SCRIM_CHART_REPOSITORY, print the digest
#
# The chart's version and appVersion are the release version, and its image
# list names the scrim image of that version: the lines release-please keeps
# current (marked x-release-please-version) are set from SCRIM_VERSION on a
# copy of the chart, so a hand-pushed pre-release tag packages right too.
. "$(dirname "$0")/lib.sh"

cmd=${1:-}
case "$cmd" in
  package)
    [ $# -eq 2 ] || die "usage: $0 package OUTDIR"
    out=$2
    mkdir -p "$out"
    out=$(cd "$out" && pwd)
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    cp -r "$ROOT/$SCRIM_CHART_DIR" "$work/scrim"
    # Every semver on a marked line becomes the release version.
    sed -i -E "/x-release-please-version/ s/[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/$SCRIM_VERSION/" "$work/scrim/Chart.yaml"
    got=$(sed -n 's/^version: *\([^ ]*\).*/\1/p' "$work/scrim/Chart.yaml")
    [ "$got" = "$SCRIM_VERSION" ] || die "Chart.yaml version is $got after stamping, want $SCRIM_VERSION"
    grep -q "image: $SCRIM_IMAGE_REGISTRY/scrim:$SCRIM_VERSION" "$work/scrim/Chart.yaml" \
      || die "Chart.yaml's image list does not name $SCRIM_IMAGE_REGISTRY/scrim:$SCRIM_VERSION"
    helm package "$work/scrim" -d "$out" >&2
    tgz="$out/scrim-$SCRIM_VERSION.tgz"
    [ -f "$tgz" ] || die "helm package wrote no $tgz"
    echo "$tgz"
    ;;
  push)
    [ $# -eq 2 ] || die "usage: $0 push TGZ"
    # helm prints "Digest: sha256:..." on stderr.
    res=$(helm push "$2" "oci://$SCRIM_CHART_REPOSITORY" 2>&1) || die "helm push failed: $res"
    digest=$(sed -n 's/^Digest: *//p' <<<"$res")
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "no digest in: $res"
    echo "$digest"
    ;;
  *) die "usage: $0 package OUTDIR | push TGZ" ;;
esac
