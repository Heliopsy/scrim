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
    helm package "$work/scrim" -d "$work/pkg" >&2
    [ -f "$work/pkg/scrim-$SCRIM_VERSION.tgz" ] || die "helm package wrote no scrim-$SCRIM_VERSION.tgz"
    # helm stamps every entry with the current time, so the same commit gave a
    # different digest on every run. Repack with the commit time, sorted
    # entries and no owner or gzip timestamp, so the package is reproducible.
    mkdir "$work/x"
    tar -xzf "$work/pkg/scrim-$SCRIM_VERSION.tgz" -C "$work/x"
    tgz="$out/scrim-$SCRIM_VERSION.tgz"
    tar -C "$work/x" --sort=name --mtime="@${SOURCE_DATE_EPOCH:?}" --owner=0 --group=0 --numeric-owner \
      --format=gnu -cf - scrim | gzip -9n > "$tgz"
    echo "$tgz"
    ;;
  push)
    [ $# -eq 2 ] || die "usage: $0 push TGZ"
    # A version that is already published is not pushed again (the registry
    # refuses to retag it). Its files must be exactly the ones built here;
    # then its digest is the one to sign and attest.
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    mkdir "$work/pub"
    if res=$(helm pull "oci://$SCRIM_CHART_REPOSITORY/scrim" --version "$SCRIM_VERSION" -d "$work/pub" 2>&1); then
      mkdir "$work/a" "$work/b"
      tar -xzf "$work/pub/scrim-$SCRIM_VERSION.tgz" -C "$work/a"
      tar -xzf "$2" -C "$work/b"
      diff -r "$work/a" "$work/b" >&2 || die "scrim $SCRIM_VERSION is already published with different files"
      digest=$(sed -n 's/^Digest: *//p' <<<"$res")
      [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "no digest in: $res"
      log "scrim $SCRIM_VERSION is already published with these files: using $digest"
      echo "$digest"
      exit 0
    elif ! grep -qiE 'not found|manifest unknown|name unknown' <<<"$res"; then
      # Only a version the registry does not have is pushed; any other error
      # (auth, network) stops here instead of trying to overwrite.
      die "could not check whether scrim $SCRIM_VERSION is published: $res"
    fi
    # helm prints "Digest: sha256:..." on stderr.
    res=$(helm push "$2" "oci://$SCRIM_CHART_REPOSITORY" 2>&1) || die "helm push failed: $res"
    digest=$(sed -n 's/^Digest: *//p' <<<"$res")
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "no digest in: $res"
    echo "$digest"
    ;;
  *) die "usage: $0 package OUTDIR | push TGZ" ;;
esac
