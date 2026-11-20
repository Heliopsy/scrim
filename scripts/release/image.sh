#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/image.sh build NAME BIN_DIR
#   Builds the image NAME (scrim or scrim-dataplane) for linux/amd64 and
#   linux/arm64 from BIN_DIR/linux-<arch>/<binary>, assembles a manifest list
#   localhost/scrim-rel/NAME:VERSION, and runs the host architecture's image
#   with a read-only root filesystem as a smoke test.
#
# scripts/release/image.sh push NAME
#   Pushes that list and both images to SCRIM_IMAGE_REGISTRY/NAME under every
#   tag `tags` prints, and writes the pushed list's digest to stdout. The
#   registry login must already be in place.
#
# scripts/release/image.sh tags
#   The tags one release publishes: VERSION, MAJOR.MINOR and latest for a
#   release, VERSION alone for a pre-release, so an rc never moves latest.
#
# scripts/release/image.sh clean NAME
#   Removes the local images and list.
#
# Rootless podman only. The image is byte-reproducible: base pinned by digest,
# every timestamp set to SOURCE_DATE_EPOCH, no build-tool identity label, and
# the binaries copied in are the release binaries.
. "$(dirname "$0")/lib.sh"

engine=podman
cleanup=()
trap 'rm -rf "${cleanup[@]}"' EXIT
command -v "$engine" >/dev/null || die "podman is required"

containerfile() {
  case "$1" in
    scrim) echo "$ROOT/Containerfile" ;;
    "$SCRIM_DATAPLANE_BIN") echo "$ROOT/Containerfile.dataplane" ;;
    *) die "unknown image: $1 (want scrim or $SCRIM_DATAPLANE_BIN)" ;;
  esac
}

version_cmd() {
  case "$1" in
    scrim) echo "$SCRIM_VERSION_CMD" ;;
    *) echo "$SCRIM_DATAPLANE_VERSION_CMD" ;;
  esac
}

local_ref() {
  echo "localhost/scrim-rel/$1:${SCRIM_VERSION//+/_}${2:+-$2}"
}

host_arch() {
  case "$(uname -m)" in
    x86_64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) die "unsupported host architecture $(uname -m)" ;;
  esac
}

cmd_tags() {
  local v=$SCRIM_VERSION
  case "$v" in
    *[!0-9.]*)
      # A pre-release or a dev build: the exact version only. `+` is not
      # allowed in a tag.
      echo "${v//+/_}"
      ;;
    *.*.*)
      printf '%s\n%s\nlatest\n' "$v" "${v%.*}"
      ;;
    *) die "not a release version: $v" ;;
  esac
}

cmd_build() {
  local name=$1 bin_dir=$2 file context arch list
  file=$(containerfile "$name")
  context=$(mktemp -d)
  cleanup+=("$context")
  mkdir -p "$context/state"
  for arch in amd64 arm64; do
    [ -f "$bin_dir/linux-$arch/$name" ] || die "missing $bin_dir/linux-$arch/$name"
    check_binary "$bin_dir/linux-$arch/$name" "linux-$arch"
    mkdir -p "$context/linux-$arch"
    cp "$bin_dir/linux-$arch/$name" "$context/linux-$arch/$name"
  done
  touch -d "@$SOURCE_DATE_EPOCH" "$context/state"

  for arch in amd64 arm64; do
    log "image $(local_ref "$name" "$arch")"
    "$engine" build \
      --file "$file" \
      --platform "linux/$arch" \
      --format oci \
      --pull=missing \
      --timestamp "$SOURCE_DATE_EPOCH" \
      --identity-label=false \
      --build-arg "VERSION=$SCRIM_VERSION" \
      --build-arg "REVISION=$SCRIM_COMMIT" \
      --build-arg "CREATED=$SCRIM_DATE" \
      --build-arg "SOURCE=$SCRIM_SOURCE_URL" \
      --tag "$(local_ref "$name" "$arch")" \
      "$context"
    if [ "$("$engine" image inspect --format '{{.Architecture}}' "$(local_ref "$name" "$arch")")" != "$arch" ]; then
      die "$(local_ref "$name" "$arch") is not an $arch image"
    fi
  done

  list=$(local_ref "$name")
  "$engine" manifest rm "$list" >/dev/null 2>&1 || true
  "$engine" manifest create "$list" >/dev/null
  for arch in amd64 arm64; do
    "$engine" manifest add "$list" "containers-storage:$(local_ref "$name" "$arch")" >/dev/null
  done

  smoke "$name" "$(local_ref "$name" "$(host_arch)")"
}

# Runs the image the way the deployment spec promises it works: read-only root
# filesystem, a non-root user, no capabilities, a writable state volume for
# scrim. The output must name this build's version, so a stale image or a
# binary that ignored the -X stamp cannot pass.
smoke() {
  local name=$1 ref=$2
  local ctr="scrim-rel-smoke-$name" vol="scrim-rel-smoke-$name" output user args
  "$engine" rm -f "$ctr" >/dev/null 2>&1 || true
  "$engine" volume rm -f "$vol" >/dev/null 2>&1 || true
  args=(run --name "$ctr" --read-only --cap-drop=all --security-opt=no-new-privileges --network=none)
  if [ "$name" = scrim ]; then
    "$engine" volume create "$vol" >/dev/null
    args+=(-v "$vol:/var/lib/scrim")
  fi
  log "smoke test $ref"
  if ! output=$("$engine" "${args[@]}" "$ref" "$(version_cmd "$name")" 2>&1); then
    "$engine" rm -f "$ctr" >/dev/null 2>&1 || true
    "$engine" volume rm -f "$vol" >/dev/null 2>&1 || true
    echo "$output" >&2
    die "$ref did not run"
  fi
  user=$("$engine" inspect --format '{{.Config.User}}' "$ctr")
  "$engine" rm -f "$ctr" >/dev/null
  "$engine" volume rm -f "$vol" >/dev/null 2>&1 || true
  echo "$output" >&2
  [ "$user" = 65532:65532 ] || die "$ref runs as '$user', want 65532:65532"
  grep -qF "$SCRIM_VERSION" <<<"$output" || die "$ref printed no version $SCRIM_VERSION"
}

cmd_push() {
  local name=$1 repo first digest digestfile tag
  repo="$SCRIM_IMAGE_REGISTRY/$name"
  first=$(cmd_tags | head -n 1)
  digestfile=$(mktemp)
  cleanup+=("$digestfile")
  log "push $repo:$first"
  "$engine" manifest push --all --format oci --digestfile "$digestfile" \
    "$(local_ref "$name")" "docker://$repo:$first" >&2
  digest=$(cat "$digestfile")
  # The other tags are copied registry side from the digest just pushed, never
  # pushed again from local storage: podman re-encodes on push, and a second
  # push could leave a tag naming a list nobody signed.
  for tag in $(cmd_tags | tail -n +2); do
    log "tag $repo:$tag -> $digest"
    skopeo copy --all --preserve-digests --quiet \
      "docker://$repo@$digest" "docker://$repo:$tag" >&2
  done
  echo "$digest"
}

cmd_clean() {
  local name=$1 arch
  "$engine" manifest rm "$(local_ref "$name")" >/dev/null 2>&1 || true
  for arch in amd64 arm64; do
    "$engine" rmi -f "$(local_ref "$name" "$arch")" >/dev/null 2>&1 || true
  done
}

case "${1:-}" in
  build) [ $# -eq 3 ] || die "usage: $0 build NAME BIN_DIR"; cmd_build "$2" "$3" ;;
  push) [ $# -eq 2 ] || die "usage: $0 push NAME"; containerfile "$2" >/dev/null; cmd_push "$2" ;;
  tags) cmd_tags ;;
  clean) [ $# -eq 2 ] || die "usage: $0 clean NAME"; cmd_clean "$2" ;;
  *) die "usage: $0 {build NAME BIN_DIR | push NAME | tags | clean NAME}" ;;
esac
