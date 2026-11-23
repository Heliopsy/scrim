#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# cargo-fuzz with the pinned nightly toolchain, for .github/workflows/fuzz.yaml
# and the release workflow's fuzzing job.
#
#   scripts/fuzz.sh tools DIR
#       Install the pinned nightly (through rustup) and the cargo-fuzz release
#       binary, checked by sha256, into DIR/bin. Put DIR/bin on PATH.
#   scripts/fuzz.sh list CRATE
#       The fuzz targets of dataplane/crates/CRATE/fuzz, sorted, one line.
#   scripts/fuzz.sh run CRATE TARGET SECONDS [RESULT_JSON]
#       Fuzz TARGET for SECONDS from an empty corpus. With RESULT_JSON, also
#       write {crate, target, seconds, runs, result} there, pass or fail, for
#       the release's published results.
#
# A finding fails the run; its reproducer is under the crate's fuzz/artifacts/.
set -euo pipefail

# renovate: datasource=custom.rust-nightly depName=rust-nightly versioning=regex:^(?<major>\d{4})-(?<minor>\d{2})-(?<patch>\d{2})$
RUST_NIGHTLY_DATE="2026-11-20"
# renovate: datasource=github-releases depName=rust-fuzz/cargo-fuzz
CARGO_FUZZ_VERSION=0.13.2
# sha256: https://github.com/rust-fuzz/cargo-fuzz/releases/download/{version}/cargo-fuzz-{version}-x86_64-unknown-linux-musl.tar.gz
CARGO_FUZZ_SHA256=b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c

root="$(cd "$(dirname "$0")/.." && pwd)"
nightly="+nightly-${RUST_NIGHTLY_DATE}"

die() {
  echo "error: $*" >&2
  exit 1
}

cmd_tools() {
  [ $# -eq 1 ] || die "usage: $0 tools DIR"
  local dir=$1 name
  rustup toolchain install "nightly-${RUST_NIGHTLY_DATE}" --profile minimal
  name="cargo-fuzz-${CARGO_FUZZ_VERSION}-x86_64-unknown-linux-musl"
  mkdir -p "$dir/bin"
  curl -fsSL --retry 5 --retry-all-errors -o "$dir/$name.tar.gz" \
    "https://github.com/rust-fuzz/cargo-fuzz/releases/download/${CARGO_FUZZ_VERSION}/$name.tar.gz"
  echo "$CARGO_FUZZ_SHA256  $dir/$name.tar.gz" | sha256sum -c -
  tar -xzf "$dir/$name.tar.gz" -C "$dir/bin" cargo-fuzz
  rm -f "$dir/$name.tar.gz"
}

cmd_list() {
  [ $# -eq 1 ] || die "usage: $0 list CRATE"
  cd "$root/dataplane/crates/$1/fuzz" || exit 1
  cargo "$nightly" fuzz list | sort | tr '\n' ' ' | sed 's/ $//'
  echo
}

cmd_run() {
  [ $# -ge 3 ] && [ $# -le 4 ] || die "usage: $0 run CRATE TARGET SECONDS [RESULT_JSON]"
  local crate=$1 target=$2 seconds=$3 result=${4:-} log status=0 done_line runs secs verdict
  log=$(mktemp)
  trap 'rm -f "$log"' RETURN
  (
    cd "$root/dataplane/crates/$crate/fuzz" || exit 1
    cargo "$nightly" fetch --locked
    # cargo-fuzz's release binary is built for musl and defaults to its own
    # triple; the toolchain has the gnu standard library.
    cargo "$nightly" fuzz run --target x86_64-unknown-linux-gnu "$target" -- \
      -max_total_time="$seconds" -timeout=30 -rss_limit_mb=2048
  ) 2>&1 | tee "$log" || status=$?
  if [ -n "$result" ]; then
    # libFuzzer's last line is "Done <runs> runs in <seconds> second(s)".
    done_line=$(grep -E '^Done [0-9]+ runs in [0-9]+ second' "$log" | tail -n 1 || true)
    runs=$(echo "$done_line" | awk '{print $2}')
    secs=$(echo "$done_line" | awk '{print $5}')
    verdict=fail
    [ "$status" = 0 ] && [ -n "$done_line" ] && verdict=pass
    mkdir -p "$(dirname "$result")"
    jq -n --arg crate "$crate" --arg target "$target" --argjson runs "${runs:-0}" \
      --argjson seconds "${secs:-0}" --arg result "$verdict" \
      '{crate: $crate, target: $target, seconds: $seconds, runs: $runs, result: $result}' | tee "$result"
  fi
  return "$status"
}

[ $# -ge 1 ] || die "usage: $0 tools|list|run ..."
command=$1
shift
case "$command" in
  tools | list | run) "cmd_$command" "$@" ;;
  *) die "unknown command: $command" ;;
esac
