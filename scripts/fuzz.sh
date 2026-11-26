#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Fuzzing for .github/workflows/fuzz.yaml and the release workflow's fuzzing
# jobs: cargo-fuzz with the pinned nightly toolchain for the data plane, Go's
# native fuzzing for the control plane, and the persistent corpus both start
# from (docs/leak-assurance.md, "Fuzzing").
#
#   scripts/fuzz.sh tools DIR
#       Install the pinned nightly (through rustup) and the cargo-fuzz release
#       binary, checked by sha256, into DIR/bin. Put DIR/bin on PATH.
#   scripts/fuzz.sh list CRATE
#       The fuzz targets of dataplane/crates/CRATE/fuzz, sorted, one line.
#   scripts/fuzz.sh targets [BASE]
#       Every fuzz target as a JSON array, one object per target:
#       {kind, unit, target, id, path}. kind is rust (unit: the crate) or go
#       (unit: the package directory). With BASE (a commit), only the targets
#       whose code changed between BASE and HEAD: a file in a local crate the
#       fuzz crate builds, or in a package the Go fuzz test's binary imports.
#       Needs cargo, go and jq with BASE; nothing but bash and awk without.
#   scripts/fuzz.sh corpus-fetch DIR
#       The persistent corpus (branch FUZZ_CORPUS_BRANCH, default fuzz-corpus,
#       of FUZZ_CORPUS_REMOTE, default this GitHub repository) checked out in
#       DIR. When it cannot be fetched DIR is left empty and the runs start
#       from the committed seeds and regressions alone, with a warning.
#   scripts/fuzz.sh run KIND UNIT TARGET SECONDS [RESULT_JSON]
#       Fuzz one target for SECONDS. With FUZZ_CORPUS set to a corpus-fetch
#       directory, start from its inputs for the target, then the committed
#       seeds and regressions. With RESULT_JSON, also write the target's
#       result there, pass or fail, for the release's published results.
#   scripts/fuzz.sh corpus-export KIND UNIT TARGET OUT_DIR
#       After a run: minimise the target's corpus (cargo fuzz cmin; Go keeps
#       only inputs that widened coverage and has no minimiser) and copy it to
#       OUT_DIR/<path>.
#   scripts/fuzz.sh corpus-push CORPUS_DIR NEW_DIR RESULTS_DIR
#       Replace the corpus of every target NEW_DIR holds (corpus-export
#       output), add the seconds and runs of RESULTS_DIR's results to
#       stats.json, and push the result as a single commit to the corpus
#       branch, only if the branch is still where corpus-fetch found it.
#       GITHUB_TOKEN authenticates the push to github.com. The scheduled run
#       is the only caller.
#
# A finding fails the run. Its reproducer is under the crate's fuzz/artifacts/
# (cargo-fuzz) or the package's testdata/fuzz/<target>/ (Go).
set -euo pipefail

# renovate: datasource=custom.rust-nightly depName=rust-nightly versioning=regex:^(?<major>\d{4})-(?<minor>\d{2})-(?<patch>\d{2})$
RUST_NIGHTLY_DATE="2026-11-20"
# renovate: datasource=github-releases depName=rust-fuzz/cargo-fuzz
CARGO_FUZZ_VERSION=0.13.2
# sha256: https://github.com/rust-fuzz/cargo-fuzz/releases/download/{version}/cargo-fuzz-{version}-x86_64-unknown-linux-musl.tar.gz
CARGO_FUZZ_SHA256=b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c

# Limits on what corpus-push accepts from the fuzzing jobs.
MAX_INPUT_BYTES=$((1024 * 1024))
MAX_CORPUS_BYTES=$((256 * 1024 * 1024))

root="$(cd "$(dirname "$0")/.." && pwd)"
nightly="+nightly-${RUST_NIGHTLY_DATE}"
corpus_branch=${FUZZ_CORPUS_BRANCH:-fuzz-corpus}
corpus_remote=${FUZZ_CORPUS_REMOTE:-${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-Heliopsy/scrim}.git}

die() {
  echo "error: $*" >&2
  exit 1
}

warn() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::warning::$*" >&2
  else
    echo "warning: $*" >&2
  fi
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

# rust_targets prints "crate target" for every [[bin]] of every fuzz crate.
rust_targets() {
  local manifest crate
  for manifest in "$root"/dataplane/crates/*/fuzz/Cargo.toml; do
    crate=$(basename "$(dirname "$(dirname "$manifest")")")
    awk -v crate="$crate" '
      /^\[\[bin\]\]/ { bin = 1; next }
      /^\[/ { bin = 0 }
      bin && /^name *= *"/ { gsub(/^name *= *"|".*$/, ""); print crate, $0 }
    ' "$manifest"
  done | sort
}

# go_targets prints "package-dir FuzzName" for every Go fuzz test.
go_targets() {
  (cd "$root" && grep -rEo --include='*_test.go' '^func Fuzz[A-Za-z0-9_]*\(' internal pkg scripts 2>/dev/null || true) |
    sed -E 's#^(.*)/[^/]+_test\.go:func (Fuzz[A-Za-z0-9_]*)\($#\1 \2#' | sort
}

# target_path is where a target's inputs live on the corpus branch.
target_path() {
  case "$1" in
    rust) echo "rust/$2/$3" ;;
    go) echo "go/$2/$3" ;;
    *) die "unknown kind $1" ;;
  esac
}

target_id() {
  echo "$1-${2//\//-}-$3"
}

all_targets() {
  local unit target
  rust_targets | while read -r unit target; do echo "rust $unit $target"; done
  go_targets | while read -r unit target; do echo "go $unit $target"; done
}

# changed_targets prints the targets (kind unit target) whose code differs
# between BASE and HEAD.
changed_targets() {
  local base=$1 files kind unit target dirs
  files=$(cd "$root" && git diff --name-only "$base" HEAD)
  # The fuzzing machinery itself: everything.
  if grep -qxE 'scripts/fuzz\.sh|\.github/workflows/fuzz\.yaml' <<<"$files"; then
    all_targets
    return
  fi
  all_targets | while read -r kind unit target; do
    case "$kind" in
      rust)
        # Every local crate the fuzz crate builds (its own directory among them), and
        # the workspace manifest the crates inherit from.
        dirs=$(cd "$root/dataplane/crates/$unit/fuzz" && cargo metadata --locked --format-version 1 |
          jq -r --arg root "$root/" '.packages[] | select(.source == null) | .manifest_path |
            ltrimstr($root) | sub("/Cargo.toml$"; "")')
        if grep -qx 'dataplane/Cargo.toml' <<<"$files" ||
          awk -v dirs="$dirs" 'BEGIN { n = split(dirs, d, "\n") }
            { for (i = 1; i <= n; i++) if (index($0, d[i] "/") == 1) { found = 1; exit } }
            END { exit !found }' <<<"$files"; then
          echo "rust $unit $target"
        fi
        ;;
      go)
        # Every package of the module the test binary imports; a file counts when it
        # sits in one of their directories or under its testdata.
        dirs=$(cd "$root" && go list -deps -test -f '{{if not .Standard}}{{.Dir}}{{end}}' "./$unit" |
          sed -n "s#^$root/##p" | sort -u)
        if grep -qxE 'go\.(mod|sum)' <<<"$files" ||
          awk -v dirs="$dirs" 'BEGIN { n = split(dirs, d, "\n"); for (i = 1; i <= n; i++) want[d[i]] = 1 }
            { f = $0; sub(/\/[^\/]*$/, "", f); if (f in want) { found = 1; exit }
              for (i = 1; i <= n; i++) if (index($0, d[i] "/testdata/") == 1) { found = 1; exit } }
            END { exit !found }' <<<"$files"; then
          echo "go $unit $target"
        fi
        ;;
    esac
  done
}

cmd_targets() {
  [ $# -le 1 ] || die "usage: $0 targets [BASE]"
  local kind unit target sep=""
  {
    if [ $# -eq 1 ]; then changed_targets "$1"; else all_targets; fi
  } | {
    printf '['
    while read -r kind unit target; do
      printf '%s{"kind":"%s","unit":"%s","target":"%s","id":"%s","path":"%s"}' \
        "$sep" "$kind" "$unit" "$target" "$(target_id "$kind" "$unit" "$target")" \
        "$(target_path "$kind" "$unit" "$target")"
      sep=,
    done
    printf ']\n'
  }
}

cmd_corpus_fetch() {
  [ $# -eq 1 ] || die "usage: $0 corpus-fetch DIR"
  local dir=$1
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q
  if git -C "$dir" fetch -q --depth=1 "$corpus_remote" "refs/heads/$corpus_branch" 2>/dev/null &&
    git -C "$dir" checkout -q FETCH_HEAD; then
    echo "corpus: $corpus_branch at $(git -C "$dir" rev-parse HEAD), $(find "$dir" -path "$dir/.git" -prune -o -type f -print | wc -l) files" >&2
  else
    warn "no corpus branch $corpus_branch at $corpus_remote: starting from the committed seeds and regressions"
  fi
}

count_files() {
  if [ -d "$1" ]; then find "$1" -maxdepth 1 -type f | wc -l; else echo 0; fi
}

# go_seconds turns a Go duration printed by the fuzzer (1h0m3s, 5m0s, 59s)
# into whole seconds.
go_seconds() {
  awk '{ s = 0; d = $0
    if (match(d, /[0-9]+h/)) s += 3600 * substr(d, RSTART, RLENGTH - 1)
    if (match(d, /[0-9]+m/)) s += 60 * substr(d, RSTART, RLENGTH - 1)
    if (match(d, /[0-9.]+s$/)) s += substr(d, RSTART, RLENGTH - 1)
    printf "%d\n", s }' <<<"$1"
}

# go_cache is the directory Go keeps a fuzz test's generated corpus in.
go_cache() {
  echo "$(cd "$root" && go env GOCACHE)/fuzz/$(cd "$root" && go list -f '{{.ImportPath}}' "./$1")/$2"
}

cmd_run() {
  [ $# -ge 4 ] && [ $# -le 5 ] || die "usage: $0 run KIND UNIT TARGET SECONDS [RESULT_JSON]"
  local kind=$1 unit=$2 target=$3 seconds=$4 result=${5:-} path log status=0
  local corpus=${FUZZ_CORPUS:-} commit=none prior=0 start=0 end=0 seeds=0 regressions=0
  local runs="" secs="" line="" verdict dir cache
  path=$(target_path "$kind" "$unit" "$target")
  if [ -n "$corpus" ] && git -C "$corpus" rev-parse -q --verify HEAD >/dev/null 2>&1; then
    commit=$(git -C "$corpus" rev-parse HEAD)
    if [ -f "$corpus/stats.json" ]; then
      prior=$(jq -r --arg p "$path" '.[$p].seconds // 0' "$corpus/stats.json")
    fi
  fi
  log=$(mktemp)
  trap 'rm -f "$log"' RETURN
  case "$kind" in
    rust)
      dir="$root/dataplane/crates/$unit/fuzz"
      [ -d "$dir" ] || die "no fuzz crate $dir"
      # libFuzzer writes new inputs to the first directory; the committed seeds and
      # findings come after it and are only read.
      mkdir -p "$dir/corpus/$target"
      if [ -n "$corpus" ] && [ -d "$corpus/$path" ]; then
        find "$corpus/$path" -maxdepth 1 -type f -exec cp -n -t "$dir/corpus/$target" {} +
      fi
      local dirs=("corpus/$target")
      [ -d "$dir/seeds/$target" ] && dirs+=("seeds/$target")
      [ -d "$dir/regressions/$target" ] && dirs+=("regressions/$target")
      start=$(count_files "$dir/corpus/$target")
      seeds=$(count_files "$dir/seeds/$target")
      regressions=$(count_files "$dir/regressions/$target")
      (
        cd "$dir" || exit 1
        # Chained with &&: errexit does not apply inside a subshell whose status
        # is tested, so a stale lockfile would otherwise be rewritten silently.
        # cargo-fuzz's release binary is built for musl and defaults to its own
        # triple; the toolchain has the gnu standard library.
        cargo "$nightly" fetch --locked &&
          cargo "$nightly" fuzz run --target x86_64-unknown-linux-gnu "$target" "${dirs[@]}" -- \
            -max_total_time="$seconds" -timeout=30 -rss_limit_mb=2048
      ) 2>&1 | tee "$log" || status=$?
      end=$(count_files "$dir/corpus/$target")
      # libFuzzer's last line is "Done <runs> runs in <seconds> second(s)".
      line=$(grep -E '^Done [0-9]+ runs in [0-9]+ second' "$log" | tail -n 1 || true)
      runs=$(awk '{print $2}' <<<"$line")
      secs=$(awk '{print $5}' <<<"$line")
      ;;
    go)
      [ -d "$root/$unit" ] || die "no package $root/$unit"
      # Go reads and extends the corpus it keeps in its build cache, after the
      # f.Add seeds and the committed findings in testdata/fuzz/<target>.
      cache=$(go_cache "$unit" "$target")
      mkdir -p "$cache"
      if [ -n "$corpus" ] && [ -d "$corpus/$path" ]; then
        find "$corpus/$path" -maxdepth 1 -type f -exec cp -n -t "$cache" {} +
      fi
      start=$(count_files "$cache")
      regressions=$(count_files "$root/$unit/testdata/fuzz/$target")
      (
        cd "$root" || exit 1
        go test -run='^$' -fuzz="^$target\$" -fuzztime="${seconds}s" -timeout="$((seconds + 900))s" "./$unit"
      ) 2>&1 | tee "$log" || status=$?
      end=$(count_files "$cache")
      # "fuzz: elapsed: 5m0s, execs: 123456 (411/sec), new interesting: 3 (total: 50)";
      # the first line, "gathering baseline coverage: 0/63 completed", says how
      # many seeds, findings and corpus inputs it started with.
      seeds=$(grep -oE 'gathering baseline coverage: [0-9]+/[0-9]+' "$log" | head -n 1 | sed 's#.*/##' || true)
      seeds=$((${seeds:-0} - start - regressions))
      [ "$seeds" -ge 0 ] || seeds=0
      line=$(grep -E '^fuzz: elapsed: [0-9hms.]+, execs: [0-9]+' "$log" | tail -n 1 || true)
      if [ -n "$line" ]; then
        runs=$(sed -E 's/.*execs: ([0-9]+).*/\1/' <<<"$line")
        secs=$(go_seconds "$(sed -E 's/^fuzz: elapsed: ([0-9hms.]+),.*/\1/' <<<"$line")")
      fi
      # A clean run ends with "ok <package>".
      grep -qE '^ok[[:space:]]' "$log" || line=""
      ;;
    *) die "unknown kind $kind" ;;
  esac
  if [ -n "$result" ]; then
    verdict=fail
    [ "$status" = 0 ] && [ -n "$line" ] && verdict=pass
    mkdir -p "$(dirname "$result")"
    jq -n --arg kind "$kind" --arg unit "$unit" --arg target "$target" --arg path "$path" \
      --argjson runs "${runs:-0}" --argjson seconds "${secs:-0}" --arg result "$verdict" \
      --arg commit "$commit" --argjson prior "${prior:-0}" --argjson start "$start" --argjson end "$end" \
      --argjson seeds "$seeds" --argjson regressions "$regressions" '
      (if $kind == "rust" then {crate: $unit} else {package: $unit} end)
      + {kind: $kind, target: $target, path: $path, seconds: $seconds, runs: $runs, result: $result,
         corpus: {commit: $commit, prior_seconds: $prior, files_at_start: $start, files_at_end: $end,
                  seeds: $seeds, regressions: $regressions}}' | tee "$result"
  fi
  return "$status"
}

cmd_corpus_export() {
  [ $# -eq 4 ] || die "usage: $0 corpus-export KIND UNIT TARGET OUT_DIR"
  local kind=$1 unit=$2 target=$3 out=$4 src before
  out="$out/$(target_path "$kind" "$unit" "$target")"
  case "$kind" in
    rust)
      src="$root/dataplane/crates/$unit/fuzz/corpus/$target"
      [ -d "$src" ] || die "no corpus at $src: run the target first"
      before=$(count_files "$src")
      (
        cd "$root/dataplane/crates/$unit/fuzz" || exit 1
        cargo "$nightly" fuzz cmin --target x86_64-unknown-linux-gnu "$target" "corpus/$target" -- \
          -timeout=30 -rss_limit_mb=2048
      )
      ;;
    go)
      src=$(go_cache "$unit" "$target")
      [ -d "$src" ] || die "no corpus at $src: run the target first"
      before=$(count_files "$src")
      ;;
    *) die "unknown kind $kind" ;;
  esac
  rm -rf "$out"
  mkdir -p "$out"
  find "$src" -maxdepth 1 -type f -exec cp -t "$out" {} +
  echo "corpus $kind $unit $target: $before inputs, $(count_files "$out") kept" >&2
}

# check_new fails unless every file under NEW_DIR is a plain input of a known
# target: the fuzzing jobs run build scripts and tests, so their output is
# checked before a job with a write token commits it.
check_new() {
  local new=$1 known bad total
  known=$(all_targets | while read -r kind unit target; do target_path "$kind" "$unit" "$target"; done)
  bad=$(cd "$new" && find . -mindepth 1 ! -type d ! -type f | head -n 5)
  [ -z "$bad" ] || die "not a plain file or directory in the new corpus: $bad"
  bad=$(cd "$new" && find . -type f | sed 's#^\./##' | awk -v known="$known" '
    BEGIN { n = split(known, k, "\n"); for (i = 1; i <= n; i++) ok[k[i]] = 1 }
    { d = $0; sub(/\/[^\/]*$/, "", d); f = $0; sub(/^.*\//, "", f)
      if (!(d in ok) || f !~ /^[0-9a-f]+$/ || length(f) < 16 || length(f) > 64) print }' | head -n 5)
  [ -z "$bad" ] || die "unexpected path in the new corpus: $bad"
  bad=$(find "$new" -type f -size +"$MAX_INPUT_BYTES"c | head -n 5)
  [ -z "$bad" ] || die "input larger than $MAX_INPUT_BYTES bytes: $bad"
  total=$(find "$new" -type f -printf '%s\n' | awk '{s += $1} END {print s + 0}')
  [ "$total" -le "$MAX_CORPUS_BYTES" ] || die "new corpus is $total bytes, over $MAX_CORPUS_BYTES"
}

cmd_corpus_push() {
  [ $# -eq 3 ] || die "usage: $0 corpus-push CORPUS_DIR NEW_DIR RESULTS_DIR"
  local old=$1 new=$2 results=$3 lease="" tree stats kind unit target path n=0 keep
  local auth=()
  [ -d "$new" ] || die "no $new"
  check_new "$new"
  if git -C "$old" rev-parse -q --verify HEAD >/dev/null 2>&1; then
    lease=$(git -C "$old" rev-parse HEAD)
  fi
  tree=$(mktemp -d)
  trap 'rm -rf "$tree"' RETURN
  # Keep the corpus of every target that still exists; replace those this run
  # exported. A target that was removed loses its corpus.
  while read -r kind unit target; do
    path=$(target_path "$kind" "$unit" "$target")
    if [ -d "$new/$path" ]; then
      mkdir -p "$tree/$path"
      find "$new/$path" -maxdepth 1 -type f -exec cp -t "$tree/$path" {} +
      n=$((n + 1))
    elif [ -d "$old/$path" ]; then
      mkdir -p "$tree/$path"
      find "$old/$path" -maxdepth 1 -type f -exec cp -t "$tree/$path" {} +
    fi
  done < <(all_targets)
  [ "$n" -gt 0 ] || die "no target exported a corpus"
  # Accumulated fuzzing time and runs per target, which the release reports
  # with the corpus it starts from. Only passing runs count.
  stats='{}'
  [ -f "$old/stats.json" ] && stats=$(cat "$old/stats.json")
  shopt -s nullglob
  local res=("$results"/*.json)
  shopt -u nullglob
  if [ ${#res[@]} -gt 0 ]; then
    stats=$(jq -s --argjson s "$stats" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
      reduce (.[] | select(.result == "pass")) as $r ($s;
        .[$r.path].seconds = ((.[$r.path].seconds // 0) + $r.seconds)
        | .[$r.path].runs = ((.[$r.path].runs // 0) + $r.runs)
        | .[$r.path].updated = $now)' "${res[@]}")
  fi
  keep=$(all_targets | while read -r kind unit target; do target_path "$kind" "$unit" "$target"; done |
    jq -R . | jq -s .)
  jq -S --argjson keep "$keep" 'with_entries(select(.key as $k | $keep | index($k)))' \
    <<<"$stats" >"$tree/stats.json"
  cat >"$tree/README.md" <<'EOF'
# scrim fuzzing corpus

Written by the scheduled run of `.github/workflows/fuzz.yaml` (`scripts/fuzz.sh corpus-push`) and
replaced by a single commit after each run. `rust/<crate>/<target>` and `go/<package>/<FuzzName>`
hold each target's inputs, `stats.json` the fuzzing time and runs behind them. Inputs are generated
bytes, never secrets. docs/leak-assurance.md, "Fuzzing", on the main branch describes the setup.
EOF
  git -C "$tree" init -q
  git -C "$tree" add -A
  git -C "$tree" -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -q -m "fuzz corpus from ${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-0}"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 -w0)")
  fi
  # The lease is the commit corpus-fetch found (empty: the branch must not exist
  # yet), so a push made since is never overwritten.
  git -C "$tree" "${auth[@]}" push -q --force-with-lease="refs/heads/$corpus_branch:$lease" \
    "$corpus_remote" "HEAD:refs/heads/$corpus_branch"
  echo "pushed $(git -C "$tree" rev-parse HEAD) to $corpus_branch: $n targets updated" >&2
  # A Markdown summary of the corpus on stdout, for the job summary.
  echo "| Target | Inputs | Hours of fuzzing behind it |"
  echo "| --- | --- | --- |"
  while read -r kind unit target; do
    path=$(target_path "$kind" "$unit" "$target")
    echo "| \`$path\` | $(count_files "$tree/$path") | $(jq -r --arg p "$path" \
      '((.[$p].seconds // 0) / 36 | round) / 100' "$tree/stats.json") |"
  done < <(all_targets)
}

[ $# -ge 1 ] || die "usage: $0 tools|list|targets|corpus-fetch|run|corpus-export|corpus-push ..."
command=$1
shift
case "$command" in
  tools | list | targets | run) "cmd_$command" "$@" ;;
  corpus-fetch | corpus-export | corpus-push) "cmd_${command//-/_}" "$@" ;;
  *) die "unknown command: $command" ;;
esac
