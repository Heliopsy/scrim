#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/results.sh COMMAND ...
#
# The leak and performance results every release publishes beside its
# binaries (docs/leak-assurance.md, "Published results"). The release workflow
# runs each command in its own job; a laptop runs the same commands.
#
#   leak BIN_DIR OUT_DIR
#       The leak suite against the release binaries in BIN_DIR (scrim and
#       scrim-dataplane for this host): OUT_DIR/leak-report.json is the gate
#       against `scrim proxy` and must pass, OUT_DIR/leak-control.json the same
#       suite against a pass-through proxy and must fail.
#
#   matrix STORE BIN_DIR OUT_DIR
#       The end-to-end matrix cells of one store (test/e2e/matrix/run.sh) with
#       the release binaries, one JSON result per cell in OUT_DIR.
#
#   bench OUT_DIR
#       The latency gate, which fails over budget: OUT_DIR/latency-gate.md is
#       its report, OUT_DIR/latency-gate.json every measurement with its rounds
#       and the machine. Then the scrim-redact criterion benchmarks
#       (OUT_DIR/redact-bench.txt). SCRIM_PERF_RUNNER names the runner class
#       recorded in the JSON (the release workflow sets ho-z10).
#
#   baseline VERSION|latest OUT_DIR
#       The latency gate results of the newest published release older than
#       VERSION (or of the newest release, for "latest" or a development
#       version), checked the way docs/install.md checks published results:
#       cosign verifies checksums.txt against the release workflow's identity,
#       then the file is checked against it. Writes OUT_DIR/baseline.json and
#       OUT_DIR/baseline.txt (the tag), or, when no release publishes the JSON
#       yet, only OUT_DIR/none.txt saying so. Needs curl, jq and cosign;
#       GITHUB_TOKEN raises the API rate limit, GITHUB_REPOSITORY picks the
#       repository (default Heliopsy/scrim). SCRIM_PERF_BASELINE_ASSET fetches
#       another results file the same way (for example latency-gate.md, to try
#       the check against a release from before the JSON).
#
#   regression CURRENT_JSON BASELINE_DIR OUT_MD
#       Compares CURRENT_JSON (latency-gate.json) with the baseline in
#       BASELINE_DIR using scripts/perfgate and the "regression" settings of
#       dataplane/crates/scrim-llm/benches/budget.json; writes the report to
#       OUT_MD and fails on a regression unless regression.enforce is false.
#       Without a baseline the report says
#       why nothing was compared.
#
#   assemble RESULTS_DIR RELEASE_DIR
#       Checks the results (latency-regression.md from the regression command
#       among them), copies them into RELEASE_DIR as
#       scrim_<version>_results*, writes the summary scrim_<version>_results.md
#       and rewrites checksums.txt over every release file. RESULTS_DIR holds
#       the output of leak and bench at its top, one directory per store with
#       the matrix cells under matrix/, and one JSON per target under fuzz/
#       (written by scripts/fuzz.sh run in the release's fuzzing jobs).
#
# No file written here holds a secret: every seed is generated for the run, and
# the reports name seeds by kind, length and a short SHA-256 only.
. "$(dirname "$0")/lib.sh"

abs() {
  mkdir -p "$1"
  (cd "$1" && pwd)
}

cmd_leak() {
  [ $# -eq 2 ] || die "usage: $0 leak BIN_DIR OUT_DIR"
  local bin out scrim
  bin=$(cd "$1" && pwd) out=$(abs "$2")
  scrim="$bin/scrim"
  [ -x "$scrim" ] && [ -x "$bin/$SCRIM_DATAPLANE_BIN" ] || die "$bin must hold scrim and $SCRIM_DATAPLANE_BIN"
  command -v jq >/dev/null || die "jq is required (test/leak/start-proxy.sh)"
  cd "$ROOT" || exit 1

  log "leak suite against a pass-through proxy (must fail)"
  if "$scrim" audit run --proxy builtin:passthrough -q --report "$out/leak-control.json" >"$out/leak-control.txt"; then
    die "the leak gate passed against a pass-through proxy"
  fi
  tail -n 1 "$out/leak-control.txt" >&2
  rm -f "$out/leak-control.txt"

  log "leak suite against scrim proxy"
  SCRIM_LEAK_SCRIM="$scrim" SCRIM_DATAPLANE_PATH="$bin/$SCRIM_DATAPLANE_BIN" \
    "$scrim" audit run --proxy http://127.0.0.1:18484 --proxy-cmd test/leak/start-proxy.sh \
    --route anthropic-messages=/anthropic --route openai-chat=/openai \
    --route openai-responses=/openai --route gemini=/gemini \
    --upstream-listen 127.0.0.1:18089 --report "$out/leak-report.json"
}

cmd_matrix() {
  [ $# -eq 3 ] || die "usage: $0 matrix STORE BIN_DIR OUT_DIR"
  local store=$1 bin out
  bin=$(cd "$2" && pwd) out=$(abs "$3")
  SCRIM_MATRIX_SCRIM="$bin/scrim" SCRIM_DATAPLANE_PATH="$bin/$SCRIM_DATAPLANE_BIN" \
    SCRIM_MATRIX_RESULTS="$out" "$ROOT/test/e2e/matrix/run.sh" "$store"
}

cmd_bench() {
  [ $# -eq 1 ] || die "usage: $0 bench OUT_DIR"
  local out
  out=$(abs "$1")
  cd "$ROOT/dataplane" || exit 1
  log "latency gate (crates/scrim-llm/benches/budget.json)"
  SCRIM_PERF_JSON="$out/latency-gate.json" cargo bench --locked --quiet -p scrim-llm --bench latency_gate \
    | tee "$out/latency-gate.md"
  log "scrim-redact benchmarks"
  cargo bench --locked --quiet -p scrim-redact --bench redact 2>&1 | tee "$out/redact-bench.txt"
}

# github_api PATH prints the GitHub API response for PATH.
github_api() {
  local auth=()
  [ -z "${GITHUB_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl --fail --silent --show-error --location --retry 3 --connect-timeout 20 --max-time 120 \
    -H "Accept: application/vnd.github+json" "${auth[@]}" "https://api.github.com/$1"
}

# version_lt A B: A sorts before B as a version.
version_lt() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]
}

cmd_baseline() {
  [ $# -eq 2 ] || die "usage: $0 baseline VERSION|latest OUT_DIR"
  local want=${1#v} out repo server releases tag v f url
  out=$(abs "$2")
  repo=${GITHUB_REPOSITORY:-Heliopsy/scrim}
  server=${GITHUB_SERVER_URL:-https://github.com}
  for f in curl jq cosign; do
    command -v "$f" >/dev/null || die "$f is required"
  done
  rm -f "$out/baseline.json" "$out/baseline.txt" "$out/none.txt"
  # A development or pull request build (0.0.0-...) compares with the newest
  # release; a release, or a pre-release of it, with the newest one before it.
  want=${want%%[-+]*}
  [ "$want" != 0.0.0 ] || want=latest

  releases=$(github_api "repos/$repo/releases?per_page=100")
  # Published, non-pre-release vX.Y.Z tags that carry the JSON, newest first.
  while read -r tag; do
    v=${tag#v}
    if [ "$want" != latest ] && ! version_lt "$v" "$want"; then
      continue
    fi
    f="scrim_${v}_results_${SCRIM_PERF_BASELINE_ASSET:-latency-gate.json}"
    if ! jq -e --arg t "$tag" --arg f "$f" \
      'any(.[]; .tag_name == $t and any(.assets[]; .name == $f))' <<<"$releases" >/dev/null; then
      log "$tag publishes no $f"
      continue
    fi
    log "baseline: $tag"
    url="$server/$repo/releases/download/$tag"
    (
      cd "$out"
      for g in checksums.txt checksums.txt.sigstore.json "$f"; do
        curl --fail --silent --show-error --location --retry 3 --connect-timeout 20 --max-time 120 \
          -o "$g" "$url/$g"
      done
      cosign verify-blob \
        --bundle checksums.txt.sigstore.json \
        --certificate-identity-regexp "^${server//./\\.}/${repo//./\\.}/\\.github/workflows/release\\.yaml@refs/(heads/main|tags/v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?)\$" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        checksums.txt
      grep -E "^[0-9a-f]{64}  ${f//./\\.}\$" checksums.txt | sha256sum --check --strict
    ) >&2 || die "the results of $tag did not verify against their signed checksums"
    mv "$out/$f" "$out/baseline.json"
    rm -f "$out/checksums.txt" "$out/checksums.txt.sigstore.json"
    echo "$tag" >"$out/baseline.txt"
    return 0
  done < <(jq -r '.[] | select(.draft == false and .prerelease == false) | .tag_name' <<<"$releases" \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -rV)

  if [ "$want" = latest ]; then
    echo "no published release of $repo has machine-readable latency results yet" >"$out/none.txt"
  else
    echo "no published release of $repo before $want has machine-readable latency results" >"$out/none.txt"
  fi
  log "$(cat "$out/none.txt")"
}

cmd_regression() {
  [ $# -eq 3 ] || die "usage: $0 regression CURRENT_JSON BASELINE_DIR OUT_MD"
  local cur base md
  cur=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
  base=$(cd "$2" && pwd)
  mkdir -p "$(dirname "$3")"
  md=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
  [ -s "$cur" ] || die "missing $cur"
  if [ ! -f "$base/baseline.json" ]; then
    [ -s "$base/none.txt" ] || die "$base holds neither baseline.json nor none.txt"
    printf '# Latency regression check\n\nNot compared: %s.\n' "$(cat "$base/none.txt")" | tee "$md"
    return 0
  fi
  cd "$ROOT" || exit 1
  {
    printf 'Baseline: the results published with %s.\n\n' "$(cat "$base/baseline.txt")"
  } >&2
  GOFLAGS=-mod=readonly go run ./scripts/perfgate \
    -current "$cur" -baseline "$base/baseline.json" \
    -config dataplane/crates/scrim-llm/benches/budget.json -report "$md"
}

# summary RESULTS_DIR prints the Markdown summary of one release's results.
summary() {
  local res=$1 report=$1/leak-report.json
  cat <<EOF
# scrim $SCRIM_VERSION: leak and performance results

Commit \`$SCRIM_COMMIT\` ($SCRIM_DATE). Produced by the release workflow from the
linux-amd64 binaries of this release. Every file named here is listed in
\`checksums.txt\`, which is signed; docs/install.md says how to check them, and
docs/limitations.md lists what these tests do not cover.

## Leak suite

\`scrim audit run\` against \`scrim proxy\` with the seeds in a file store
(\`scrim_${SCRIM_VERSION}_results_leak-report.json\`).

EOF
  jq -r '
    "| Rows | Cases | Passed | Gated leaks | Limitation leaks | Scenario leaks | Errors | Gate |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    "| \(.matrix.totals.rows) | \(.matrix.totals.cases) | \(.matrix.totals.passed) | \(.summary.gated_leaks) | \(.summary.limitation_leaks) | \(.summary.scenario_leaks) | \(.summary.errors) | \(if .pass then "pass" else "FAIL" end) |"
  ' "$report"
  echo
  jq -r '"The same suite against a pass-through proxy found \(.summary.gated_leaks) gated leaks and failed, as it must (`scrim_'"$SCRIM_VERSION"'_results_leak-control.json`)."' \
    "$res/leak-control.json"
  echo
  echo "Documented limitations that leaked in this run (rows marked \`limitation\`, which do not fail the gate):"
  echo
  echo "| Limitation | Transforms | Cases |"
  echo "| --- | --- | --- |"
  jq -r '
    [.matrix.results[] | select(.expect == "limitation" and .outcome == "leaked")]
    | group_by(.note)[]
    | "| \(.[0].note // "" | sub("^limitation: "; "") | gsub("\\|"; "\\|")) | \(map("`\(.transform)`") | unique | join(", ")) | \(length) |"
  ' "$report"

  cat <<EOF

## End-to-end matrix

Every interception mode, store and provider route through the real proxy and data
plane, with the leak gate in every cell (docs/leak-assurance.md, "End-to-end
matrix"; \`scrim_${SCRIM_VERSION}_results_e2e-matrix.json\`). The Kubernetes cell
runs in CI on every change, not here.

EOF
  jq -r '
    "\(length) cells, \(map(select(.pass)) | length) passed, \(map(.gated_leaks) | add) gated leaks, \(map(.limitation_leaks // 0) | add) limitation leaks.",
    "",
    "| Cell | Result | Matrix rows | Scenarios | Gated leaks | Limitation leaks |",
    "| --- | --- | --- | --- | --- | --- |",
    (.[] | "| `\(.cell)` | \(if .pass then "pass" else "FAIL" end) | \(.rows // 0) | \(.scenarios // 0) | \(.gated_leaks) | \(.limitation_leaks // 0) |")
  ' "$res/e2e-matrix.json"

  cat <<EOF

## Fuzzing

Each cargo-fuzz target run from an empty corpus for this release
(\`scrim_${SCRIM_VERSION}_results_fuzz.json\`); the weekly run adds 15 minutes per
target.

EOF
  jq -r '
    "| Target | Seconds | Runs | Result |",
    "| --- | --- | --- | --- |",
    (.[] | "| `\(.crate)/\(.target)` | \(.seconds) | \(.runs) | \(.result) |"),
    "",
    "Total: \(map(.seconds) | add / 3600 * 100 | round / 100) hours."
  ' "$res/fuzz.json"

  echo
  echo "## Latency"
  echo
  echo "The latency gate with the production engine; the release fails when a gated"
  echo "value misses its budget (\`scrim_${SCRIM_VERSION}_results_latency-gate.md\`, every"
  echo "measurement and its rounds in \`scrim_${SCRIM_VERSION}_results_latency-gate.json\`),"
  echo "and reports the comparison with the previous release"
  echo "(\`scrim_${SCRIM_VERSION}_results_latency-regression.md\`), which fails it only when"
  echo "the budget file's regression.enforce is on. Criterion's redaction"
  echo "throughput per secret set and body size is in"
  echo "\`scrim_${SCRIM_VERSION}_results_redact-bench.txt\`. docs/performance.md says how to"
  echo "read and reproduce them."
  echo
  # One heading level down, so each report's own title sits under this section.
  sed 's/^#/##/' "$res/latency-gate.md"
  echo
  sed 's/^#/##/' "$res/latency-regression.md"
}

cmd_assemble() {
  [ $# -eq 2 ] || die "usage: $0 assemble RESULTS_DIR RELEASE_DIR"
  local res rel p f
  res=$(cd "$1" && pwd) rel=$(cd "$2" && pwd)
  command -v jq >/dev/null || die "jq is required"
  [ -f "$rel/checksums.txt" ] || die "no checksums.txt in $rel"
  (cd "$rel" && sha256sum --check --strict --quiet checksums.txt) || die "$rel does not match its checksums.txt"
  for f in leak-report.json leak-control.json latency-gate.md latency-gate.json latency-regression.md redact-bench.txt; do
    [ -s "$res/$f" ] || die "missing $res/$f"
  done

  jq -e '.pass == true and .summary.gated_leaks == 0 and .summary.errors == 0' "$res/leak-report.json" >/dev/null \
    || die "the leak report did not pass"
  jq -e '.pass == false and .summary.gated_leaks > 0' "$res/leak-control.json" >/dev/null \
    || die "the pass-through control did not leak"
  jq -e '.schema == 1 and .pass == true and .method.quick == false' "$res/latency-gate.json" >/dev/null \
    || die "the latency gate did not pass, or ran in quick mode"
  # A regression fails the release only while the budget file enforces the check; report
  # only, it stays in the results for the reader.
  if jq -e '.regression.enforce != false' "$ROOT/dataplane/crates/scrim-llm/benches/budget.json" >/dev/null; then
    ! grep -q '^REGRESSION:' "$res/latency-regression.md" || die "the latency regression check failed"
  fi

  shopt -s nullglob
  local cells=("$res"/matrix/*/*.json) fuzz=("$res"/fuzz/*.json)
  shopt -u nullglob
  [ ${#cells[@]} -gt 0 ] || die "no matrix cell results under $res/matrix"
  [ ${#fuzz[@]} -gt 0 ] || die "no fuzz results under $res/fuzz"
  jq -s 'sort_by(.cell)' "${cells[@]}" >"$res/e2e-matrix.json"
  jq -e 'all(.[]; .pass and .gated_leaks == 0)' "$res/e2e-matrix.json" >/dev/null \
    || die "an end-to-end matrix cell failed"
  jq -s 'sort_by(.crate, .target)' "${fuzz[@]}" >"$res/fuzz.json"
  jq -e 'all(.[]; .result == "pass" and .seconds > 0)' "$res/fuzz.json" >/dev/null \
    || die "a fuzz target failed or did not run"

  p="scrim_${SCRIM_VERSION}_results"
  install -m 0644 "$res/leak-report.json" "$rel/${p}_leak-report.json"
  install -m 0644 "$res/leak-control.json" "$rel/${p}_leak-control.json"
  install -m 0644 "$res/e2e-matrix.json" "$rel/${p}_e2e-matrix.json"
  install -m 0644 "$res/fuzz.json" "$rel/${p}_fuzz.json"
  install -m 0644 "$res/latency-gate.md" "$rel/${p}_latency-gate.md"
  install -m 0644 "$res/latency-gate.json" "$rel/${p}_latency-gate.json"
  install -m 0644 "$res/latency-regression.md" "$rel/${p}_latency-regression.md"
  install -m 0644 "$res/redact-bench.txt" "$rel/${p}_redact-bench.txt"
  summary "$res" >"$rel/$p.md"
  log "$rel/$p.md"
  write_checksums "$rel"
  cat "$rel/checksums.txt" >&2
}

[ $# -ge 1 ] || die "usage: $0 leak|matrix|bench|baseline|regression|assemble ..."
command=$1
shift
case "$command" in
  leak | matrix | bench | baseline | regression | assemble) "cmd_$command" "$@" ;;
  *) die "unknown command: $command" ;;
esac
