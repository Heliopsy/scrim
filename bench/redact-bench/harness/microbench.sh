#!/usr/bin/env bash
# microbench.sh <quick|full> <results dir>
# Go: go test -bench (+ benchstat), Rust: criterion. Both pinned to one CPU with taskset.
set -euo pipefail
mode=$1; mkdir -p "$2"; R=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")/.." && pwd)
D=$here/fixtures/data
CPU=${RB_CPU_MICRO:-4}

export RB_FIXTURES=$D CGO_ENABLED=0 GOAMD64=${GOAMD64:-v3}
if [ "$mode" = full ]; then
  GOCOUNT=10; GOTIME=200ms; BUILDCOUNT=5
  export RB_GO_ENGINES="petar-nfa pgavlin-nfa petar-dfa coregx" RB_RUST_ENGINES="ac-auto ac-dfa"
  REDACT_FILTER='Redact'; RS_FILTER='redact|restore|build'
else
  GOCOUNT=3; GOTIME=100ms; BUILDCOUNT=1
  export RB_GO_ENGINES="petar-nfa petar-dfa" RB_RUST_ENGINES="ac-auto"
  REDACT_FILTER='Redact/.*/size=1m'; RS_FILTER='redact/.*/size=1m|restore|build'
fi

echo "== Go micro (GOAMD64=$GOAMD64, cpu $CPU)"
cd "$here/go"
go test -c -o bin/redact.test ./redact
taskset -c $CPU bin/redact.test -test.run '^$' -test.bench "$REDACT_FILTER|Restore" -test.benchmem \
  -test.count $GOCOUNT -test.benchtime $GOTIME | tee "$R/go-bench.txt"
taskset -c $CPU bin/redact.test -test.run '^$' -test.bench 'Build' -test.benchmem \
  -test.count $BUILDCOUNT -test.benchtime 1x | tee "$R/go-bench-build.txt"
"$here/.bin/benchstat" "$R/go-bench.txt" > "$R/go-benchstat.txt" || true
"$here/.bin/benchstat" "$R/go-bench-build.txt" > "$R/go-benchstat-build.txt" || true

echo "== Rust micro (criterion, cpu $CPU)"
cd "$here/rust"
rm -rf target/criterion
taskset -c $CPU cargo bench --bench redact -- "$RS_FILTER" 2>&1 | grep -E 'time:|thrpt:|^(redact|restore|build)/' | tee "$R/rust-criterion.txt"
python3 - "$here/rust/target/criterion" "$R/rust-criterion.json" <<'PY'
import json, os, sys
root, out = sys.argv[1:]
res = []
for dp, _, fs in os.walk(root):
    if dp.endswith("/new") and "estimates.json" in fs:
        bm = json.load(open(os.path.join(dp, "benchmark.json")))
        est = json.load(open(os.path.join(dp, "estimates.json")))
        res.append({"id": bm["full_id"], "throughput": bm.get("throughput"),
                    "mean_ns": est["mean"]["point_estimate"], "mean_lo": est["mean"]["confidence_interval"]["lower_bound"],
                    "mean_hi": est["mean"]["confidence_interval"]["upper_bound"], "median_ns": est["median"]["point_estimate"],
                    "stddev_ns": est["std_dev"]["point_estimate"]})
json.dump(sorted(res, key=lambda r: r["id"]), open(out, "w"), indent=1)
PY

echo "== automaton build memory + allocations"
: > "$R/buildmem.jsonl"
for n in 10 1000 10000; do
  for e in petar-nfa pgavlin-nfa petar-dfa coregx; do
    { [ $n = 10000 ] && [ $e = petar-dfa -o $e = coregx ]; } && continue
    [ "$mode" = quick ] && [ $e = pgavlin-nfa -o $e = coregx ] && continue
    "$here/go/bin/rbcli" buildmem -secrets $D/secrets-$n.json -engine $e >> "$R/buildmem.jsonl"
  done
  for e in ac-auto ac-dfa; do
    [ $n = 10000 ] && [ $e = ac-dfa ] && [ "$mode" = quick ] && continue
    "$here/rust/target/release/rbcli" buildmem -secrets $D/secrets-$n.json -engine $e >> "$R/buildmem.jsonl"
  done
done
: > "$R/rust-allocs.jsonl"
for n in 10 1000 10000; do
  "$here/rust/target/release/rbcli" allocs -secrets $D/secrets-$n.json -engine ac-auto \
    -in "$(ls $D/body-*-s$n.json $D/body-*-clean.json | tr '\n' ',')" \
    -streams "$( [ $n = 1000 ] && echo $D/stream-2k,$D/stream-20k )" | sed "s/^{/{\"set\":$n,/" >> "$R/rust-allocs.jsonl"
done

if [ "$mode" = full ]; then
  echo "== x86-64-v2 subset (both languages)"
  cd "$here/go"
  GOAMD64=v2 go test -c -o bin/redact-v2.test ./redact
  RB_GO_ENGINES="petar-nfa petar-dfa" taskset -c $CPU bin/redact-v2.test -test.run '^$' -test.bench 'Redact/.*/size=1m/hits|Restore' \
    -test.benchmem -test.count 3 -test.benchtime 200ms | tee "$R/go-bench-v2.txt"
  cd "$here/rust"
  RUSTFLAGS="-C target-cpu=x86-64-v2" CARGO_TARGET_DIR=target-v2 RB_RUST_ENGINES="ac-auto" taskset -c $CPU \
    cargo bench --bench redact -- 'redact/.*/size=1m/hits|restore' 2>&1 | grep -E 'time:|thrpt:|^(redact|restore)/' | tee "$R/rust-criterion-v2.txt"
fi
