#!/usr/bin/env bash
# run-cli.sh <go|rust> <outdir> : run one implementation's CLI over every fixture
set -euo pipefail
lang=$1; out=$2
here=$(cd "$(dirname "$0")/.." && pwd)
D=$here/fixtures/data
if [ "$lang" = go ]; then
  cli=$here/go/bin/rbcli
  engines_small="petar-nfa petar-dfa pgavlin-nfa coregx"   # DFA variants do not fit in RAM at 10k secrets
  engines_big="petar-nfa pgavlin-nfa"
else
  cli=$here/rust/target/release/rbcli
  engines_small="ac-auto ac-dfa"
  engines_big="ac-auto"
fi
rm -rf "$out"; mkdir -p "$out/restore"
for n in 10 1000 10000; do
  files=$(ls $D/body-*-s$n.json | tr '\n' ',')
  [ $n = 1000 ] && files="$files$(ls $D/body-*-clean.json | tr '\n' ',')"
  files=${files%,}
  engs=$engines_small; [ $n = 10000 ] && engs=$engines_big
  for e in $engs; do
    mkdir -p "$out/redact/$e"
    "$cli" redact -engine $e -secrets $D/secrets-$n.json -in "$files" -out "$out/redact/$e"
  done
done
for s in 2k 20k proxy proxy-s10000; do
  n=1000; [ $s = proxy-s10000 ] && n=10000
  "$cli" restore -secrets $D/secrets-$n.json -in $D/stream-$s.sse -chunks $D/stream-$s.chunks -out "$out/restore/stream-$s.sse" >/dev/null
done
"$cli" patterns -secrets $D/secrets-10000.json | sha256sum | cut -d' ' -f1 > "$out/patterns-10000.sha256"
echo "$lang outputs in $out"
