#!/usr/bin/env bash
# env.sh: record machine and toolchain info
echo "date: $(date -Is)"
echo "kernel: $(uname -srmo)"
lscpu | grep -E '^(Model name|CPU\(s\)|Thread|Core|Socket|CPU max MHz|CPU min MHz|L1d|L2|L3|Flags)' | sed 's/^Flags:.*avx512f.*/Flags: (avx2, avx512f, bmi2 present)/'
echo "governor: $(cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor 2>/dev/null)"
echo "thp: $(cat /sys/kernel/mm/transparent_hugepage/enabled)"
echo "mem: $(free -g | awk '/Mem:/{print $2" GiB total"}')"
echo "loadavg at start: $(cut -d' ' -f1-3 /proc/loadavg)"
echo "go: $(go version)"
echo "rustc: $(rustc --version)"
echo "cargo: $(cargo --version)"
echo "podman: $(podman --version)"
echo "oha image: ghcr.io/hatoo/oha:1.17.0"
echo "Go build: CGO_ENABLED=0 GOAMD64=v3; Rust: release lto=fat codegen-units=1 panic=abort target-cpu=x86-64-v3"
cd "$(dirname "$0")/.."
echo "go deps:"; grep -E 'aho|corasick' go/go.mod | sed 's/^/  /'
echo "rust deps:"; grep -A1 -E '^name = "(aho-corasick|memchr|serde_json|hyper|tokio|criterion|hmac|sha2)"$' rust/Cargo.lock | grep -v '^--' | paste - - | sed 's/^/  /'
