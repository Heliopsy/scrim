#!/usr/bin/env python3
"""Build results/summary.md (tables used in README) from the raw results.

usage: report.py <results dir>
"""
import json, os, re, statistics as st, sys

R = sys.argv[1]
out = []
P = lambda s="": out.append(s)


def load_json(name, default=None):
    p = os.path.join(R, name)
    return json.load(open(p)) if os.path.exists(p) else default


def jsonl(name):
    p = os.path.join(R, name)
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def gobench(name):
    """name -> dict(metric -> median over -count runs)."""
    p = os.path.join(R, name)
    res = {}
    if not os.path.exists(p):
        return res
    for l in open(p):
        if not l.startswith("Benchmark"):
            continue
        f = l.split()
        key = re.sub(r"-\d+$", "", f[0])
        vals = {}
        for i in range(2, len(f) - 1, 2):
            try:
                vals[f[i + 1]] = float(f[i])
            except ValueError:
                pass
        res.setdefault(key, []).append(vals)
    return {k: {m: st.median([v[m] for v in vs if m in v]) for m in vs[0]} for k, vs in res.items()}


def fmt(x, d=1):
    if x is None:
        return "n/a"
    if x >= 1000:
        return f"{x:,.0f}"
    return f"{x:.{d}f}"


go = gobench("go-bench.txt")
gob = gobench("go-bench-build.txt")
rs = {r["id"]: r for r in load_json("rust-criterion.json", [])}
MiB = 1024 * 1024


def rs_mbps(i):
    r = rs.get(i)
    if not r or not r.get("throughput"):
        return None
    b = r["throughput"].get("Bytes") or r["throughput"].get("BytesDecimal")
    return b / (r["mean_ns"] / 1e9) / 1e6


def go_mbps(k):
    return go.get(k, {}).get("MB/s")


GO_ENG = ["petar-nfa", "pgavlin-nfa", "petar-dfa", "coregx"]
RS_ENG = ["ac-auto", "ac-dfa"]
CONFORMING_GO = ["petar-nfa", "pgavlin-nfa", "petar-dfa"]

env = open(os.path.join(R, "env.txt")).read() if os.path.exists(os.path.join(R, "env.txt")) else ""

P("## Micro: redact throughput (MB/s, 1 MB = 10^6 bytes, single pinned CPU, median)")
P()
P("| set | body | " + " | ".join(f"Go {e}" for e in GO_ENG) + " | " + " | ".join(f"Rust {e}" for e in RS_ENG) + " | best Rust / best Go |")
P("|---|---|" + "---|" * (len(GO_ENG) + len(RS_ENG) + 1))
ratios = []
for n in (10, 1000, 10000):
    for size in ("100k", "1m", "4m"):
        for kind in ("hits", "clean"):
            gv = [go_mbps(f"BenchmarkRedact/engine={e}/set={n}/size={size}/{kind}") for e in GO_ENG]
            rv = [rs_mbps(f"redact/engine={e}/set={n}/size={size}/{kind}") for e in RS_ENG]
            if not any(gv) and not any(rv):
                continue
            bg = max([v for e, v in zip(GO_ENG, gv) if v and e in CONFORMING_GO], default=None)
            br = max([v for v in rv if v], default=None)
            ratio = br / bg if bg and br else None
            if ratio:
                ratios.append((n, size, kind, ratio))
            P(f"| {n} | {size} {kind} | " + " | ".join(fmt(v) for v in gv) + " | " + " | ".join(fmt(v) for v in rv) + f" | {fmt(ratio, 2)}x |")
P()
P("coregx is not leftmost-longest (earliest-end); it fails the round-trip and cross-check on one fixture, so it is excluded from 'best Go'. "
  "DFA engines are not run at 10k secrets (Go petar-dfa needs ~14 GB, Rust ac-dfa 3.4 GB).")
P()

P("## Micro: allocations per redact call")
P()
P("| set | body | Go petar-nfa allocs/op | Go petar-nfa B/op | Go petar-dfa allocs/op | Rust ac-auto allocs | Rust ac-auto bytes |")
P("|---|---|---|---|---|---|---|")
ra = {(a["set"], a["file"]): a for a in jsonl("rust-allocs.jsonl") if a["op"] == "redact"}
for n in (10, 1000, 10000):
    for size in ("100k", "1m", "4m"):
        for kind in ("hits", "clean"):
            k1 = go.get(f"BenchmarkRedact/engine=petar-nfa/set={n}/size={size}/{kind}", {})
            k2 = go.get(f"BenchmarkRedact/engine=petar-dfa/set={n}/size={size}/{kind}", {})
            f = f"body-{size}-s{n}.json" if kind == "hits" else f"body-{size}-clean.json"
            a = ra.get((n, f), {})
            if not k1 and not a:
                continue
            P(f"| {n} | {size} {kind} | {fmt(k1.get('allocs/op'),0)} | {fmt(k1.get('B/op'),0)} | {fmt(k2.get('allocs/op'),0)} | {a.get('allocs','n/a')} | {a.get('bytes','n/a')} |")
P()
P("Go output buffers come from a sync.Pool; Rust reuses one Vec. Go allocations are inside the AC libraries' iterators (one *Match per match plus iterator state).")
P()

P("## Micro: SSE restore (secret set 1000)")
P()
P("| stream | chunks | Go µs/stream | Go µs/chunk | Go MB/s | Go allocs/stream | Rust µs/stream | Rust µs/chunk | Rust MB/s | Rust allocs/stream | Go/Rust time |")
P("|---|---|---|---|---|---|---|---|---|---|---|")
rsa = {a["file"]: a for a in jsonl("rust-allocs.jsonl") if a["op"] == "restore"}
for s_ in ("2k", "20k"):
    g = go.get(f"BenchmarkRestore/stream={s_}", {})
    rk = [k for k in rs if k.startswith(f"restore/stream={s_}/")]
    r = rs.get(rk[0]) if rk else None
    chunks = int(rk[0].split("chunks=")[1]) if rk else None
    rus = r["mean_ns"] / 1000 if r else None
    gus = g.get("ns/op", 0) / 1000 if g else None
    P(f"| {s_} | {chunks} | {fmt(gus)} | {fmt(g.get('us/chunk'),2)} | {fmt(g.get('MB/s'))} | {fmt(g.get('allocs/op'),0)} | {fmt(rus)} | "
      f"{fmt(rus / chunks if rus and chunks else None, 2)} | {fmt(rs_mbps(rk[0]) if rk else None)} | {rsa.get('stream-'+s_, {}).get('allocs','n/a')} | {fmt(gus / rus if gus and rus else None, 2)}x |")
P()

P("## Micro: automaton build")
P()
P("| set | lang | engine | build ms (one-shot) | build ms (bench median) | retained heap MB | peak RSS MB |")
P("|---|---|---|---|---|---|---|")
for b in jsonl("buildmem.jsonl"):
    if b["lang"] == "go":
        bm = gob.get(f"BenchmarkBuild/engine={b['engine']}/set={b['secrets']}", {}).get("ns/op")
    else:
        r = rs.get(f"build/engine={b['engine']}/set={b['secrets']}")
        bm = r["median_ns"] if r else None
    P(f"| {b['secrets']} | {b['lang']} | {b['engine']}{' ('+b['ac_kind']+')' if 'ac_kind' in b else ''} | {fmt(b['build_ms'])} | "
      f"{fmt(bm / 1e6 if bm else None)} | {fmt(b['retained_bytes'] / MiB)} | {fmt(b['peak_rss_kb'] / 1024)} |")
P()

for v2name, rsv2 in (("go-bench-v2.txt", "rust-criterion-v2.txt"),):
    if os.path.exists(os.path.join(R, v2name)):
        P("## x86-64-v2 vs v3 (subset)")
        P()
        g2 = gobench(v2name)
        r2 = {}
        cur = None
        for l in open(os.path.join(R, rsv2)):
            if re.match(r"^(redact|restore)/", l):
                cur = l.strip()
            m = re.search(r"thrpt:\s+\[[^\]]*?([\d.]+) (GiB|MiB|KiB)/s ([\d.]+) (GiB|MiB|KiB)/s", l)
            if m and cur:
                mult = {"GiB": 1024**3, "MiB": MiB, "KiB": 1024}[m.group(4)]
                r2[cur] = float(m.group(3)) * mult / 1e6
                cur = None
        P("| benchmark | Go v3 MB/s | Go v2 MB/s | Rust v3 MB/s | Rust v2 MB/s |")
        P("|---|---|---|---|---|")
        for n in (10, 1000, 10000):
            for e in ("petar-nfa", "petar-dfa"):
                k = f"BenchmarkRedact/engine={e}/set={n}/size=1m/hits"
                if k in g2:
                    P(f"| Go {e} set={n} 1m hits | {fmt(go_mbps(k))} | {fmt(g2[k].get('MB/s'))} | | |")
            k = f"redact/engine=ac-auto/set={n}/size=1m/hits"
            if k in r2:
                P(f"| Rust ac-auto set={n} 1m hits | | | {fmt(rs_mbps(k))} | {fmt(r2[k])} |")
        P()

# ------------------------------------------------------------------ proxy
def agg(rows, key):
    xs = [r[key] for r in rows if r.get(key) is not None]
    return st.median(xs) if xs else None


def proxy_tables(px, title):
    if not px:
        return {}
    res = px["results"]
    P(f"## {title}")
    P()
    P(f"Dictionary: {px['secret_set']} secrets; response fixture `{px['stream']}`; medians over repetitions. "
      "Latency = full request incl. streamed response (oha). Added = target minus direct-to-upstream at the same load.")
    P()
    groups = {}
    for r in res:
        groups.setdefault((r["scenario"], r["concurrency"], r["target"]), []).append(r)
    scen = sorted({(r["scenario"], r["concurrency"]) for r in res}, key=lambda x: (x[0], x[1]))
    targets = [t for t in ["direct", "go", "rust", "combo-async", "combo-nodiff", "combo-syncaudit", "combo-grant"]
               if any(r["target"] == t for r in res)]
    P("| scenario | conc | target | ok req | req/s | p50 ms | p99 ms | p999 ms | added p50 | added p99 | added p999 | TTFB p50 | CPU s/GB (proxy) | CPU s/GB (+cp) | peak RSS MB (proxy) | cp RSS MB |")
    P("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    summary = {}
    for sc, c in scen:
        d = groups.get((sc, c, "direct"), [])
        dp = {k: agg(d, k) for k in ("p50_ms", "p99_ms", "p999_ms")}
        for t in targets:
            g = groups.get((sc, c, t))
            if not g:
                continue
            m = {k: agg(g, k) for k in ("ok_requests", "rps", "p50_ms", "p99_ms", "p999_ms", "ttfb_p50_ms", "cpu_s_per_gb",
                                        "cpu_s_per_gb_incl_cp", "peak_rss_kb", "cp_peak_rss_kb")}
            add = {k: (m[k] - dp[k]) if t != "direct" and dp[k] is not None else None for k in ("p50_ms", "p99_ms", "p999_ms")}
            summary[(sc, c, t)] = dict(m, **{"add_" + k: v for k, v in add.items()})
            P(f"| {sc} | {c} | {t} | {fmt(m['ok_requests'],0)} | {fmt(m['rps'])} | {fmt(m['p50_ms'])} | {fmt(m['p99_ms'])} | {fmt(m['p999_ms'])} | "
              f"{fmt(add['p50_ms'])} | {fmt(add['p99_ms'])} | {fmt(add['p999_ms'])} | {fmt(m['ttfb_p50_ms'])} | {fmt(m['cpu_s_per_gb'],2)} | "
              f"{fmt(m['cpu_s_per_gb_incl_cp'],2) if t.startswith('combo') else ''} | {fmt(m['peak_rss_kb']/1024)} | "
              f"{fmt(m['cp_peak_rss_kb']/1024) if t.startswith('combo') else ''} |")
    P()
    return summary


px = load_json("proxy.json")
pxs = proxy_tables(px, "Proxy level (main run)")
px2 = load_json("proxy-set1000.json")
pxs2 = proxy_tables(px2, "Proxy level (secondary run, 1000-secret dictionary)")

if px:
    P("## Combo arm: boundary details (control plane in Go over UDS, length-prefixed JSON frames)")
    P()
    P("| scenario | conc | variant | audit events | events/s | UDS in MB/s | batches | drops | grant RTT p50/p99 ms | req p99 outside rebuild | req p99 during rebuild | n during | cp CPU s |")
    P("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    full_push, diffs = None, []
    for r in px["results"]:
        c = r.get("cp")
        if not c:
            continue
        full_push = full_push or c.get("full_push")
        diffs += [d for d in (c.get("diff_pushes") or []) if d.get("ack")]
        g = c["grant_rtt"]
        P(f"| {r['scenario']} | {r['concurrency']} | {r['target']} r{r['rep']} | {c['async_events'] + c['sync_events']} | {fmt(c['events_per_s'])} | "
          f"{fmt(c['uds_in_MBps'],3)} | {c['audit_batches']} | {c['dp_reported_drops']} | "
          f"{(fmt(g['p50_ms'],3) + ' / ' + fmt(g['p99_ms'],3)) if g['n'] else ''} | {fmt(c['latency_outside_rebuild']['p99_ms'])} | "
          f"{fmt(c['latency_during_rebuild']['p99_ms'])} | {c['latency_during_rebuild']['n']} | {fmt(r['cp_cpu_s'],2)} |")
    P()
    if full_push:
        a = full_push["ack"]
        P("Dictionary sync:")
        P()
        P("| push | secrets | payload bytes | CP encode ms | DP decode ms | DP automaton build ms | send -> live ms |")
        P("|---|---|---|---|---|---|---|")
        P(f"| full (start) | {full_push['secrets']} | {full_push['bytes']:,} | {fmt(full_push['encode_ms'])} | {fmt(a['decode_ms'])} | {fmt(a['build_ms'])} | {fmt(full_push['sync_ms'])} |")
        if diffs:
            med = lambda k, sub=None: st.median([(d["ack"][k] if sub else d[k]) for d in diffs])
            P(f"| diff (every 2 s, n={len(diffs)}) | {diffs[0]['secrets']} | {diffs[0]['bytes']:,} | {fmt(med('encode_ms'))} | "
              f"{fmt(med('decode_ms', 1))} | {fmt(med('build_ms', 1))} (p max {fmt(max(d['ack']['build_ms'] for d in diffs))}) | {fmt(med('sync_ms'))} |")
        P()
        P("A diff triggers a full automaton rebuild (aho-corasick has no incremental insert) on a tokio blocking thread; "
          "the old snapshot keeps serving until an atomic swap.")
        P()

# ------------------------------------------------------------------ decision rule
P("## Decision rule evaluation")
P()
if pxs:
    P("| load (unpaced 1 MB) | Go CPU s/GB | Rust CPU s/GB | Go/Rust | combo-async (+cp) s/GB | Go/combo | Go p99 | Rust p99 | combo p99 |")
    P("|---|---|---|---|---|---|---|---|---|")
    for c in (10, 100, 1000):
        g = pxs.get(("unpaced-1m", c, "go"))
        r = pxs.get(("unpaced-1m", c, "rust"))
        k = pxs.get(("unpaced-1m", c, "combo-async"))
        if not g or not r:
            continue
        kc = k["cpu_s_per_gb_incl_cp"] if k else None
        P(f"| c={c} | {fmt(g['cpu_s_per_gb'],2)} | {fmt(r['cpu_s_per_gb'],2)} | {fmt(g['cpu_s_per_gb']/r['cpu_s_per_gb'],2)}x | "
          f"{fmt(kc,2)} | {fmt(g['cpu_s_per_gb']/kc if kc else None,2)}x | {fmt(g['p99_ms'])} | {fmt(r['p99_ms'])} | {fmt(k['p99_ms'] if k else None)} |")
    P()
P("<!-- generated by harness/report.py -->")
open(os.path.join(R, "summary.md"), "w").write("\n".join(out) + "\n")
print("\n".join(out))
