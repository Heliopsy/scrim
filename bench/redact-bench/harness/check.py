#!/usr/bin/env python3
"""Language-neutral invariant checks, applied identically to Go and Rust outputs.

usage: check.py <fixtures/data> <outdir-go> <outdir-rust>
Each outdir holds: redact/<engine>/<body>.json (+ .meta.json from the CLI) and restore/<stream>.sse
"""
import hashlib, hmac, json, os, re, sys

D, OUTS = sys.argv[1], sys.argv[2:]
man = json.load(open(os.path.join(D, "manifest.json")))
key = bytes.fromhex(man["hmac_key_hex"])
fail = []
report = {"checks": [], "crosscheck": []}


# engines known not to implement leftmost-longest; their failures are reported, not gated
NONCONFORMING = ("coregx",)
xfail = []


def ok(name, cond, detail=""):
    report["checks"].append({"check": name, "pass": bool(cond), "detail": detail})
    if not cond:
        (xfail if any(e in name for e in NONCONFORMING) else fail).append(f"{name}: {detail}")


def esc(s):  # canonical J1 escaping (same as the spec)
    return json.dumps(s, ensure_ascii=False)[1:-1]


def ph(v):
    return "⟦kss:" + hmac.new(key, v.encode(), hashlib.sha256).hexdigest()[:12] + "⟧"


secrets = {n: json.load(open(os.path.join(D, f"secrets-{n}.json")))["secrets"] for n in (10, 1000, 10000)}
phmaps = {n: {ph(s): s for s in secrets[n]} for n in (1000, 10000)}
phmap = phmaps[1000]


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def parse_sse(b):
    evs = []
    for raw in b.split(b"\n\n"):
        if not raw:
            continue
        lines = raw.split(b"\n")
        name = lines[0][len(b"event: "):].decode()
        data = json.loads(lines[1][len(b"data: "):])
        evs.append((name, data, raw))
    return evs


for out in OUTS:
    lang = os.path.basename(out.rstrip("/"))
    # --- redact
    rdir = os.path.join(out, "redact")
    for eng in sorted(os.listdir(rdir)):
        for f in sorted(os.listdir(os.path.join(rdir, eng))):
            if not f.endswith(".json") or f.endswith(".meta.json"):
                continue
            p = os.path.join(rdir, eng, f)
            meta = json.load(open(p[:-5] + ".meta.json"))
            ok(f"{lang}/{eng}/{f}: no variant left (rescan)", meta["remaining"] == 0, str(meta))
            body = open(p, "rb").read()
            try:
                json.loads(body)
                valid = True
            except Exception as e:  # noqa
                valid = False
            ok(f"{lang}/{eng}/{f}: output is valid JSON", valid)
            exp_hits = man["bodies"][f]["hits"]
            if "clean" in f:
                ok(f"{lang}/{eng}/{f}: clean body has 0 matches and is unchanged",
                   meta["matches"] == 0 and sha(p) == man["sha256"][f])
            else:
                ok(f"{lang}/{eng}/{f}: matches >= embedded hits", meta["matches"] >= exp_hits,
                   f'{meta["matches"]} vs {exp_hits}')
            if f == "body-rt-s1000.json":
                s = body.decode()
                restored = re.sub("⟦kss:[0-9a-f]{12}⟧", lambda m: esc(phmap[m.group(0)]), s)
                ok(f"{lang}/{eng}/{f}: restore(redact(x)) == x", restored.encode() == open(os.path.join(D, f), "rb").read())
    # --- restore
    sdir = os.path.join(out, "restore")
    for f in sorted(os.listdir(sdir)):
        if not f.endswith(".sse"):
            continue
        name = f[len("stream-"):-4]
        got = parse_sse(open(os.path.join(sdir, f), "rb").read())
        src = parse_sse(open(os.path.join(D, f), "rb").read())
        exp = json.load(open(os.path.join(D, f"stream-{name}.expected.json")))
        blocks, sigs = {}, {}
        for n, d, raw in got:
            if n == "content_block_delta":
                dl = d["delta"]
                k = {"text_delta": "text", "thinking_delta": "thinking", "input_json_delta": "partial_json"}.get(dl["type"])
                if k:
                    blocks[d["index"]] = blocks.get(d["index"], "") + dl[k]
                elif dl["type"] == "signature_delta":
                    sigs[d["index"]] = raw
        bad = [e["index"] for e in exp if blocks.get(e["index"], "") != e["content"]]
        ok(f"{lang}/{f}: restored block content == original ({len(exp)} blocks)", not bad, f"bad blocks {bad[:5]}")
        tools_ok = all(json.loads(blocks[e["index"]]) is not None for e in exp if e["type"] == "tool_use")
        ok(f"{lang}/{f}: restored tool input parses as JSON", tools_ok)
        src_sigs = {d["index"]: raw for n, d, raw in src if n == "content_block_delta" and d["delta"]["type"] == "signature_delta"}
        ok(f"{lang}/{f}: signature_delta byte-identical", src_sigs == sigs and len(sigs) > 0)
        nd = lambda evs: [raw for n, d, raw in evs if n != "content_block_delta"]
        ok(f"{lang}/{f}: non-delta events byte-identical and in order", nd(src) == nd(got))
        # placeholders that must remain: only unknown ones
        left = set(re.findall("⟦kss:[0-9a-f]{12}⟧", "".join(blocks.values())))
        ok(f"{lang}/{f}: no known placeholder left in text", not (left & set(phmaps[man["streams"][name]["secret_set"]])))

# --- cross-check: byte-identical outputs Go vs Rust
if len(OUTS) == 2:
    a, b = OUTS
    for sub in ("redact", "restore"):
        ra = os.path.join(a, sub)
        for root, _, files in os.walk(ra):
            for f in sorted(files):
                if f.endswith(".meta.json"):
                    continue
                pa = os.path.join(root, f)
                rel = os.path.relpath(pa, ra)
                if sub == "redact":  # compare every engine against every engine of the other language
                    fname = os.path.basename(rel)
                    for eng in sorted(os.listdir(os.path.join(b, sub))):
                        pb = os.path.join(b, sub, eng, fname)
                        if os.path.exists(pb):
                            same = sha(pa) == sha(pb)
                            report["crosscheck"].append({"a": rel, "b": f"{eng}/{fname}", "identical": same})
                            ok(f"crosscheck {sub}/{rel} == rust/{eng}/{fname}", same)
                else:
                    pb = os.path.join(b, sub, rel)
                    same = os.path.exists(pb) and sha(pa) == sha(pb)
                    report["crosscheck"].append({"a": rel, "b": rel, "identical": same})
                    ok(f"crosscheck {sub}/{rel}", same)

n = len(report["checks"])
print(f"{n - len(fail) - len(xfail)}/{n} checks passed, {len(xfail)} xfail (nonconforming engine), {sum(c['identical'] for c in report['crosscheck'])}/{len(report['crosscheck'])} cross-check pairs identical")
for f in fail[:30]:
    print("FAIL", f)
for f in xfail:
    print("XFAIL (nonconforming engine)", f)
report["xfail"] = xfail
json.dump(report, open(os.environ.get("CHECK_REPORT", "/dev/null"), "w"), indent=1)
sys.exit(1 if fail else 0)
