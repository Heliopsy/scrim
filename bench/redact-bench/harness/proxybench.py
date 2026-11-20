#!/usr/bin/env python3
"""Proxy-level benchmark: direct-to-upstream vs Go proxy vs Rust proxy.

Load generator: oha in a rootless podman container (--network host), pinned with --cpuset-cpus.
Proxies and upstream are pinned with taskset. Each run starts fresh processes so VmHWM is per run.

usage: proxybench.py --mode quick|full --out results/proxy.json
"""
import argparse, json, os, signal, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, "fixtures", "data")
OHA_IMAGE = "ghcr.io/hatoo/oha:1.17.0"

CPU_PROXY = os.environ.get("RB_CPU_PROXY", "2-5")       # 4 logical CPUs, distinct physical cores
CPU_UPSTREAM = os.environ.get("RB_CPU_UPSTREAM", "8-13")
CPU_LOADGEN = os.environ.get("RB_CPU_LOADGEN", "14-17,32-35")

CPU_CP = os.environ.get("RB_CPU_CP", "6-7")             # control plane (combo arm only)
PORT_UP, PORT_GO, PORT_RS = 18100, 18101, 18102
SET = int(os.environ.get("RB_PROXY_SET", "10000"))      # dictionary size for all proxy-level runs
STREAM = f"stream-proxy-s{SET}" if SET != 1000 else "stream-proxy"
# combo arm variants: (data-plane args, control-plane diff interval)
COMBO = {"combo-async": (["-audit", "async"], "2s"),
         "combo-nodiff": (["-audit", "async"], "0s"),
         "combo-syncaudit": (["-audit", "sync"], "2s"),
         "combo-grant": (["-audit", "async", "-grant", "sync"], "2s")}
TICK = os.sysconf("SC_CLK_TCK")


def cpu_seconds(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / TICK  # utime, stime


def hwm_kb(pid):
    for l in open(f"/proc/{pid}/status"):
        if l.startswith("VmHWM:"):
            return int(l.split()[1])
    return 0


def port_free(port):
    import socket
    try:
        socket.create_connection(("127.0.0.1", port), 0.2).close()
        return False
    except OSError:
        return True


def wait_port(port, timeout=60):
    import socket
    t = time.time()
    while time.time() - t < timeout:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} not up")


def start(cmd, cpus, env=None, log=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.Popen(["taskset", "-c", cpus] + cmd, env=e, stdout=log or subprocess.DEVNULL,
                            stderr=subprocess.STDOUT, start_new_session=True)


def stop(p):
    if p and p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)


def oha(port, body, conc, dur, tag):
    name = f"redact-bench-oha-{tag}"
    cmd = ["podman", "run", "--rm", "--name", name, "--network", "host", "--cpuset-cpus", CPU_LOADGEN,
           "-v", f"{D}:/data:ro", OHA_IMAGE, "-z", dur, "-c", str(conc), "-m", "POST",
           "-H", "content-type: application/json", "-D", f"/data/{body}", "--no-tui",
           "--output-format", "json", f"http://127.0.0.1:{port}/v1/messages"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    subprocess.run(["podman", "rm", "-f", name], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[-2000:])
    return json.loads(r.stdout)


def run_one(target, body, conc, dur, delay, secrets, go_engine, rs_engine, tag, logdir):
    for p in (PORT_UP, PORT_GO, PORT_RS):
        if not port_free(p):
            raise RuntimeError(f"port {p} busy: a stale process is listening")
    up = start([f"{ROOT}/go/bin/upstream", "-addr", f"127.0.0.1:{PORT_UP}", "-stream", f"{D}/{STREAM}.sse",
                "-chunks", f"{D}/{STREAM}.chunks", "-delay", delay], CPU_UPSTREAM)
    px = cp = None
    cp_out = f"{logdir}/{tag}-cp.json"
    sock = f"{ROOT}/scratch/cp-{tag}.sock"
    try:
        wait_port(PORT_UP)
        port = PORT_UP
        if target == "go":
            px = start([f"{ROOT}/go/bin/proxy", "-listen", f"127.0.0.1:{PORT_GO}", "-secrets", secrets, "-engine", go_engine],
                       CPU_PROXY, log=open(f"{logdir}/{tag}.log", "w"))
            port = PORT_GO
        elif target == "rust":
            px = start([f"{ROOT}/rust/target/release/proxy", "-listen", f"127.0.0.1:{PORT_RS}", "-secrets", secrets, "-engine", rs_engine],
                       CPU_PROXY, log=open(f"{logdir}/{tag}.log", "w"))
            port = PORT_RS
        elif target in COMBO:
            cp = start([f"{ROOT}/go/bin/controlplane", "-sock", sock, "-secrets", secrets, "-out", cp_out,
                        "-diff-every", COMBO[target][1], "-diff-n", "100"], CPU_CP, log=open(f"{logdir}/{tag}-cp.log", "w"))
            px = start([f"{ROOT}/rust/target/release/proxy", "-listen", f"127.0.0.1:{PORT_RS}", "-cp", sock, "-engine", rs_engine]
                       + COMBO[target][0], CPU_PROXY, log=open(f"{logdir}/{tag}.log", "w"))
            port = PORT_RS
        wait_port(port)
        time.sleep(0.3)
        meas = px or up
        c0, u0 = cpu_seconds(meas.pid), cpu_seconds(up.pid)
        k0 = cpu_seconds(cp.pid) if cp else 0
        rss_idle = hwm_kb(meas.pid)
        t0 = time.time()
        res = oha(port, body, conc, dur, tag)
        wall = time.time() - t0
        c1, u1 = cpu_seconds(meas.pid), cpu_seconds(up.pid)
        k1 = cpu_seconds(cp.pid) if cp else 0
        rss = hwm_kb(meas.pid)
        cp_rss = hwm_kb(cp.pid) if cp else 0
    finally:
        stop(px)
        stop(cp)  # SIGTERM -> control plane writes its summary
        stop(up)
    cp_summary = json.load(open(cp_out)) if cp and os.path.exists(cp_out) else None
    s = res["summary"]
    lp = res.get("latencyPercentiles", {})
    fb = res.get("firstBytePercentiles") or {}
    codes = res.get("statusCodeDistribution", {})
    ok = int(codes.get("200", 0))
    body_bytes = os.path.getsize(f"{D}/{body}")
    resp_bytes = os.path.getsize(f"{D}/{STREAM}.sse")
    gb = ok * (body_bytes + resp_bytes) / 1e9
    proc_cpu = c1 - c0
    return {
        "target": target, "body": body, "secret_set": SET, "concurrency": conc, "duration": dur, "delay": delay,
        "ok_requests": ok, "status_codes": codes, "error_distribution": res.get("errorDistribution", {}),
        "rps": ok / s["total"] if s.get("total") else 0, "success_rate": s.get("successRate"),
        "p50_ms": (lp.get("p50") or 0) * 1000, "p99_ms": (lp.get("p99") or 0) * 1000,
        "p999_ms": (lp.get("p99.9") or 0) * 1000, "avg_ms": (s.get("average") or 0) * 1000,
        "ttfb_p50_ms": (fb.get("p50") or 0) * 1000, "ttfb_p99_ms": (fb.get("p99") or 0) * 1000,
        "proc_cpu_s": proc_cpu, "cp_cpu_s": k1 - k0, "upstream_cpu_s": u1 - u0, "gb_processed": gb,
        "cpu_s_per_gb": proc_cpu / gb if gb > 0 else None,
        "cpu_s_per_gb_incl_cp": (proc_cpu + k1 - k0) / gb if gb > 0 else None,
        "peak_rss_kb": rss, "cp_peak_rss_kb": cp_rss, "rss_after_start_kb": rss_idle, "wall_s": wall,
        "cp": cp_summary,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="quick")
    ap.add_argument("--out", required=True)
    ap.add_argument("--go-engine", default=os.environ.get("RB_GO_PROXY_ENGINE", "petar-nfa"))
    ap.add_argument("--rs-engine", default="ac-auto")
    ap.add_argument("--secondary", action="store_true", help="short run: direct/go/rust only")
    a = ap.parse_args()
    full = a.mode == "full"
    secrets = f"{D}/secrets-{SET}.json"
    logdir = os.path.join(ROOT, "scratch", "proxylogs")
    os.makedirs(logdir, exist_ok=True)
    subprocess.run(["podman", "image", "exists", OHA_IMAGE]) .returncode == 0 or \
        subprocess.run(["podman", "pull", "-q", OHA_IMAGE], check=True)
    concs = [10, 100, 1000] if full else [10, 100]
    reps = 2 if full else 1
    core = ["direct", "go", "rust", "combo-async"] + (["combo-nodiff"] if full else [])
    syncv = ["combo-syncaudit", "combo-grant"] if full else []
    scen = []
    if a.secondary:
        core, syncv, reps = ["direct", "go", "rust"], [], 1
        concs = [10, 100]
    # latency with realistic pacing: 100 KB request, 21-chunk SSE response, 15 ms between chunks
    for c in concs:
        scen.append(dict(name="paced", body=f"body-100k-s{SET}.json", conc=c, dur="12s" if full else "5s", delay="15ms", targets=core + syncv))
    # throughput / CPU per GB: 1 MB request, no pacing
    for c in concs:
        scen.append(dict(name="unpaced-1m", body=f"body-1m-s{SET}.json", conc=c, dur="8s" if full else "5s", delay="0s",
                         targets=core + (syncv if c == 100 else [])))
    if full:  # clean body (common case, no hits)
        scen.append(dict(name="unpaced-1m-clean", body="body-1m-clean.json", conc=100, dur="8s", delay="0s", targets=core))
    results = []
    for rep in range(reps):
        for sc in scen:
            for tgt in sc["targets"]:
                if rep > 0 and tgt in syncv:
                    continue
                tag = f"{sc['name']}-c{sc['conc']}-{tgt}-r{rep}"
                r = run_one(tgt, sc["body"], sc["conc"], sc["dur"], sc["delay"], secrets, a.go_engine, a.rs_engine, tag, logdir)
                r.update(scenario=sc["name"], rep=rep, go_engine=a.go_engine, rs_engine=a.rs_engine,
                         cpus={"proxy": CPU_PROXY, "upstream": CPU_UPSTREAM, "loadgen": CPU_LOADGEN, "cp": CPU_CP})
                print(f"{tag:36s} ok={r['ok_requests']:6d} rps={r['rps']:8.1f} p50={r['p50_ms']:8.1f} p99={r['p99_ms']:8.1f} "
                      f"p999={r['p999_ms']:8.1f} ttfb50={r['ttfb_p50_ms']:7.1f} cpu/GB={r['cpu_s_per_gb'] or 0:6.2f}"
                      f"(+cp {r['cpu_s_per_gb_incl_cp'] or 0:6.2f}) rss={r['peak_rss_kb']/1024:7.1f}MB cp_rss={r['cp_peak_rss_kb']/1024:6.1f}MB", flush=True)
                results.append(r)
    json.dump({"image": OHA_IMAGE, "secret_set": SET, "stream": STREAM, "results": results}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
