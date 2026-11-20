//! proxy: minimal redacting proxy (hyper 1.x + tokio). Redacts the request body,
//! forwards it, restores the streamed SSE response chunk by chunk.
//!
//! Pure mode (default): dictionary loaded from -secrets.
//! Combo mode (-cp <unix socket>): dictionary + policy snapshot pushed by the Go control
//! plane over a Unix domain socket; audit events sent to it (async batched or sync);
//! optional synchronous "check grant" round trip per request.
//!
//! Wire format (both directions): frame = u32 big-endian length of (type+payload), u8 type, payload (JSON).
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use redactbench::*;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::mpsc;

type Body = BoxBody<Bytes, hyper::Error>;

// frame types
const T_HELLO: u8 = 0;
const T_DICT_FULL: u8 = 1;
const T_DICT_DIFF: u8 = 2;
const T_AUDIT_BATCH: u8 = 3;
const T_AUDIT_SYNC: u8 = 4;
const T_AUDIT_ACK: u8 = 5;
const T_GRANT_REQ: u8 = 6;
const T_GRANT_REPLY: u8 = 7;
const T_DICT_ACK: u8 = 8;

struct Snap {
    red: Redactor,
    table: Arc<Table>,
    dict_version: u64,
    allowed_provider: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Audit {
    Off,
    Async,
    Sync,
}

struct State {
    snap: Arc<RwLock<Arc<Snap>>>,
    client: Client<HttpConnector, Full<Bytes>>,
    upstream: String,
    audit: Audit,
    grant_sync: bool,
    audit_tx: Option<mpsc::Sender<Vec<u8>>>,
    cp_path: String,
    pool: Mutex<Vec<UnixStream>>,
    reqs: AtomicU64,
    drops: AtomicU64,
}

fn arg(name: &str, def: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned()).unwrap_or_else(|| def.to_string())
}

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

fn text(code: u16, msg: String) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(Full::new(Bytes::from(msg)).map_err(|never: Infallible| match never {}).boxed())
        .unwrap()
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[..4].copy_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    hdr[4] = t;
    w.write_all(&hdr).await?;
    w.write_all(payload).await
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    let n = u32::from_be_bytes(hdr[..4].try_into().unwrap()) as usize;
    let mut p = vec![0u8; n - 1];
    r.read_exact(&mut p).await?;
    Ok((hdr[4], p))
}

/// Synchronous request/reply over a pooled UDS connection.
async fn sync_call(st: &State, t: u8, payload: &[u8]) -> std::io::Result<(u8, Vec<u8>)> {
    let conn = st.pool.lock().unwrap().pop();
    let mut c = match conn {
        Some(c) => c,
        None => {
            let mut c = UnixStream::connect(&st.cp_path).await?;
            write_frame(&mut c, T_HELLO, br#"{"role":"sync"}"#).await?;
            c
        }
    };
    write_frame(&mut c, t, payload).await?;
    let r = read_frame(&mut c).await?;
    st.pool.lock().unwrap().push(c);
    Ok(r)
}

struct ReqInfo {
    id: u64,
    agent: String,
    refs: Vec<u32>,
    matches: usize,
    dict_version: u64,
    t0: Instant,
    t_redact_us: u64,
    t_grant_us: u64,
    t_ttfb_us: u64,
    bytes_in: usize,
    bytes_out: usize,
}

fn audit_event(ri: &ReqInfo, drops: u64) -> Vec<u8> {
    let mut refs = String::new();
    for (i, r) in ri.refs.iter().take(16).enumerate() {
        if i > 0 {
            refs.push(',');
        }
        refs.push_str(&r.to_string());
    }
    format!(
        r#"{{"ts_us":{},"agent_id":"{}","provider":"anthropic","model":"claude-sonnet-4-5","req":{},"secret_refs":[{}],"matches":{},"decision":"allow","dict_v":{},"t_redact_us":{},"t_grant_us":{},"t_ttfb_us":{},"t_total_us":{},"bytes_in":{},"bytes_out":{},"drops":{}}}"#,
        now_us(),
        ri.agent,
        ri.id,
        refs,
        ri.matches,
        ri.dict_version,
        ri.t_redact_us,
        ri.t_grant_us,
        ri.t_ttfb_us,
        ri.t0.elapsed().as_micros(),
        ri.bytes_in,
        ri.bytes_out,
        drops
    )
    .into_bytes()
}

async fn emit_audit(st: &State, ri: &ReqInfo) {
    match st.audit {
        Audit::Off => {}
        Audit::Async => {
            let ev = audit_event(ri, st.drops.load(Relaxed));
            if st.audit_tx.as_ref().unwrap().try_send(ev).is_err() {
                st.drops.fetch_add(1, Relaxed); // never block the request
            }
        }
        Audit::Sync => {
            let ev = audit_event(ri, 0);
            if !matches!(sync_call(st, T_AUDIT_SYNC, &ev).await, Ok((T_AUDIT_ACK, _))) {
                st.drops.fetch_add(1, Relaxed);
            }
        }
    }
}

async fn handle(st: Arc<State>, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let t0 = Instant::now();
    let agent = req.headers().get("x-agent-id").and_then(|v| v.to_str().ok()).unwrap_or("agent-0001").to_string();
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return Ok(text(400, e.to_string())),
    };
    let snap = st.snap.read().unwrap().clone();
    // local policy decision from the pushed snapshot (no round trip)
    if snap.allowed_provider != "anthropic" {
        return Ok(text(403, "provider not allowed".into()));
    }
    let mut buf = Vec::new();
    let mut refs = Vec::new();
    let n = if st.audit == Audit::Off && !st.grant_sync {
        snap.red.redact_into(&body, &mut buf)
    } else {
        snap.red.redact_refs(&body, &mut buf, &mut refs)
    };
    refs.sort_unstable();
    refs.dedup();
    let t_redact_us = t0.elapsed().as_micros() as u64;
    let bytes_in = body.len();
    let out = if n == 0 { body } else { Bytes::from(buf) };
    let mut t_grant_us = 0;
    if st.grant_sync {
        let tg = Instant::now();
        let q = format!(r#"{{"agent_id":"{agent}","provider":"anthropic","secret_refs":{}}}"#, refs.len());
        match sync_call(&st, T_GRANT_REQ, q.as_bytes()).await {
            Ok((T_GRANT_REPLY, _)) => {}
            _ => return Ok(text(503, "grant check failed".into())),
        }
        t_grant_us = tg.elapsed().as_micros() as u64;
    }
    let up = Request::post(format!("{}/v1/messages", st.upstream))
        .header("content-type", "application/json")
        .body(Full::new(out))
        .unwrap();
    let resp = match st.client.request(up).await {
        Ok(r) => r,
        Err(e) => return Ok(text(502, e.to_string())),
    };
    let ri = ReqInfo {
        id: st.reqs.fetch_add(1, Relaxed),
        agent,
        refs,
        matches: n,
        dict_version: snap.dict_version,
        t0,
        t_redact_us,
        t_grant_us,
        t_ttfb_us: t0.elapsed().as_micros() as u64,
        bytes_in,
        bytes_out: 0,
    };
    let (parts, incoming) = resp.into_parts();
    let restorer = Restorer::new(snap.table.clone());
    let st2 = st.clone();
    let stream = futures_util::stream::unfold(Some((incoming, restorer, ri, st2)), |s| async move {
        let (mut inc, mut rs, mut ri, st) = s?;
        loop {
            match inc.frame().await {
                Some(Ok(f)) => {
                    if let Ok(data) = f.into_data() {
                        let mut out = Vec::with_capacity(data.len() + 64);
                        rs.feed(&mut out, &data);
                        if !out.is_empty() {
                            ri.bytes_out += out.len();
                            return Some((Ok(Frame::data(Bytes::from(out))), Some((inc, rs, ri, st))));
                        }
                    }
                }
                Some(Err(e)) => return Some((Err(e), None)),
                None => {
                    let mut out = Vec::new();
                    rs.finish(&mut out);
                    ri.bytes_out += out.len();
                    emit_audit(&st, &ri).await; // sync mode: response does not complete until acked
                    if out.is_empty() {
                        return None;
                    }
                    return Some((Ok(Frame::data(Bytes::from(out))), None));
                }
            }
        }
    });
    let mut r = Response::new(StreamBody::new(stream).boxed());
    *r.status_mut() = parts.status;
    if let Some(ct) = parts.headers.get("content-type") {
        r.headers_mut().insert("content-type", ct.clone());
    }
    Ok(r)
}

// ------------------------------------------------------------ dictionary from the control plane

#[derive(Deserialize)]
struct PushedSecret {
    id: u32,
    value: String,
    variants: Vec<String>,
}

#[derive(Deserialize)]
struct DictMsg {
    version: u64,
    #[serde(default)]
    key_hex: String,
    #[serde(default)]
    allowed_provider: String,
    #[serde(default)]
    secrets: Vec<PushedSecret>,
}

/// Dictionary held by the data plane: secret id -> (value, variants).
struct Dict {
    key: Vec<u8>,
    allowed_provider: String,
    entries: Vec<Option<(Vec<u8>, Vec<Vec<u8>>)>>,
}

impl Dict {
    fn apply(&mut self, m: DictMsg, full: bool) {
        if full {
            self.entries.clear();
            self.key = hex::decode(&m.key_hex).unwrap();
            self.allowed_provider = m.allowed_provider;
        }
        for s in m.secrets {
            let i = s.id as usize;
            if self.entries.len() <= i {
                self.entries.resize(i + 1, None);
            }
            self.entries[i] = Some((s.value.into_bytes(), s.variants.into_iter().map(String::into_bytes).collect()));
        }
    }

    /// Same dedup rule as patterns(): id order, variant order, drop < MIN_VARIANT_LEN, first wins.
    fn build(&self, version: u64, engine: &str) -> Snap {
        let mut seen = std::collections::HashSet::new();
        let (mut pats, mut owner) = (Vec::new(), Vec::new());
        let mut ph = Vec::with_capacity(self.entries.len());
        let mut values = Vec::with_capacity(self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            let Some((v, vars)) = e else {
                ph.push(Vec::new());
                values.push(Vec::new());
                continue;
            };
            ph.push(placeholder(&self.key, v));
            values.push(v.clone());
            for x in vars {
                if x.len() < MIN_VARIANT_LEN || !seen.insert(x.as_slice()) {
                    continue;
                }
                pats.push(x.clone());
                owner.push(i as u32);
            }
        }
        let red = Redactor::from_patterns(&pats, owner, ph, engine);
        Snap { red, table: Arc::new(Table::new(&values, &self.key)), dict_version: version, allowed_provider: self.allowed_provider.clone() }
    }
}

/// Connects the control channel, waits for the first full dictionary, then keeps applying diffs.
async fn control_plane(path: String, engine: String, mut audit_rx: Option<mpsc::Receiver<Vec<u8>>>) -> (Arc<RwLock<Arc<Snap>>>, tokio::task::JoinHandle<()>) {
    let c = loop {
        match UnixStream::connect(&path).await {
            Ok(c) => break c,
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    let (mut rd, mut wr) = c.into_split();
    let (wtx, mut wrx) = mpsc::channel::<(u8, Vec<u8>)>(1024);
    // writer task
    tokio::spawn(async move {
        write_frame(&mut wr, T_HELLO, br#"{"role":"control"}"#).await.unwrap();
        while let Some((t, p)) = wrx.recv().await {
            if write_frame(&mut wr, t, &p).await.is_err() {
                return;
            }
        }
    });
    // audit batcher: flush every 5 ms or 256 events
    if let Some(mut rx) = audit_rx.take() {
        let wtx = wtx.clone();
        tokio::spawn(async move {
            let mut batch: Vec<u8> = Vec::with_capacity(256 * 320);
            while let Some(ev) = rx.recv().await {
                batch.extend_from_slice(&ev);
                let mut n = 1;
                let deadline = tokio::time::Instant::now() + Duration::from_millis(5);
                while n < 256 {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(ev)) => {
                            batch.push(b'\n');
                            batch.extend_from_slice(&ev);
                            n += 1;
                        }
                        _ => break,
                    }
                }
                if wtx.send((T_AUDIT_BATCH, std::mem::take(&mut batch))).await.is_err() {
                    return;
                }
                batch.reserve(256 * 320);
            }
        });
    }
    let dict = Arc::new(Mutex::new(Dict { key: Vec::new(), allowed_provider: String::new(), entries: Vec::new() }));
    // first frame must be the full dictionary
    let (t, p) = read_frame(&mut rd).await.unwrap();
    assert_eq!(t, T_DICT_FULL);
    let snap = Arc::new(RwLock::new(Arc::new(apply_and_ack(&dict, p, true, &engine, &wtx, None).await.unwrap())));
    let snap2 = snap.clone();
    let h = tokio::spawn(async move {
        while let Ok((t, p)) = read_frame(&mut rd).await {
            if t == T_DICT_DIFF {
                apply_and_ack(&dict, p, false, &engine, &wtx, Some(&snap2)).await;
            }
        }
    });
    (snap, h)
}

/// Decode + rebuild on a blocking thread, swap the snapshot, ack with timings.
async fn apply_and_ack(
    dict: &Arc<Mutex<Dict>>,
    p: Vec<u8>,
    full: bool,
    engine: &str,
    wtx: &mpsc::Sender<(u8, Vec<u8>)>,
    swap_into: Option<&Arc<RwLock<Arc<Snap>>>>,
) -> Option<Snap> {
    let recv_us = now_us();
    let bytes = p.len();
    let d = dict.clone();
    let eng = engine.to_string();
    let (snap, decode_ms, build_ms, n_pats) = tokio::task::spawn_blocking(move || {
        let t = Instant::now();
        let m: DictMsg = serde_json::from_slice(&p).unwrap();
        let v = m.version;
        let mut g = d.lock().unwrap();
        g.apply(m, full);
        let decode_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let s = g.build(v, &eng);
        let n = s.red.ac.patterns_len();
        (s, decode_ms, t.elapsed().as_secs_f64() * 1000.0, n)
    })
    .await
    .unwrap();
    let version = snap.dict_version;
    let snap = if let Some(cell) = swap_into {
        *cell.write().unwrap() = Arc::new(snap);
        None
    } else {
        Some(snap)
    };
    let ack = format!(
        r#"{{"version":{version},"full":{full},"bytes":{bytes},"recv_unix_us":{recv_us},"swap_unix_us":{},"decode_ms":{decode_ms:.2},"build_ms":{build_ms:.2},"patterns":{n_pats}}}"#,
        now_us()
    );
    let _ = wtx.send((T_DICT_ACK, ack.into_bytes())).await;
    snap
}

#[tokio::main]
async fn main() {
    let listen = arg("-listen", "127.0.0.1:18102");
    let upstream = arg("-upstream", "http://127.0.0.1:18100");
    let engine = arg("-engine", "ac-auto");
    let cp = arg("-cp", "");
    let audit = match arg("-audit", if cp.is_empty() { "off" } else { "async" }).as_str() {
        "async" => Audit::Async,
        "sync" => Audit::Sync,
        _ => Audit::Off,
    };
    let grant_sync = arg("-grant", "none") == "sync";
    let t0 = Instant::now();
    let (audit_tx, audit_rx) = if audit == Audit::Async {
        let (tx, rx) = mpsc::channel(65536);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let snap_cell = if cp.is_empty() {
        let (secrets, key) = load_secrets(&arg("-secrets", ""));
        let red = Redactor::new(&secrets, &key, &engine);
        let table = Arc::new(Table::new(&secrets, &key));
        Arc::new(RwLock::new(Arc::new(Snap { red, table, dict_version: 0, allowed_provider: "anthropic".into() })))
    } else {
        let (cell, _h) = control_plane(cp.clone(), engine.clone(), audit_rx).await;
        cell
    };
    eprintln!("automaton {engine} ready in {:?} (cp={cp:?})", t0.elapsed());
    let mut conn = HttpConnector::new();
    conn.set_nodelay(true);
    let client = Client::builder(TokioExecutor::new()).pool_max_idle_per_host(4096).build(conn);
    let st = Arc::new(State {
        snap: snap_cell,
        client,
        upstream: upstream.clone(),
        audit,
        grant_sync,
        audit_tx,
        cp_path: cp.clone(),
        pool: Mutex::new(Vec::new()),
        reqs: AtomicU64::new(0),
        drops: AtomicU64::new(0),
    });
    let l = TcpListener::bind(&listen).await.unwrap();
    eprintln!("rust proxy on {listen} -> {upstream}, workers={}", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    loop {
        let (sock, _) = match l.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        sock.set_nodelay(true).ok();
        let st = st.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(st.clone(), req));
            let _ = http1::Builder::new().serve_connection(TokioIo::new(sock), svc).await;
        });
    }
}
