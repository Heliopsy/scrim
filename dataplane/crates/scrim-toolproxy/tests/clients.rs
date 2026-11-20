//! Real clients through the proxy: curl, git over HTTPS, Python requests and Node fetch.
//!
//! Each test is skipped (with a note on stderr) when its tool is not installed.
#![allow(
    clippy::pedantic,
    clippy::type_complexity,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    missing_docs,
    unreachable_pub
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use bytes::Bytes;
use common::*;
use http::Response;
use tokio::process::Command;

fn have(tool: &str) -> bool {
    let ok = std::process::Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipping: {tool} not installed");
    }
    ok
}

struct Env {
    proxy: Proxy,
    up: Upstream,
    dir: tempfile::TempDir,
    ca_file: PathBuf,
}

async fn env(handler: Handler, extra_yaml: &str) -> Env {
    let ca = UpstreamCa::new();
    let hosts = ["api.acme.test", "git.acme.test", "evil.test"];
    let up = tls_upstream(&ca, &hosts, handler).await;
    let mut opts = ProxyOptions::default();
    opts.roots.push(ca.der());
    for h in hosts {
        opts.hosts.push((h.to_owned(), up.addr));
    }
    let proxy = start_proxy(opts).await;
    let p = up.port();
    let yaml = format!(
        r"
credentials:
  - name: acme
    reference: env://ACME
    placeholders: [SCRIM_ACME_KEY]
    binding: {{ hosts: ['api.acme.test:{p}'] }}
    inject: [header, body]
  - name: git
    reference: env://GIT
    placeholders: [SCRIM_GIT_TOKEN]
    binding: {{ hosts: ['git.acme.test:{p}'] }}
{extra_yaml}"
    );
    proxy
        .proxy
        .apply(snapshot(
            &yaml,
            &[("env://ACME", ACME_VALUE), ("env://GIT", GIT_VALUE)],
        ))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca_file = dir.path().join("scrim-ca.pem");
    std::fs::write(&ca_file, proxy.proxy.ca().trust_bundle_pem()).unwrap();
    Env {
        proxy,
        up,
        dir,
        ca_file,
    }
}

impl Env {
    fn proxy_url(&self) -> String {
        format!("http://{}", self.proxy.addr)
    }

    /// A command with a clean environment: no inherited proxy settings or user config.
    fn cmd(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }
}

async fn run(mut c: Command) -> (bool, String, String) {
    let out = c.output().await.unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn curl_injects_and_sees_placeholders() {
    if !have("curl") {
        return;
    }
    let e = env(echo_handler(), "").await;
    let url = format!("https://api.acme.test:{}/v1/me", e.up.port());
    let mut c = e.cmd("curl");
    c.args(["-sS", "--proxy", &e.proxy_url(), "--cacert"])
        .arg(&e.ca_file)
        .args([
            "-H",
            "Authorization: Bearer SCRIM_ACME_KEY",
            "-H",
            "Content-Type: application/json",
            "--compressed",
            "-d",
            r#"{"key":"SCRIM_ACME_KEY"}"#,
            &url,
        ]);
    let (ok, out, err) = run(c).await;
    assert!(ok, "curl failed: {err}");
    let seen = e.up.seen();
    assert_eq!(
        seen[0].headers["authorization"],
        format!("Bearer {ACME_VALUE}").as_str()
    );
    assert_eq!(seen[0].body, format!(r#"{{"key":"{ACME_VALUE}"}}"#));
    assert!(out.contains("Bearer SCRIM_ACME_KEY"), "{out}");
    assert_no_values(&[out, err]);

    // Toward an unbound host curl gets the documented error and nothing is sent.
    let mut c = e.cmd("curl");
    c.args(["-sS", "--proxy", &e.proxy_url(), "--cacert"])
        .arg(&e.ca_file)
        .args([
            "-H",
            "Authorization: Bearer SCRIM_ACME_KEY",
            &format!("https://evil.test:{}/", e.up.port()),
        ]);
    let (_, out, _) = run(c).await;
    assert!(out.contains("unbound_destination"), "{out}");
    assert_eq!(e.up.seen().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn curl_http2() {
    if !have("curl") {
        return;
    }
    let e = env(echo_handler(), "").await;
    let mut c = e.cmd("curl");
    c.args([
        "-sS",
        "--http2",
        "-w",
        "\n%{http_version}",
        "--proxy",
        &e.proxy_url(),
        "--cacert",
    ])
    .arg(&e.ca_file)
    .args([
        "-H",
        "x-api-key: SCRIM_ACME_KEY",
        &format!("https://api.acme.test:{}/", e.up.port()),
    ]);
    let (ok, out, err) = run(c).await;
    assert!(ok, "{err}");
    assert!(out.ends_with("\n2"), "{out}");
    assert_eq!(e.up.seen()[0].headers["x-api-key"], ACME_VALUE);
}

/// Runs `git http-backend` as CGI for one request, requiring Basic auth with the real token.
fn git_backend(root: PathBuf) -> Handler {
    Arc::new(move |s: &Seen| {
        use base64::Engine as _;
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{GIT_VALUE}"))
        );
        if s.headers.get("authorization").map(|v| v.as_bytes()) != Some(expected.as_bytes()) {
            return Response::builder()
                .status(401)
                .header("www-authenticate", "Basic realm=\"test\"")
                .body(ResponseBody::Full(Bytes::new()))
                .unwrap();
        }
        let (path, query) = s.uri.split_once('?').unwrap_or((&s.uri, ""));
        let mut cmd = std::process::Command::new("git");
        cmd.arg("http-backend")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("GIT_PROJECT_ROOT", &root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REMOTE_USER", "x-access-token")
            .env("REQUEST_METHOD", &s.method)
            .env("PATH_INFO", path)
            .env("QUERY_STRING", query)
            .env("CONTENT_LENGTH", s.body.len().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        for (h, env) in [
            ("content-type", "CONTENT_TYPE"),
            ("content-encoding", "HTTP_CONTENT_ENCODING"),
            ("git-protocol", "GIT_PROTOCOL"),
        ] {
            if let Some(v) = s.headers.get(h) {
                cmd.env(env, v.to_str().unwrap());
            }
        }
        let mut child = cmd.spawn().unwrap();
        {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(&s.body).unwrap();
        }
        let out = child.wait_with_output().unwrap().stdout;
        let split = out
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| (i, 4))
            .or_else(|| out.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))
            .unwrap();
        let head = String::from_utf8_lossy(&out[..split.0]).to_string();
        let mut b = Response::builder();
        for line in head.lines() {
            let (k, v) = line.split_once(':').unwrap();
            if k.eq_ignore_ascii_case("status") {
                b = b.status(v.trim()[..3].parse::<u16>().unwrap());
            } else {
                b = b.header(k.trim(), v.trim());
            }
        }
        b.body(ResponseBody::Full(Bytes::copy_from_slice(
            &out[split.0 + split.1..],
        )))
        .unwrap()
    })
}

async fn git(dir: &Path, e: &Env, args: &[&str]) -> (bool, String) {
    let mut c = e.cmd("git");
    c.current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .args(["-c", &format!("http.proxy={}", e.proxy_url())])
        .args(["-c", &format!("http.sslCAInfo={}", e.ca_file.display())])
        .args(["-c", "credential.helper=", "-c", "credential.helper=!f() { echo username=x-access-token; echo password=SCRIM_GIT_TOKEN; }; f"])
        .args(["-c", "init.defaultBranch=main"])
        .args(args);
    let (ok, out, err) = run(c).await;
    (ok, format!("{out}{err}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn git_clone_and_push_over_https() {
    if !have("git") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let e = env(git_backend(root.path().to_owned()), "").await;
    let base = e.dir.path();
    assert!(
        git(root.path(), &e, &["init", "-q", "--bare", "repo.git"])
            .await
            .0
    );
    assert!(
        git(
            &root.path().join("repo.git"),
            &e,
            &["config", "http.receivepack", "true"]
        )
        .await
        .0
    );
    let seed = base.join("seed");
    std::fs::create_dir(&seed).unwrap();
    assert!(git(&seed, &e, &["init", "-q"]).await.0);
    std::fs::write(seed.join("README"), "hello\n").unwrap();
    assert!(git(&seed, &e, &["add", "."]).await.0);
    assert!(git(&seed, &e, &["commit", "-qm", "seed"]).await.0);
    let bare = root.path().join("repo.git");
    assert!(
        git(
            &seed,
            &e,
            &["push", "-q", bare.to_str().unwrap(), "HEAD:main"]
        )
        .await
        .0
    );

    let url = format!("https://git.acme.test:{}/repo.git", e.up.port());
    let (ok, out) = git(base, &e, &["clone", "-q", &url, "clone"]).await;
    assert!(ok, "clone failed: {out}");
    assert_eq!(
        std::fs::read_to_string(base.join("clone/README")).unwrap(),
        "hello\n"
    );

    let clone = base.join("clone");
    // Enough content that git compresses the pack and may use chunked transfer.
    std::fs::write(clone.join("data.txt"), "line of data\n".repeat(20_000)).unwrap();
    assert!(git(&clone, &e, &["add", "."]).await.0);
    assert!(git(&clone, &e, &["commit", "-qm", "more"]).await.0);
    let (ok, out) = git(&clone, &e, &["push", "-q", "origin", "HEAD:main"]).await;
    assert!(ok, "push failed: {out}");
    assert_no_values(&[out]);
    let (ok, log) = git(&bare, &e, &["log", "--oneline"]).await;
    assert!(ok && log.contains("more"), "{log}");
    assert!(e.proxy.audit.events().iter().any(|ev| matches!(ev, scrim_toolproxy::AuditEvent::CredentialInjected { credentials, .. } if credentials == &["git"])));
}

#[tokio::test(flavor = "multi_thread")]
async fn python_requests_with_escaped_json() {
    if !have("python3") {
        return;
    }
    let ok = std::process::Command::new("python3")
        .args(["-c", "import requests"])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipping: python requests not installed");
        return;
    }
    let e = env(echo_handler(), "").await;
    let script = format!(
        r#"
import requests
r = requests.post("https://api.acme.test:{port}/py", json={{"k": "{ph}"}},
                  headers={{"Authorization": "Bearer SCRIM_ACME_KEY"}})
print(r.status_code)
print(r.text)
"#,
        port = e.up.port(),
        ph = GENERATED_ACME
    );
    let mut c = e.cmd("python3");
    c.args(["-I", "-c", &script])
        .env("HTTPS_PROXY", e.proxy_url())
        .env("REQUESTS_CA_BUNDLE", &e.ca_file);
    let (ok, out, err) = run(c).await;
    assert!(ok, "{err}");
    assert!(out.starts_with("200"), "{out}");
    let s = &e.up.seen()[0];
    // requests sends json with ensure_ascii, so the placeholder arrived \u-escaped.
    let v: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
    assert_eq!(v["k"], ACME_VALUE);
    assert_no_values(&[out, err]);
}

#[tokio::test(flavor = "multi_thread")]
async fn node_fetch_through_env_proxy() {
    if !have("node") {
        return;
    }
    let e = env(echo_handler(), "").await;
    let script = format!(
        r#"
fetch("https://api.acme.test:{port}/node", {{method: "POST",
  headers: {{authorization: "Bearer SCRIM_ACME_KEY", "content-type": "application/json"}},
  body: JSON.stringify({{k: "{ph}"}})}})
 .then(async r => {{ console.log(r.status); console.log(await r.text()); }})
 .catch(e => {{ console.error(String(e.cause || e)); process.exit(1); }});
"#,
        port = e.up.port(),
        ph = GENERATED_ACME
    );
    // Version managers (asdf, nvm) wrap node in shims that need the user's environment; run
    // the real binary instead.
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    let node = String::from_utf8(node.stdout).unwrap().trim().to_owned();
    let mut c = e.cmd(&node);
    c.args(["-e", &script])
        .env("NODE_USE_ENV_PROXY", "1")
        .env("HTTPS_PROXY", e.proxy_url())
        .env("NODE_EXTRA_CA_CERTS", &e.ca_file);
    let (ok, out, err) = run(c).await;
    assert!(ok, "node failed: {out} {err}");
    assert!(out.starts_with("200"), "{out}");
    let s = &e.up.seen()[0];
    assert_eq!(
        s.headers["authorization"],
        format!("Bearer {ACME_VALUE}").as_str()
    );
    let v: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
    assert_eq!(v["k"], ACME_VALUE);
    assert!(out.contains("SCRIM_ACME_KEY"), "{out}");
    assert_no_values(&[out, err]);
}
