//! AWS `SigV4` re-signing through a real proxy listener (credential-injection spec, "Re-signing
//! for signed request protocols"). The fake upstream checks every signature with the real secret.
#![allow(
    clippy::pedantic,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

mod common;

use bytes::Bytes;
use common::*;
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use scrim_toolproxy::sigv4_testing as sig;
use scrim_toolproxy::*;

const HOSTS: &[&str] = &[
    "s3.us-east-1.amazonaws.test",
    "sts.amazonaws.test",
    "evil.test",
];
// Generated-looking test values, never real keys.
const REAL_AKID: &str = "AKIAREALTEST7Q2W4E6R";
const REAL_TOKEN: &str = "IQoJb3JpZ2luX2VjEXAMPLEreal0a1b2c3d4e5f6a7b8c9d0e1f";
const PH_AKID: &str = "AKIAPLACEHOLDER00001";
const PH_TOKEN: &str = "SCRIM_AWS_SESSION_TOKEN_PLACEHOLDER";
const DATE: &str = "20260101T000000Z";

/// A value made at run time, different in every test process.
fn runtime_value(prefix: &str) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    );
    format!("{prefix}{:016x}{:016x}", h.finish(), std::process::id())
}

/// The real secret access key, generated at run time.
fn real_secret() -> &'static str {
    static V: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| runtime_value("rEaLsEcReT/"));
    &V
}

/// The secret placeholder the agent signs with, generated at run time.
fn ph_secret() -> &'static str {
    static V: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| runtime_value("SCRIM_AWS_SECRET_PLACEHOLDER_"));
    &V
}

fn config(port: u16) -> String {
    let ph = ph_secret();
    let hosts = format!("['s3.us-east-1.amazonaws.test:{port}', 'sts.amazonaws.test:{port}']");
    format!(
        r"
credentials:
  - name: aws-akid
    reference: env://AKID
    placeholders: [{PH_AKID}]
    binding: {{ hosts: {hosts} }}
    inject: [header:authorization, query]
  - name: aws-secret
    reference: env://SECRET
    placeholders: [{ph}]
    binding: {{ hosts: {hosts} }}
    inject: [header:authorization, query]
    aws_sigv4: {{ access_key_id: env://AKID, regions: [us-east-1], services: [s3, sts] }}
  - name: aws-token
    reference: env://TOKEN
    placeholders: [{PH_TOKEN}]
    binding: {{ hosts: {hosts} }}
    inject: [header:x-amz-security-token, query]
"
    )
}

/// Answers 200 when the request carries a signature made with the real secret, 403 otherwise.
fn aws_handler() -> Handler {
    std::sync::Arc::new(|s: &Seen| {
        let uri: Uri = s.uri.parse().unwrap();
        let method: Method = s.method.parse().unwrap();
        let chunked = s
            .headers
            .get("x-amz-content-sha256")
            .is_some_and(|v| v.as_bytes().starts_with(b"STREAMING-AWS4"));
        let ok = sig::verify(
            &method,
            &uri,
            &s.headers,
            Some(&s.body),
            real_secret().as_bytes(),
        );
        let chunks_ok = !chunked || {
            let seed = s.headers["authorization"]
                .to_str()
                .unwrap()
                .rsplit("Signature=")
                .next()
                .unwrap()
                .to_owned();
            sig::rechain(
                &s.headers,
                &uri,
                real_secret().as_bytes(),
                real_secret().as_bytes(),
                &seed,
                &s.body,
            )
            .is_ok()
        };
        let status = if ok.as_deref() == Some(REAL_AKID) && chunks_ok {
            200
        } else {
            403
        };
        http::Response::builder()
            .status(status)
            .header("content-type", "application/xml")
            .body(ResponseBody::Full(Bytes::from(format!(
                "<Result><AccessKeyId>{}</AccessKeyId></Result>",
                ok.unwrap_or_default()
            ))))
            .unwrap()
    })
}

struct World {
    proxy: Proxy,
    up: Upstream,
    client: Client,
}

async fn world(settings: ToolProxySettings) -> World {
    let ca = UpstreamCa::new();
    let up = tls_upstream(&ca, HOSTS, aws_handler()).await;
    let mut opts = ProxyOptions {
        settings,
        ..Default::default()
    };
    opts.roots.push(ca.der());
    for h in HOSTS {
        opts.hosts.push(((*h).to_owned(), up.addr));
    }
    let proxy = start_proxy(opts).await;
    proxy
        .proxy
        .apply(snapshot(
            &config(up.port()),
            &[
                ("env://AKID", REAL_AKID),
                ("env://SECRET", real_secret()),
                ("env://TOKEN", REAL_TOKEN),
            ],
        ))
        .unwrap();
    let client = Client::new(&proxy);
    World { proxy, up, client }
}

impl World {
    /// Signs like an AWS client with `secret` and sends through the proxy.
    async fn signed(
        &self,
        host: &str,
        method: Method,
        path: &str,
        region: &str,
        service: &str,
        secret: &str,
        payload: Option<&str>,
        body: Vec<u8>,
    ) -> Got {
        let port = self.up.port();
        let uri: Uri = path.parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("host", format!("{host}:{port}").parse().unwrap());
        h.insert("x-amz-security-token", PH_TOKEN.parse().unwrap());
        sig::sign(
            &method,
            &uri,
            &mut h,
            PH_AKID,
            secret.as_bytes(),
            DATE,
            region,
            service,
            payload,
            &body,
        );
        let mut b = req(method.as_str(), host, port, path);
        for (k, v) in &h {
            if k != "host" {
                b = b.header(k, v);
            }
        }
        self.client
            .send(host, port, b.body(common::body(body)).unwrap())
            .await
            .unwrap()
    }

    fn texts(&self, got: &Got) -> Vec<String> {
        let mut t = audit_texts(&self.proxy);
        t.push(got.text());
        t.push(format!("{:?}", got.headers));
        t
    }
}

fn no_aws_values(texts: &[String]) {
    for t in texts {
        for v in [REAL_AKID, real_secret(), REAL_TOKEN] {
            assert!(!t.contains(v), "a real AWS value leaked: {t}");
        }
    }
}

#[tokio::test]
async fn header_signed_request_is_resigned_with_the_real_keys() {
    let w = world(ToolProxySettings::default()).await;
    let got = w
        .signed(
            "sts.amazonaws.test",
            Method::POST,
            "/",
            "us-east-1",
            "sts",
            ph_secret(),
            None,
            b"Action=GetCallerIdentity&Version=2011-06-15".to_vec(),
        )
        .await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let seen = w.up.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers["x-amz-security-token"], REAL_TOKEN);
    assert!(
        seen[0].headers["authorization"]
            .to_str()
            .unwrap()
            .contains(&format!("Credential={REAL_AKID}/20260101/us-east-1/sts/"))
    );
    // The echoed access key id comes back as the placeholder the agent used.
    assert!(got.text().contains(PH_AKID), "{}", got.text());
    no_aws_values(&w.texts(&got));
}

#[tokio::test]
async fn s3_put_with_a_body_hash_and_unsigned_payload() {
    let w = world(ToolProxySettings::default()).await;
    let body = b"object bytes".to_vec();
    let hash = sig_hash(&body);
    let got = w
        .signed(
            "s3.us-east-1.amazonaws.test",
            Method::PUT,
            "/bucket/a%20key.txt",
            "us-east-1",
            "s3",
            ph_secret(),
            Some(&hash),
            body,
        )
        .await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let got = w
        .signed(
            "s3.us-east-1.amazonaws.test",
            Method::GET,
            "/bucket?list-type=2&prefix=a%2Fb",
            "us-east-1",
            "s3",
            ph_secret(),
            Some("UNSIGNED-PAYLOAD"),
            Vec::new(),
        )
        .await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
}

fn sig_hash(b: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

#[tokio::test]
async fn unbound_region_is_refused() {
    let w = world(ToolProxySettings::default()).await;
    let got = w
        .signed(
            "sts.amazonaws.test",
            Method::POST,
            "/",
            "eu-west-1",
            "sts",
            ph_secret(),
            None,
            b"Action=GetCallerIdentity".to_vec(),
        )
        .await;
    assert_eq!(got.status, StatusCode::FORBIDDEN);
    assert_eq!(got.error_code().as_deref(), Some("unbound_destination"));
    assert!(got.text().contains("eu-west-1"), "{}", got.text());
    assert!(w.up.seen().is_empty());
    let got = w
        .signed(
            "sts.amazonaws.test",
            Method::POST,
            "/",
            "us-east-1",
            "iam",
            ph_secret(),
            None,
            Vec::new(),
        )
        .await;
    assert_eq!(got.error_code().as_deref(), Some("unbound_destination"));
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn unbound_host_is_refused() {
    let w = world(ToolProxySettings::default()).await;
    let got = w
        .signed(
            "evil.test",
            Method::GET,
            "/",
            "us-east-1",
            "s3",
            ph_secret(),
            Some("UNSIGNED-PAYLOAD"),
            Vec::new(),
        )
        .await;
    assert_eq!(got.status, StatusCode::FORBIDDEN);
    assert_eq!(got.error_code().as_deref(), Some("unbound_destination"));
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn signature_not_made_with_the_placeholder_is_refused() {
    let w = world(ToolProxySettings::default()).await;
    let got = w
        .signed(
            "sts.amazonaws.test",
            Method::POST,
            "/",
            "us-east-1",
            "sts",
            "some-other-secret",
            None,
            Vec::new(),
        )
        .await;
    assert_eq!(got.status, StatusCode::FORBIDDEN);
    assert_eq!(got.error_code().as_deref(), Some("signature_invalid"));
    assert!(w.up.seen().is_empty());
    no_aws_values(&w.texts(&got));
}

#[tokio::test]
async fn presigned_url_is_resigned() {
    let w = world(ToolProxySettings::default()).await;
    let port = w.up.port();
    let host = "s3.us-east-1.amazonaws.test";
    // Build a presigned URL the way a client does: sign the canonical query, then append the
    // signature. The test-only signer signs headers, so presign by hand here.
    let cred = format!("{PH_AKID}%2F20260101%2Fus-east-1%2Fs3%2Faws4_request");
    let q = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={cred}&X-Amz-Date={DATE}&X-Amz-Expires=300&X-Amz-Security-Token={PH_TOKEN}&X-Amz-SignedHeaders=host"
    );
    let path = format!("/bucket/key?{q}");
    let canonical = format!("GET\n/bucket/key\n{q}\nhost:{host}:{port}\n\nhost\nUNSIGNED-PAYLOAD");
    let signature = presign(ph_secret(), &canonical);
    let full = format!("{path}&X-Amz-Signature={signature}");
    let got = w
        .client
        .send(
            host,
            port,
            req("GET", host, port, &full)
                .body(common::body(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let seen = w.up.seen();
    assert!(seen[0].uri.contains(REAL_AKID) && seen[0].uri.contains(REAL_TOKEN));
    assert_eq!(seen[0].uri.matches("X-Amz-Signature=").count(), 1);
}

fn presign(secret: &str, canonical: &str) -> String {
    use hmac::{KeyInit, Mac};
    let h = |k: &[u8], d: &[u8]| {
        let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(k).unwrap();
        m.update(d);
        m.finalize().into_bytes().to_vec()
    };
    let k = h(format!("AWS4{secret}").as_bytes(), b"20260101");
    let k = h(&k, b"us-east-1");
    let k = h(&k, b"s3");
    let k = h(&k, b"aws4_request");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{DATE}\n20260101/us-east-1/s3/aws4_request\n{}",
        sig_hash(canonical.as_bytes())
    );
    h(&k, sts.as_bytes())
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

async fn chunked_upload(w: &World, trailer: bool, size: usize) -> Got {
    let port = w.up.port();
    let host = "s3.us-east-1.amazonaws.test";
    let path = "/bucket/big.bin";
    let uri: Uri = path.parse().unwrap();
    let kw = if trailer {
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    } else {
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    };
    let data = vec![b'z'; size];
    let mut h = HeaderMap::new();
    h.insert("host", format!("{host}:{port}").parse().unwrap());
    h.insert("content-encoding", "aws-chunked".parse().unwrap());
    h.insert(
        "x-amz-decoded-content-length",
        data.len().to_string().parse().unwrap(),
    );
    if trailer {
        h.insert("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());
    }
    sig::sign(
        &Method::PUT,
        &uri,
        &mut h,
        PH_AKID,
        ph_secret().as_bytes(),
        DATE,
        "us-east-1",
        "s3",
        Some(kw),
        b"",
    );
    let pieces: Vec<&[u8]> = data.chunks(64 * 1024).collect();
    let trailers: &[(&str, &str)] = if trailer {
        &[("x-amz-checksum-crc32", "AAAAAA==")]
    } else {
        &[]
    };
    let body = sig::sign_chunks(&h, &uri, ph_secret().as_bytes(), &pieces, trailers);
    let mut b = Request::builder()
        .method("PUT")
        .uri(format!("https://{host}:{port}{path}"));
    for (k, v) in &h {
        if k != "host" {
            b = b.header(k, v);
        }
    }
    w.client
        .send(host, port, b.body(common::body(body)).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn chunk_signed_upload_is_rechained_buffered_and_streamed() {
    for (limit, size) in [(32 << 20, 200 * 1024), (64 * 1024, 300 * 1024)] {
        let w = world(ToolProxySettings {
            max_buffered_body: limit,
            ..Default::default()
        })
        .await;
        for trailer in [false, true] {
            let got = chunked_upload(&w, trailer, size).await;
            assert_eq!(
                got.status,
                StatusCode::OK,
                "limit {limit} trailer {trailer}: {}",
                got.text()
            );
        }
    }
}

#[tokio::test]
async fn placeholder_in_a_chunk_signed_body_is_refused() {
    let w = world(ToolProxySettings::default()).await;
    let port = w.up.port();
    let host = "s3.us-east-1.amazonaws.test";
    let uri: Uri = "/bucket/x".parse().unwrap();
    let mut h = HeaderMap::new();
    h.insert("host", format!("{host}:{port}").parse().unwrap());
    h.insert("content-encoding", "aws-chunked".parse().unwrap());
    sig::sign(
        &Method::PUT,
        &uri,
        &mut h,
        PH_AKID,
        ph_secret().as_bytes(),
        DATE,
        "us-east-1",
        "s3",
        Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
        b"",
    );
    let body = sig::sign_chunks(
        &h,
        &uri,
        ph_secret().as_bytes(),
        &[PH_TOKEN.as_bytes()],
        &[],
    );
    let mut b = Request::builder()
        .method("PUT")
        .uri(format!("https://{host}:{port}/bucket/x"));
    for (k, v) in &h {
        if k != "host" {
            b = b.header(k, v);
        }
    }
    let got = w
        .client
        .send(host, port, b.body(common::body(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(
        got.error_code().as_deref(),
        Some("unsupported_encoding"),
        "{}",
        got.text()
    );
    assert!(w.up.seen().is_empty());
}
