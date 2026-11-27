// SPDX-License-Identifier: AGPL-3.0-only

//! Attachments referenced by URL or file ID (`redaction.remote-attachments`): fetched, scanned
//! and inlined under `inline`, refused under `refuse`, forwarded under `pass`; fetches never
//! reach a non-public address unless allowed; file IDs pass only after a scanned upload.

#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unreachable_pub,
    dead_code,
    reason = "test code"
)]

mod common;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use common::*;
use scrim_llm::testing::{FakeUpstream, Fixture, Scripted};
use scrim_llm::{AuditEvent, Network, RemoteMode, RemotePolicy};

const H: &[(&str, &str)] = &[("content-type", "application/json")];

/// A 1x1 greyscale PNG with a tEXt chunk holding `text`.
fn png_with_text(text: &[u8]) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, typ: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(typ);
        out.extend_from_slice(data);
        let mut h = crc32fast::Hasher::new();
        h.update(typ);
        h.update(data);
        out.extend_from_slice(&h.finalize().to_be_bytes());
    }
    let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut p, b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]);
    let mut t = b"Comment\0".to_vec();
    t.extend_from_slice(text);
    chunk(&mut p, b"tEXt", &t);
    chunk(
        &mut p,
        b"IDAT",
        &[0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01],
    );
    chunk(&mut p, b"IEND", &[]);
    p
}

/// A one-page PDF whose content stream (Flate-compressed) shows `text`.
fn pdf_with_text(text: &str) -> Vec<u8> {
    use std::io::Write as _;
    let content = format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET");
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(content.as_bytes()).unwrap();
    let stream = z.finish().unwrap();
    let mut p = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n".to_vec();
    p.extend_from_slice(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n");
    p.extend_from_slice(b"3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj\n");
    p.extend_from_slice(
        format!(
            "4 0 obj << /Length {} /Filter /FlateDecode >>\nstream\n",
            stream.len()
        )
        .as_bytes(),
    );
    p.extend_from_slice(&stream);
    p.extend_from_slice(b"\nendstream\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF\n");
    p
}

/// A server for attachments: `path -> (content type, bytes)`, 404 otherwise.
async fn files(entries: Vec<(&'static str, &'static str, Vec<u8>)>) -> FakeUpstream {
    let entries = Arc::new(entries);
    FakeUpstream::start_with(move |r| {
        let path = r.uri.split('?').next().unwrap_or_default().to_owned();
        match entries.iter().find(|(p, _, _)| *p == path) {
            Some((_, ct, b)) => Scripted {
                status: 200,
                headers: vec![("content-type".into(), (*ct).into())],
                chunks: vec![Bytes::from(b.clone())],
                delay: std::time::Duration::ZERO,
            },
            None => Scripted::json(404, "{}"),
        }
    })
    .await
}

fn loopback_allowed(fx: &mut Fixture) {
    fx.remote = RemotePolicy {
        mode: RemoteMode::Inline,
        allowed_networks: vec!["127.0.0.0/8".parse::<Network>().unwrap()],
    };
}

fn anthropic_url(url: &str, kind: &str) -> String {
    format!(
        r#"{{"model":"m","max_tokens":10,"messages":[{{"role":"user","content":[{{"type":"{kind}","source":{{"type":"url","url":"{url}"}}}},{{"type":"text","text":"describe"}}]}}]}}"#
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn inline_fetches_scans_and_inlines_an_anthropic_image() {
    let mut fx = fixture();
    loopback_allowed(&mut fx);
    let png = png_with_text(b"nothing to see");
    let srv = files(vec![("/a.png", "application/octet-stream", png.clone())]).await;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let body = anthropic_url(&format!("{}/a.png", srv.url()), "image");
    let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let got = h.upstream.received();
    assert_eq!(got.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&got[0].body).unwrap();
    let src = &v["messages"][0]["content"][0]["source"];
    assert_eq!(src["type"], "base64");
    assert_eq!(
        src["media_type"], "image/png",
        "type from magic bytes, not the header"
    );
    assert_eq!(B64.decode(src["data"].as_str().unwrap()).unwrap(), png);
    assert!(src.get("url").is_none());
    let fetched = srv.received();
    assert_eq!(fetched.len(), 1);
    assert!(fetched[0].headers.get("x-api-key").is_none());
    assert_eq!(fetched[0].headers["user-agent"], "scrim");
}

#[tokio::test(flavor = "multi_thread")]
async fn inline_refuses_a_fetched_image_or_pdf_with_a_secret() {
    let mut fx = fixture();
    loopback_allowed(&mut fx);
    let secret = fx.value("s0");
    let srv = files(vec![
        ("/leak.png", "image/png", png_with_text(secret.as_bytes())),
        ("/leak.pdf", "application/pdf", pdf_with_text(&secret)),
    ])
    .await;
    for (path, kind) in [("/leak.png", "image"), ("/leak.pdf", "document")] {
        let h = start(
            Some(&fx),
            FakeUpstream::start(Scripted::json(200, "{}")).await,
            |_| {},
        )
        .await;
        let body = anthropic_url(&format!("{}{path}", srv.url()), kind);
        let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
        assert_eq!(r.status, 422, "{path}: {}", r.text());
        assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "secret_in_binary");
        assert!(
            h.upstream.received().is_empty(),
            "{path}: nothing reaches the provider"
        );
        assert!(fx.leaks(&r.body).is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inline_redacts_a_fetched_text_document() {
    let mut fx = fixture();
    loopback_allowed(&mut fx);
    let text = format!("DB_PASSWORD={}\n", fx.value("s0"));
    let srv = files(vec![("/env.txt", "text/plain", text.into_bytes())]).await;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let body = anthropic_url(&format!("{}/env.txt", srv.url()), "document");
    let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let sent = &h.upstream.received()[0].body;
    assert!(fx.leaks(sent).is_empty());
    let v: serde_json::Value = serde_json::from_slice(sent).unwrap();
    let src = &v["messages"][0]["content"][0]["source"];
    assert_eq!(src["type"], "text");
    assert!(
        src["data"]
            .as_str()
            .unwrap()
            .contains(&fx.placeholder("s0"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_public_addresses_are_never_fetched_by_default() {
    let fx = fixture();
    let srv = files(vec![("/a.png", "image/png", png_with_text(b"x"))]).await;
    for url in [
        format!("{}/a.png", srv.url()),
        format!("http://localhost:{}/a.png", srv.addr.port()),
        "http://10.0.0.1/a.png".into(),
        "http://169.254.169.254/latest/meta-data/".into(),
        "http://[::1]/a.png".into(),
        "http://[fd00:ec2::254]/".into(),
    ] {
        let h = start(
            Some(&fx),
            FakeUpstream::start(Scripted::json(200, "{}")).await,
            |_| {},
        )
        .await;
        let r = send(
            &h,
            "/anthropic/v1/messages",
            H,
            anthropic_url(&url, "image"),
            false,
        )
        .await;
        assert_eq!(r.status, 422, "{url}: {}", r.text());
        assert_eq!(
            r.headers[scrim_llm::ERROR_HEADER],
            "remote_attachment",
            "{url}"
        );
        assert!(!r.text().contains(&url), "the error does not echo the URL");
        assert!(h.upstream.received().is_empty());
    }
    assert!(
        srv.received().is_empty(),
        "the loopback server was never contacted"
    );
}

/// A server on 127.0.0.2 that redirects every request to `to`.
#[cfg(target_os = "linux")]
async fn redirector(to: String) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let to = to.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nlocation: {to}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_to_a_refused_address_is_not_followed() {
    let mut fx = fixture();
    fx.remote.allowed_networks = vec!["127.0.0.2/32".parse().unwrap()];
    let target = files(vec![("/secret", "image/png", png_with_text(b"x"))]).await;
    let r_addr = redirector(format!("{}/secret", target.url())).await;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let body = anthropic_url(&format!("http://{r_addr}/a.png"), "image");
    let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
    assert_eq!(r.status, 422, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "remote_attachment");
    assert!(
        target.received().is_empty(),
        "127.0.0.1 was never contacted"
    );
    assert!(h.upstream.received().is_empty());

    // Allowed, the same redirect is followed and the target inlined.
    fx.remote
        .allowed_networks
        .push("127.0.0.1/32".parse().unwrap());
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let body = anthropic_url(&format!("http://{r_addr}/a.png"), "image");
    let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(target.received().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_url_with_a_secret_value_is_not_fetched() {
    let mut fx = fixture();
    loopback_allowed(&mut fx);
    let srv = files(vec![]).await;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let url = format!("{}/a.png?token={}", srv.url(), fx.value("s0"));
    let r = send(
        &h,
        "/anthropic/v1/messages",
        H,
        anthropic_url(&url, "image"),
        false,
    )
    .await;
    assert_eq!(r.status, 422, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "remote_attachment");
    assert!(srv.received().is_empty());
    assert!(fx.leaks(&r.body).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_failures_refuse() {
    let mut fx = fixture();
    loopback_allowed(&mut fx);
    let srv = files(vec![]).await;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let body = anthropic_url(&format!("{}/missing.png", srv.url()), "image");
    let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
    assert_eq!(r.status, 502, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "attachment_unavailable");
    assert!(h.upstream.received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn refuse_and_pass_modes() {
    let mut fx = fixture();
    fx.remote.mode = RemoteMode::Refuse;
    let body = anthropic_url("https://example.com/a.png", "image");
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let r = send(&h, "/anthropic/v1/messages", H, body.clone(), false).await;
    assert_eq!(r.status, 422, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "remote_attachment");
    assert!(h.upstream.received().is_empty());

    fx.remote.mode = RemoteMode::Pass;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let sent = String::from_utf8(h.upstream.received()[0].body.to_vec()).unwrap();
    assert!(
        sent.contains("https://example.com/a.png"),
        "forwarded as is"
    );
    assert!(h.audit.events().iter().any(|e| matches!(
        e,
        AuditEvent::Forwarded { unscanned, .. } if unscanned.iter().any(|u| u == "remote:url")
    )));
}

#[tokio::test(flavor = "multi_thread")]
async fn openai_chat_and_responses_urls_are_inlined() {
    let mut fx = fixture();
    loopback_allowed(&mut fx);
    let png = png_with_text(b"ok");
    let pdf = pdf_with_text("quarterly figures");
    let srv = files(vec![
        ("/i.png", "image/png", png.clone()),
        ("/docs/report.pdf", "application/pdf", pdf.clone()),
    ])
    .await;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let chat = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":[{{"type":"image_url","image_url":{{"url":"{}/i.png","detail":"low"}}}}]}}]}}"#,
        srv.url()
    );
    let r = send(&h, "/openai/v1/chat/completions", H, chat, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let responses = format!(
        r#"{{"model":"m","input":[{{"role":"user","content":[{{"type":"input_image","image_url":"{u}/i.png"}},{{"type":"input_file","file_url":"{u}/docs/report.pdf"}}]}}]}}"#,
        u = srv.url()
    );
    let r = send(&h, "/openai/v1/responses", H, responses, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let got = h.upstream.received();
    let want_png = format!("data:image/png;base64,{}", B64.encode(&png));
    let v: serde_json::Value = serde_json::from_slice(&got[0].body).unwrap();
    let iu = &v["messages"][0]["content"][0]["image_url"];
    assert_eq!(iu["url"], want_png.as_str());
    assert_eq!(iu["detail"], "low");
    let v: serde_json::Value = serde_json::from_slice(&got[1].body).unwrap();
    let parts = &v["input"][0]["content"];
    assert_eq!(parts[0]["image_url"], want_png.as_str());
    assert_eq!(parts[1]["type"], "input_file");
    assert!(parts[1].get("file_url").is_none());
    assert_eq!(parts[1]["filename"], "report.pdf");
    assert_eq!(
        parts[1]["file_data"],
        format!("data:application/pdf;base64,{}", B64.encode(&pdf)).as_str()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gemini_file_data_urls_are_inlined_and_storage_refused() {
    let mut fx = fixture();
    loopback_allowed(&mut fx);
    let png = png_with_text(b"ok");
    let srv = files(vec![("/i.png", "image/png", png.clone())]).await;
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |_| {},
    )
    .await;
    let body = format!(
        r#"{{"contents":[{{"role":"user","parts":[{{"text":"what"}},{{"fileData":{{"mimeType":"image/png","fileUri":"{}/i.png"}}}}]}}]}}"#,
        srv.url()
    );
    let r = send(
        &h,
        "/gemini/v1beta/models/g:generateContent",
        H,
        body,
        false,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v: serde_json::Value = serde_json::from_slice(&h.upstream.received()[0].body).unwrap();
    let part = &v["contents"][0]["parts"][1];
    assert!(part.get("fileData").is_none());
    assert_eq!(part["inlineData"]["mimeType"], "image/png");
    assert_eq!(part["inlineData"]["data"], B64.encode(&png).as_str());

    for uri in [
        "gs://bucket/a.png",
        "https://www.youtube.com/watch?v=x",
        "https://generativelanguage.googleapis.com/v1beta/files/abc",
    ] {
        let body = format!(
            r#"{{"contents":[{{"parts":[{{"fileData":{{"mimeType":"image/png","fileUri":"{uri}"}}}}]}}]}}"#
        );
        let r = send(
            &h,
            "/gemini/v1beta/models/g:generateContent",
            H,
            body,
            false,
        )
        .await;
        assert_eq!(r.status, 422, "{uri}: {}", r.text());
        assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "remote_attachment");
    }
}

fn multipart(boundary: &str, mt: &str, file: &[u8]) -> Vec<u8> {
    let mut b = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\nContent-Type: {mt}\r\n\r\n"
    )
    .into_bytes();
    b.extend_from_slice(file);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    b
}

#[tokio::test(flavor = "multi_thread")]
async fn file_ids_pass_only_after_a_scanned_upload_on_the_same_route() {
    let fx = fixture();
    let up = FakeUpstream::start_with(|r| {
        if r.uri.ends_with("/files") {
            Scripted::json(200, r#"{"id":"file-scanned1","object":"file"}"#)
        } else {
            Scripted::json(200, "{}")
        }
    })
    .await;
    let h = start(Some(&fx), up, |_| {}).await;
    let refer = |id: &str| {
        format!(
            r#"{{"model":"m","input":[{{"role":"user","content":[{{"type":"input_file","file_id":"{id}"}}]}}]}}"#
        )
    };
    let r = send(&h, "/openai/v1/responses", H, refer("file-scanned1"), false).await;
    assert_eq!(r.status, 422, "unknown before the upload: {}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "remote_attachment");

    let ct = [("content-type", "multipart/form-data; boundary=BnD")];
    let up = multipart("BnD", "application/pdf", &pdf_with_text("clean"));
    let r = send(&h, "/openai/v1/files", &ct, up, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json()["id"],
        "file-scanned1",
        "the answer passes unchanged"
    );

    let r = send(&h, "/openai/v1/responses", H, refer("file-scanned1"), false).await;
    assert_eq!(r.status, 200, "known after the upload: {}", r.text());
    let r = send(&h, "/openai/v1/responses", H, refer("file-other"), false).await;
    assert_eq!(r.status, 422);
    let anthropic = r#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file-scanned1"}}]}]}"#;
    let r = send(&h, "/anthropic/v1/messages", H, anthropic, false).await;
    assert_eq!(r.status, 422, "another route does not know it");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upload_with_a_secret_is_refused_and_its_id_never_known() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"id":"file_leaky"}"#)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let ct = [("content-type", "multipart/form-data; boundary=BnD")];
    let body = multipart("BnD", "application/pdf", &pdf_with_text(&fx.value("s0")));
    let r = send(&h, "/anthropic/v1/files", &ct, body, false).await;
    assert_eq!(r.status, 422, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "secret_in_binary");
    assert!(h.upstream.received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn fetches_go_through_the_upstream_proxy() {
    use scrim_upstream_proxy::testing::{Options, TestProxy};
    let mut fx = fixture();
    fx.remote.mode = RemoteMode::Inline;
    let png = png_with_text(b"via proxy");
    let srv = files(vec![("/p.png", "image/png", png.clone())]).await;
    let proxy = TestProxy::start(Options {
        redirect: Some(srv.addr),
        ..Options::default()
    })
    .await;
    let handle = scrim_upstream_proxy::ProxyHandle::new();
    let h = start(
        Some(&fx),
        FakeUpstream::start(Scripted::json(200, "{}")).await,
        |c| {
            c.upstream_proxy = handle.clone();
        },
    )
    .await;
    // Set after the start: the provider (on loopback) stays direct, the attachment host does not.
    // The test proxy accepts any credentials; generated ones keep the setup realistic.
    let password = scrim_llm::testing::random_value("proxy-");
    handle.set(Some(
        scrim_upstream_proxy::UpstreamProxy::new::<&str>(
            &format!("http://{}", proxy.addr()),
            &["127.0.0.1"],
            "scrim",
            password.as_bytes(),
        )
        .unwrap(),
    ));
    // The name does not resolve here; the proxy resolves it (here: sends it to `srv`).
    let body = anthropic_url("http://attachments.invalid/p.png", "image");
    let r = send(&h, "/anthropic/v1/messages", H, body, false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(proxy.seen()[0].target, "attachments.invalid:80");
    assert!(proxy.seen()[0].sent_authorization);
    let v: serde_json::Value = serde_json::from_slice(&h.upstream.received()[0].body).unwrap();
    assert_eq!(
        v["messages"][0]["content"][0]["source"]["data"],
        B64.encode(&png).as_str()
    );
}
