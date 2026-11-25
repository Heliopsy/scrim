//! The committed seed inputs of the `sigv4` fuzz target (`fuzz/seeds/sigv4`), built from AWS's
//! SigV4 test suite in `testdata/aws-sigv4-test-suite`: each signed request split into the
//! NUL-separated fields `sigv4_testing::fuzz_one` reads (Authorization, X-Amz-Date, the presigned
//! query, the body, the path, one more header value), plus aws-chunked bodies for the chunk
//! re-signer.
//!
//! The test fails when the committed seeds differ from what the suite gives; rewrite them with
//! `SCRIM_FUZZ_SEEDS=update cargo test -p scrim-toolproxy --test fuzz_seeds`.
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A request of the suite: its request line's path and query, headers and body.
struct Request {
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

fn parse(file: &Path) -> Request {
    let text = fs::read_to_string(file).unwrap().replace("\r\n", "\n");
    let (head, body) = text.split_once("\n\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let target = lines.next().unwrap().split(' ').nth(1).unwrap();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
        .collect();
    Request {
        path: path.trim_start_matches('/').to_owned(),
        query: query.to_owned(),
        headers,
        body: body.to_owned(),
    }
}

impl Request {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    }
}

fn input(fields: [&str; 6]) -> Vec<u8> {
    fields.join("\0").into_bytes()
}

fn seeds() -> BTreeMap<String, Vec<u8>> {
    let suite = manifest_dir().join("testdata/aws-sigv4-test-suite");
    let mut cases: Vec<PathBuf> = fs::read_dir(&suite)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("header-signed-request.txt").is_file())
        .collect();
    cases.sort();
    let mut out = BTreeMap::new();
    for case in cases {
        let name = case.file_name().unwrap().to_str().unwrap().to_owned();
        let h = parse(&case.join("header-signed-request.txt"));
        let q = parse(&case.join("query-signed-request.txt"));
        // The last field: the session token where the case has one, else the first header that
        // is not one of the others.
        let extra = h
            .headers
            .iter()
            .find(|(k, _)| k == "x-amz-security-token")
            .or_else(|| {
                h.headers.iter().find(|(k, _)| {
                    !["authorization", "x-amz-date", "host", "content-length"].contains(&k.as_str())
                })
            })
            .map_or("", |(_, v)| v.as_str());
        out.insert(
            name,
            input([
                h.header("authorization"),
                h.header("x-amz-date"),
                &q.query,
                &h.body,
                &h.path,
                extra,
            ]),
        );
    }
    // aws-chunked bodies (STREAMING-AWS4-HMAC-SHA256-PAYLOAD), without and with a trailer.
    let sig = "0".repeat(64);
    let chunked = format!(
        "5;chunk-signature={sig}\r\nhello\r\n6;chunk-signature={sig}\r\n world\r\n0;chunk-signature={sig}\r\n\r\n"
    );
    let trailer = format!(
        "5;chunk-signature={sig}\r\nhello\r\n0;chunk-signature={sig}\r\nx-amz-checksum-crc32:NhCmhg==\r\nx-amz-trailer-signature:{sig}\r\n\r\n"
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={sig}"
    );
    for (name, body) in [("chunked", &chunked), ("chunked-trailer", &trailer)] {
        out.insert(
            name.to_owned(),
            input([
                &auth,
                "20150830T123600Z",
                "",
                body,
                "bucket/key",
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            ]),
        );
    }
    out
}

#[test]
fn fuzz_seeds_match_the_sigv4_suite() {
    let want = seeds();
    let dir = manifest_dir().join("fuzz/seeds/sigv4");
    if std::env::var("SCRIM_FUZZ_SEEDS").as_deref() == Ok("update") {
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in &want {
            fs::write(dir.join(name), bytes).unwrap();
        }
    }
    let mut have: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    have.sort();
    let mut problems = Vec::new();
    for name in &have {
        match want.get(name) {
            None => problems.push(format!("{name}: not built from the suite")),
            Some(b) if *b != fs::read(dir.join(name)).unwrap() => {
                problems.push(format!("{name}: differs from the suite"));
            }
            Some(_) => {}
        }
    }
    for (name, b) in &want {
        if !have.contains(name) {
            problems.push(format!("{name}: missing"));
        }
        assert!(b.len() <= 4096, "{name} is {} bytes, over 4096", b.len());
    }
    assert!(
        problems.is_empty(),
        "fuzz/seeds/sigv4 is out of date ({}); rewrite it with \
         SCRIM_FUZZ_SEEDS=update cargo test -p scrim-toolproxy --test fuzz_seeds",
        problems.join("; ")
    );
}
