//! The real `aws` CLI through the tool proxy against LocalStack, with placeholder keys only (task
//! 10a.2). Ignored by default; `test/e2e/toolproxy-aws.sh` starts LocalStack in rootless
//! podman and runs it with:
//!
//! - `SCRIM_E2E_AWS_ENDPOINT`: `https://localhost.localstack.cloud:4566`
//! - `SCRIM_E2E_AWS_CLI`: path of the `aws` binary
//!
//! LocalStack checks presigned signatures (`S3_SKIP_SIGNATURE_VALIDATION=0`) and derives the
//! account from a 12-digit access key id, so the test sees both swaps: the access key id (the
//! caller identity and the bucket owner are the real key's account) and the secret (a presigned
//! URL made with the placeholder secret is refused directly and accepted through the proxy).
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

use std::path::Path;
use std::process::Command;

use scrim_toolproxy::*;

// LocalStack takes a 12-digit access key id as the account id; its secret is `test`.
const REAL_AKID: &str = "424242424242";
const REAL_SECRET: &str = "test";

struct Env {
    endpoint: String,
    cli: String,
    host: String,
}

fn env() -> Option<Env> {
    let endpoint = std::env::var("SCRIM_E2E_AWS_ENDPOINT").ok()?;
    let cli = std::env::var("SCRIM_E2E_AWS_CLI").unwrap_or_else(|_| "aws".into());
    let host = endpoint
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_owned();
    Some(Env {
        endpoint,
        cli,
        host,
    })
}

// LocalStack's keys are too short to have a shape (a 12-digit key id, the secret `test`), so the
// agent holds declared placeholders shaped like AWS keys, as a profile would write them.
const PH_AKID: &str = "AKIASCRIMPLACEHOLDR1";
const PH_SECRET: &str = "SCRIMplaceholderSECRET0000000000000000001";

fn placeholders(reference: &str, value: &SecretValue) -> Vec<String> {
    let key = scrim_redact::PlaceholderKey::new(1, &[42u8; 32]).unwrap();
    let slug = scrim_redact::RefSlug::from_alias(reference);
    vec![scrim_redact::placeholder_for(&key, &slug, value.expose())]
}

fn config(host: &str) -> String {
    format!(
        r"
credentials:
  - name: aws-akid
    reference: env://AWS_AKID
    placeholders: [{PH_AKID}]
    binding: {{ hosts: ['{host}'] }}
    inject: [header:authorization, query]
  - name: aws-secret
    reference: env://AWS_SECRET
    placeholders: [{PH_SECRET}]
    binding: {{ hosts: ['{host}'] }}
    inject: [header:authorization, query]
    aws_sigv4: {{ access_key_id: env://AWS_AKID, regions: [us-east-1], services: [s3, sts] }}
"
    )
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn aws(
    e: &Env,
    home: &Path,
    ca: &Path,
    proxy: Option<&str>,
    keys: (&str, &str),
    args: &[&str],
) -> Run {
    let mut c = Command::new(&e.cli);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("AWS_CONFIG_FILE", home.join("config"))
        .env("AWS_SHARED_CREDENTIALS_FILE", home.join("credentials"))
        .env("AWS_ACCESS_KEY_ID", keys.0)
        .env("AWS_SECRET_ACCESS_KEY", keys.1)
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env("AWS_PAGER", "")
        .arg("--endpoint-url")
        .arg(&e.endpoint)
        .args(args);
    if let Some(p) = proxy {
        c.env("HTTPS_PROXY", p).env("AWS_CA_BUNDLE", ca);
    }
    let out = c.output().expect("aws runs");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn curl(url: &str, proxy: Option<(&str, &Path)>) -> String {
    let mut c = Command::new("curl");
    c.args(["-s", "-o", "/dev/null", "-w", "%{http_code}"]);
    if let Some((p, ca)) = proxy {
        c.arg("--proxy").arg(p).arg("--cacert").arg(ca);
    }
    let out = c.arg(url).output().expect("curl runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs LocalStack, see test/e2e/toolproxy-aws.sh"]
async fn aws_cli_against_localstack_with_placeholder_keys() {
    let Some(e) = env() else {
        panic!("set SCRIM_E2E_AWS_ENDPOINT");
    };
    let audit = MemoryAuditSink::new();
    let proxy = ToolProxy::builder()
        .upstream(UpstreamSettings::default())
        .audit(std::sync::Arc::new(audit.clone()))
        .build()
        .unwrap();
    let cfg: ToolProxyConfig = serde_yaml::from_str(&config(&e.host)).unwrap();
    let snap = Snapshot::from_config(
        1,
        &cfg,
        |r| match r {
            "env://AWS_AKID" => Some(SecretValue::new(REAL_AKID)),
            "env://AWS_SECRET" => Some(SecretValue::new(REAL_SECRET)),
            _ => None,
        },
        placeholders,
    )
    .unwrap();
    let (ph_akid, ph_secret) = (PH_AKID.to_owned(), PH_SECRET.to_owned());
    proxy.apply(snap).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let p2 = proxy.clone();
    tokio::spawn(async move { p2.serve(listener, std::future::pending()).await });
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("scrim-ca.pem");
    std::fs::write(&ca, proxy.ca().trust_bundle_pem()).unwrap();
    let purl = format!("http://{addr}");
    let p = Some(purl.as_str());
    let agent = (ph_akid.as_str(), ph_secret.as_str());
    let real = (REAL_AKID, REAL_SECRET);
    let home = dir.path();

    let r = tokio::task::block_in_place(|| {
        // Set-up with the real keys, directly: a bucket the real account owns.
        let bucket = format!("scrim-e2e-{}", std::process::id());
        let mb = aws(
            &e,
            home,
            &ca,
            None,
            real,
            &["s3", "mb", &format!("s3://{bucket}")],
        );
        assert_eq!(mb.status, 0, "{}", mb.stderr);

        // The account LocalStack sees is the real key's, through the proxy.
        let id = aws(
            &e,
            home,
            &ca,
            p,
            agent,
            &["sts", "get-caller-identity", "--output", "json"],
        );
        assert_eq!(id.status, 0, "{}", id.stderr);
        // LocalStack answered with the real key id as the account; the response redaction shows
        // the agent its placeholder there instead, never the real value.
        assert!(!id.stdout.contains(REAL_AKID), "{}", id.stdout);
        assert!(
            id.stdout.contains(&format!("\"Account\": \"{PH_AKID}\"")),
            "{}",
            id.stdout
        );
        // Directly, with the placeholder key id, it is LocalStack's default account.
        let direct = aws(
            &e,
            home,
            &ca,
            None,
            agent,
            &["sts", "get-caller-identity", "--output", "json"],
        );
        assert!(direct.stdout.contains("000000000000"), "{}", direct.stdout);

        // Upload (aws-chunked with a trailing checksum), list, download.
        let file = home.join("object.txt");
        std::fs::write(&file, "scrim e2e object\n").unwrap();
        let cp = aws(
            &e,
            home,
            &ca,
            p,
            agent,
            &[
                "s3",
                "cp",
                file.to_str().unwrap(),
                &format!("s3://{bucket}/object.txt"),
            ],
        );
        assert_eq!(cp.status, 0, "{}", cp.stderr);
        let ls = aws(
            &e,
            home,
            &ca,
            p,
            agent,
            &["s3", "ls", &format!("s3://{bucket}")],
        );
        assert_eq!(ls.status, 0, "{}", ls.stderr);
        assert!(ls.stdout.contains("object.txt"), "{}", ls.stdout);
        let lsall = aws(&e, home, &ca, p, agent, &["s3", "ls"]);
        assert!(lsall.stdout.contains(&bucket), "{}", lsall.stdout);
        // Bucket lists are per account: the placeholder key id's account has none of them.
        let direct = aws(&e, home, &ca, None, agent, &["s3", "ls"]);
        assert!(!direct.stdout.contains(&bucket), "{}", direct.stdout);

        // A presigned URL made with the placeholder secret: refused directly, re-signed through
        // the proxy.
        let url = aws(
            &e,
            home,
            &ca,
            None,
            agent,
            &["s3", "presign", &format!("s3://{bucket}/object.txt")],
        );
        let url = url.stdout.trim().to_owned();
        assert_eq!(curl(&url, None), "403");
        assert_eq!(curl(&url, Some((&purl, &ca))), "200");

        // A region the credential is not bound to.
        let eu = aws(
            &e,
            home,
            &ca,
            p,
            agent,
            &["--region", "eu-west-1", "sts", "get-caller-identity"],
        );
        assert_ne!(eu.status, 0);
        assert!(
            eu.stderr.contains("unbound_destination") || eu.stderr.contains("403"),
            "{}",
            eu.stderr
        );

        let rm = aws(
            &e,
            home,
            &ca,
            None,
            real,
            &["s3", "rb", "--force", &format!("s3://{bucket}")],
        );
        assert_eq!(rm.status, 0, "{}", rm.stderr);
        eu
    });
    let texts = audit_texts_of(&audit);
    assert!(!r.stderr.contains(REAL_AKID), "{}", r.stderr);
    assert!(texts.iter().any(|t| t.contains("eu-west-1")), "{texts:?}");
}

fn audit_texts_of(a: &MemoryAuditSink) -> Vec<String> {
    a.events().iter().map(|e| format!("{e:?}")).collect()
}
