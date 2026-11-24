//! The real `kubectl` through the tool proxy against a kind API server with certificate
//! authentication (task 10a.4). Ignored by default; `test/e2e/toolproxy-kube.sh` creates a
//! rootless podman kind cluster with a private kubeconfig and runs it with:
//!
//! - `SCRIM_E2E_KUBECONFIG`: the cluster's private kubeconfig (its admin client certificate is the
//!   credential the store would hold)
//! - `SCRIM_E2E_KUBE_CONTEXT`: its context
//! - `SCRIM_E2E_KUBECTL`: path of the `kubectl` binary
//!
//! The API server certificate must name `kind-api.scrim.test` (a kubeadm `certSANs` patch):
//! clients do not send loopback addresses through a proxy, so the agent's kubeconfig names that
//! host and the proxy resolves it to the cluster.
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]
// Runs kubectl with a Unix PATH against a kind cluster.
#![cfg(unix)]

use std::collections::HashMap;
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use scrim_toolproxy::*;

const HOST: &str = "kind-api.scrim.test";
const DECLARED: &str = "SCRIM_KIND_ADMIN_CERT";

struct Kind {
    port: u16,
    ca_pem: Vec<u8>,
    client_pem: String,
}

fn kind() -> Kind {
    let path = std::env::var("SCRIM_E2E_KUBECONFIG").expect("set SCRIM_E2E_KUBECONFIG");
    let ctx = std::env::var("SCRIM_E2E_KUBE_CONTEXT").expect("set SCRIM_E2E_KUBE_CONTEXT");
    let doc: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let find = |list: &str, name: &str| {
        doc[list]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|e| e["name"].as_str() == Some(name))
            .unwrap()
            .clone()
    };
    let context = find("contexts", &ctx);
    let cluster = find("clusters", context["context"]["cluster"].as_str().unwrap());
    let user = find("users", context["context"]["user"].as_str().unwrap());
    let server = cluster["cluster"]["server"].as_str().unwrap();
    let port = server.rsplit(':').next().unwrap().parse().unwrap();
    let b64 = |v: &serde_yaml::Value| STANDARD.decode(v.as_str().unwrap()).unwrap();
    let mut client = b64(&user["user"]["client-certificate-data"]);
    client.extend(b64(&user["user"]["client-key-data"]));
    Kind {
        port,
        ca_pem: b64(&cluster["cluster"]["certificate-authority-data"]),
        client_pem: String::from_utf8(client).unwrap(),
    }
}

fn agent_kubeconfig(port: u16, proxy: &str, scrim_ca: &str, cert: &str, key: &str) -> String {
    let e = |s: &str| STANDARD.encode(s);
    format!(
        "apiVersion: v1
kind: Config
clusters:
- name: kind
  cluster:
    server: https://{HOST}:{port}
    certificate-authority-data: {}
    proxy-url: {proxy}
users:
- name: admin
  user:
    client-certificate-data: {}
    client-key-data: {}
contexts:
- name: scrim-agent
  context: {{cluster: kind, user: admin}}
current-context: scrim-agent
",
        e(scrim_ca),
        e(cert),
        e(key)
    )
}

fn kubectl(kubeconfig: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let bin = std::env::var("SCRIM_E2E_KUBECTL").unwrap_or_else(|_| "kubectl".into());
    let out = Command::new(bin)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", kubeconfig.parent().unwrap())
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .arg("--context")
        .arg("scrim-agent")
        .arg("--request-timeout=20s")
        .args(args)
        .output()
        .expect("kubectl runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a kind cluster, see test/e2e/toolproxy-kube.sh"]
async fn kubectl_with_certificate_auth_through_the_proxy() {
    let k = kind();
    let roots: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&k.ca_pem)
        .collect::<Result<_, _>>()
        .unwrap();
    let mut overrides = HashMap::new();
    overrides.insert(
        HOST.to_owned(),
        vec![format!("127.0.0.1:{}", k.port).parse().unwrap()],
    );
    let audit = MemoryAuditSink::new();
    let proxy = ToolProxy::builder()
        .upstream(UpstreamSettings {
            native_roots: false,
            extra_roots: roots,
            resolve_overrides: overrides,
            ..Default::default()
        })
        .audit(std::sync::Arc::new(audit.clone()))
        .build()
        .unwrap();
    let cfg: ToolProxyConfig = serde_yaml::from_str(&format!(
        r"
credentials:
  - name: kind-admin
    reference: env://KIND_ADMIN
    placeholders: [{DECLARED}]
    binding: {{ hosts: ['{HOST}:{}'] }}
    client_certificate: true
",
        k.port
    ))
    .unwrap();
    let value = k.client_pem.clone();
    let snap = Snapshot::from_config(
        1,
        &cfg,
        move |_| Some(SecretValue::new(value.clone())),
        |_, _| vec![],
    )
    .unwrap();
    proxy.apply(snap).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let p2 = proxy.clone();
    tokio::spawn(async move { p2.serve(listener, std::future::pending()).await });

    let dir = tempfile::tempdir().unwrap();
    let purl = format!("http://{addr}");
    let ca = proxy.ca().trust_bundle_pem();
    let (cert, key) = placeholder_certificate(DECLARED, "scrim placeholder kind-admin").unwrap();
    let kc = dir.path().join("kubeconfig");
    std::fs::write(&kc, agent_kubeconfig(k.port, &purl, &ca, &cert, &key)).unwrap();
    // The agent's kubeconfig holds no part of the real key.
    let written = std::fs::read_to_string(&kc).unwrap();
    let real_key_b64 = STANDARD.encode(&k.client_pem);
    assert!(!written.contains(&real_key_b64[..64]));

    let other_kc = dir.path().join("other");
    let (oc, ok) = placeholder_certificate("SCRIM_NOT_A_CREDENTIAL", "other").unwrap();
    std::fs::write(&other_kc, agent_kubeconfig(k.port, &purl, &ca, &oc, &ok)).unwrap();

    tokio::task::block_in_place(|| {
        let (code, out, err) = kubectl(&kc, &["get", "nodes", "-o", "name"]);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("node/"), "{out}");
        let (code, out, err) = kubectl(
            &kc,
            &["auth", "whoami", "-o", "jsonpath={.status.userInfo.groups}"],
        );
        assert_eq!(code, 0, "{err}");
        assert!(
            out.contains("kubeadm:cluster-admins") || out.contains("system:masters"),
            "{out}"
        );
        // A certificate that is not the placeholder: nothing is presented upstream, so the API
        // server sees an anonymous client.
        let (code, _, err) = kubectl(&other_kc, &["get", "nodes"]);
        assert_ne!(code, 0);
        assert!(
            err.contains("Forbidden") || err.contains("Unauthorized") || err.contains("forbidden"),
            "{err}"
        );
    });
    let events: Vec<String> = audit.events().iter().map(|e| format!("{e:?}")).collect();
    assert!(
        events.iter().any(|e| e.contains("kind-admin")),
        "{events:?}"
    );
    for e in &events {
        assert!(!e.contains("PRIVATE KEY"), "{e}");
    }
}
