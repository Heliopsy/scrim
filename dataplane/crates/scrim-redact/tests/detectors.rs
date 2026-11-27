//! Fallback detectors: rule fixtures and the false-positive corpus.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs,
    // The corpus test reports its hits.
    clippy::print_stderr
)]

mod common;

use common::fixtures::{Rng, b64, gen_body, hex};
use scrim_redact::*;

/// The default rules with encoded forms on, so every corpus test covers them too.
fn detector_snapshot(entropy: bool) -> Snapshot {
    let cfg = Config {
        detectors: DetectorConfig {
            entropy: entropy.then(EntropyConfig::default),
            encoded: true,
            ..Default::default()
        },
        ..Config::default()
    };
    Snapshot::build(vec![], common::keyring(), &cfg).unwrap()
}

fn rules_hit(s: &Snapshot, text: &str) -> Vec<&'static str> {
    let mut v = Vec::new();
    let mut out = Vec::new();
    s.redactor()
        .redact_with(text.as_bytes(), &mut out, &mut |h| {
            if let Hit::Detected { rule, .. } = h {
                v.push(rule);
            }
        })
        .unwrap();
    v
}

/// Generated tokens in each format (never real ones): the rule, the text it sits in, and the
/// secret that must not survive. Vendor prefixes are joined to random bodies at run time, so no
/// token-shaped literal is committed.
fn cases() -> Vec<(&'static str, String, String)> {
    let mut r = Rng::new(42);
    let b62 = common::fixtures::BASE62;
    let b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let hexl = "0123456789abcdef";
    let letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let bech32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";
    let b64s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let pw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#&()*+,-.;=?_~";
    // Forced classes, so a generated AWS secret always mixes upper, lower and digits.
    let aws_secret = format!("Ab3{}", r.string(b64s, 37));
    let whole = |rule: &'static str, tok: String| (rule, tok.clone(), tok);
    let mut v = vec![
        whole("aws-access-key-id", format!("AKIA{}", r.string(b32, 16))),
        whole("aws-access-key-id", format!("ASIA{}", r.string(b32, 16))),
        (
            "aws-secret-access-key",
            format!("aws_secret_access_key = {aws_secret}"),
            aws_secret.clone(),
        ),
        whole("github-token", format!("ghp_{}", r.string(b62, 36))),
        whole("github-token", format!("ghs_{}", r.string(b62, 36))),
        whole(
            "github-fine-grained-token",
            format!("github_pat_{}_{}", r.string(b62, 22), r.string(b62, 59)),
        ),
        whole(
            "anthropic-api-key",
            format!("sk-ant-api03-{}AA", r.string(url, 93)),
        ),
        whole("openai-api-key", format!("sk-proj-{}", r.string(url, 64))),
        whole(
            "openai-api-key",
            format!("sk-{}T3BlbkFJ{}", r.string(b62, 20), r.string(b62, 20)),
        ),
        whole("gitlab-token", format!("glpat-{}", r.string(url, 20))),
        whole("gitlab-token", format!("glptt-{}", r.string(hexl, 40))),
        whole("gitlab-token", format!("GR1348941{}", r.string(url, 20))),
        whole(
            "gitlab-token",
            format!("glcbt-{}_{}", r.string(b62, 2), r.string(url, 20)),
        ),
        whole(
            "slack-token",
            format!("xoxb-{}-{}", r.string("0123456789", 12), r.string(b62, 24)),
        ),
        whole(
            "slack-token",
            format!("xapp-1-A{}-{}", r.string(b62, 10), r.string(hexl, 40)),
        ),
        whole(
            "slack-webhook-url",
            format!(
                "hooks.slack.com/services/T{}/B{}/{}",
                r.string(b32, 8),
                r.string(b32, 8),
                r.string(b62, 24)
            ),
        ),
        whole("stripe-key", format!("sk_live_{}", r.string(b62, 24))),
        whole(
            "stripe-webhook-secret",
            format!("whsec_{}", r.string(b62, 32)),
        ),
        whole("google-api-key", format!("AIza{}", r.string(url, 35))),
        whole(
            "google-oauth-client-secret",
            format!("GOCSPX-{}", r.string(url, 28)),
        ),
        whole("npm-token", format!("npm_{}", r.string(b62, 36))),
        whole(
            "pypi-token",
            format!("pypi-AgEIcHlwaS5vcmc{}", r.string(url, 70)),
        ),
        whole(
            "docker-hub-token",
            format!("dckr_pat_{}", r.string(url, 27)),
        ),
        whole(
            "huggingface-token",
            format!("hf_Ab{}", r.string(letters, 32)),
        ),
        {
            let t = r.string(hexl, 32);
            ("twilio-credential", format!("TWILIO_AUTH_TOKEN={t}"), t)
        },
        {
            let t = format!("SK{}", r.string(hexl, 32));
            ("twilio-credential", format!("twilio_api_key: {t}"), t)
        },
        whole(
            "sendgrid-api-key",
            format!("SG.{}.{}", r.string(url, 22), r.string(url, 43)),
        ),
        {
            let k = b64(&r.bytes(64), false, true);
            (
                "azure-storage-key",
                format!(
                    "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={k};EndpointSuffix=core.windows.net"
                ),
                k,
            )
        },
        {
            let k = b64(&r.bytes(32), false, true);
            (
                "azure-shared-access-key",
                format!(
                    "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey={k}"
                ),
                k,
            )
        },
        whole(
            "azure-ad-client-secret",
            format!("{}8Q~{}", r.string(b62, 3), r.string(url, 34)),
        ),
        whole(
            "digitalocean-token",
            format!("dop_v1_{}", r.string(hexl, 64)),
        ),
        whole("shopify-token", format!("shpat_{}", r.string(hexl, 32))),
        whole(
            "atlassian-api-token",
            format!("ATATT3{}", r.string(url, 186)),
        ),
        {
            let p = format!("Zq7{}", r.string(pw, 17));
            (
                "database-url-password",
                format!("postgres://app:{p}@db.internal:5432/app"),
                p,
            )
        },
        {
            let p = r.string(b62, 24);
            (
                "database-url-password",
                format!("mongodb+srv://svc:{p}@cluster0.example.net/db"),
                p,
            )
        },
        whole(
            "hashicorp-vault-token",
            format!("hvs.{}", r.string(url, 90)),
        ),
        whole("doppler-token", format!("dp.st.dev.{}", r.string(b62, 40))),
        whole(
            "onepassword-service-account-token",
            format!("ops_eyJ{}", r.string(b64s, 200)),
        ),
        whole(
            "grafana-token",
            format!("glsa_{}_{}", r.string(b62, 32), r.string(hexl, 8)),
        ),
        whole("sentry-token", format!("sntryu_{}", r.string(hexl, 64))),
        whole("linear-api-key", format!("lin_api_{}", r.string(b62, 40))),
        whole(
            "postman-api-key",
            format!("PMAK-{}-{}", r.string(hexl, 24), r.string(hexl, 34)),
        ),
        whole(
            "age-secret-key",
            format!("AGE-SECRET-KEY-1{}", r.string(bech32, 58)),
        ),
        whole("databricks-token", format!("dapi{}a1", r.string(hexl, 30))),
        whole(
            "jwt",
            format!(
                "{}.{}.{}",
                b64(br#"{"alg":"HS256","typ":"JWT"}"#, true, false),
                b64(br#"{"sub":"1234567890","iat":1516239022}"#, true, false),
                b64(&r.bytes(32), true, false)
            ),
        ),
        // Formats added in the November 2026 review.
        whole("groq-api-key", format!("gsk_{}", r.string(b62, 52))),
        whole("xai-api-key", format!("xai-{}", r.string(b62, 80))),
        whole("perplexity-api-key", format!("pplx-{}", r.string(b62, 48))),
        whole(
            "openrouter-api-key",
            format!("sk-or-v1-{}", r.string(hexl, 64)),
        ),
        whole("deepseek-api-key", format!("sk-{}a1", r.string(hexl, 30))),
        {
            let u = r.string(hexl, 32);
            whole(
                "langfuse-secret-key",
                format!(
                    "sk-lf-{}-{}-{}-{}-{}",
                    &u[..8],
                    &u[8..12],
                    &u[12..16],
                    &u[16..20],
                    &u[20..]
                ),
            )
        },
        whole("elevenlabs-api-key", format!("sk_{}b2", r.string(hexl, 46))),
        whole("replicate-api-token", format!("r8_{}", r.string(b62, 37))),
        whole(
            "langsmith-api-key",
            format!("lsv2_pt_{}_{}", r.string(hexl, 32), r.string(hexl, 10)),
        ),
        whole("pinecone-api-key", format!("pcsk_{}", r.string(b62, 70))),
        whole("tavily-api-key", format!("tvly-dev-{}", r.string(b62, 32))),
        whole(
            "aws-bedrock-api-key",
            format!("{}{}{}", "ABSK", "QmVkcm9ja0FQSUtleS", r.string(b64s, 110)),
        ),
        whole(
            "aws-bedrock-api-key",
            // The prefix and the base64 of the host are joined at run time, as every case is.
            format!(
                "{}{}{}==",
                "bedrock-api-key-",
                "YmVkcm9jay5hbWF6b25hd3MuY29t",
                r.string(b64s, 400)
            ),
        ),
        whole(
            "google-oauth-access-token",
            format!("ya29.{}", r.string(url, 150)),
        ),
        whole("heroku-api-key", format!("HRKU-AA{}", r.string(url, 58))),
        whole(
            "notion-token",
            format!("ntn_{}{}", r.string("0123456789", 11), r.string(b62, 35)),
        ),
        whole(
            "tailscale-key",
            format!(
                "tskey-auth-k{}CNTRL-{}",
                r.string(b62, 8),
                r.string(b62, 32)
            ),
        ),
        whole(
            "sourcegraph-token",
            format!("sgp_{}_{}", r.string(hexl, 16), r.string(hexl, 40)),
        ),
        whole(
            "planetscale-token",
            format!("pscale_tkn_{}", r.string(url, 43)),
        ),
        whole("supabase-key", format!("sbp_{}", r.string(hexl, 40))),
        whole("supabase-key", format!("sb_secret_{}", r.string(url, 31))),
        whole("contentful-token", format!("CFPAT-{}", r.string(url, 43))),
        whole(
            "new-relic-key",
            format!(
                "NRAK-{}",
                r.string("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 27)
            ),
        ),
        whole(
            "dynatrace-token",
            format!(
                "dt0c01.{}.{}",
                r.string("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 24),
                r.string("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 64)
            ),
        ),
        whole(
            "mapbox-secret-token",
            format!("sk.eyJ{}.{}", r.string(url, 60), r.string(url, 22)),
        ),
        whole("prefect-api-key", format!("pnu_{}", r.string(b62, 36))),
        whole(
            "posthog-personal-api-key",
            format!("phx_{}", r.string(b62, 43)),
        ),
        whole("square-token", format!("sq0csp-{}", r.string(url, 43))),
        whole(
            "discord-webhook-url",
            format!(
                "discord.com/api/webhooks/{}/{}",
                r.string("0123456789", 19),
                r.string(url, 68)
            ),
        ),
        whole(
            "telegram-bot-token",
            format!("{}:AA{}", r.string("0123456789", 10), r.string(url, 33)),
        ),
        whole(
            "private-key",
            format!(
                "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----",
                b64(&r.bytes(90), false, true)
            ),
        ),
    ];
    v.sort_by_key(|c| c.0);
    v
}

/// Hits as (rule, matched text).
fn hits_with_text(s: &Snapshot, text: &str) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    let mut out = Vec::new();
    s.redactor()
        .redact_with(text.as_bytes(), &mut out, &mut |h| {
            if let Hit::Detected { rule, start, end } = h {
                v.push((rule, text[start..end].to_string()));
            }
        })
        .unwrap();
    v
}

#[test]
fn every_rule_fires_in_context() {
    let s = detector_snapshot(false);
    for (rule, text, secret) in cases() {
        for ctx in [
            "{}",
            "export TOKEN={}",
            "\"key\": \"{}\"",
            "Bearer {}\n",
            "a\\n{}\\n",
        ] {
            let t = ctx.replace("{}", &text);
            assert_eq!(
                hits_with_text(&s, &t),
                vec![(rule, secret.clone())],
                "{rule} in {ctx}"
            );
            let mut out = Vec::new();
            s.redactor().redact(t.as_bytes(), &mut out).unwrap();
            assert!(!common::contains(&out, secret.as_bytes()), "{rule}");
            let slug = format!("⟦scrim:det-{rule}:");
            assert!(common::contains(&out, slug.as_bytes()), "{rule}");
        }
    }
}

/// Every built-in rule has a generated case, and no rule is left without one.
#[test]
fn every_rule_has_a_case() {
    let covered: std::collections::BTreeSet<&str> = cases().iter().map(|c| c.0).collect();
    let off = default_off_rule_names();
    for name in builtin_rule_names() {
        if !off.contains(&name) {
            assert!(covered.contains(name), "no case for {name}");
        }
    }
}

#[test]
fn each_rule_can_be_disabled() {
    for (rule, text, _) in cases() {
        let cfg = Config {
            detectors: DetectorConfig {
                disabled_rules: vec![rule.into()],
                ..Default::default()
            },
            ..Config::default()
        };
        let s = Snapshot::build(vec![], common::keyring(), &cfg).unwrap();
        assert!(!rules_hit(&s, &text).contains(&rule), "{rule}");
    }
    assert!(builtin_rule_names().len() >= 35);
    // The group switch turns every rule off.
    let cfg = Config {
        detectors: DetectorConfig {
            rules_enabled: false,
            ..Default::default()
        },
        ..Config::default()
    };
    let s = Snapshot::build(vec![], common::keyring(), &cfg).unwrap();
    for (rule, text, _) in cases() {
        assert!(rules_hit(&s, &text).is_empty(), "{rule} with the group off");
    }
}

#[test]
fn rule_lists_are_checked() {
    let build = |enabled: &[&str], disabled: &[&str]| {
        Snapshot::build(
            vec![],
            common::keyring(),
            &Config {
                detectors: DetectorConfig {
                    enabled_rules: enabled.iter().map(|s| s.to_string()).collect(),
                    disabled_rules: disabled.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                },
                ..Config::default()
            },
        )
    };
    assert!(build(&["no-such-rule"], &[]).is_err());
    assert!(build(&[], &["no-such-rule"]).is_err());
    assert!(
        build(
            &["generic-secret-assignment"],
            &["generic-secret-assignment"]
        )
        .is_err()
    );
    assert!(build(&["generic-secret-assignment"], &[]).is_ok());
}

/// An AWS secret on the line of its key id, without a key name: `credentials.csv` and pasted
/// pairs.
#[test]
fn aws_secret_next_to_key_id() {
    let s = detector_snapshot(false);
    let mut r = Rng::new(5);
    let id = format!("AKIA{}", r.string("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16));
    let secret = format!(
        "x9Y{}",
        r.string(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            37
        )
    );
    for text in [
        format!("User name,Password,Access key ID,Secret access key\nci,,{id},{secret}\n"),
        format!("{id} {secret}"),
        format!(r#"{{"content":"id={id}\tsecret={secret}\n"}}"#),
        format!("\"AccessKeyId\": \"{id}\", \"SecretAccessKey\": \"{secret}\""),
        format!(r#"\"AccessKeyId\": \"{id}\",\n\"SecretAccessKey\": \"{secret}\""#),
    ] {
        assert_eq!(
            hits_with_text(&s, &text),
            vec![
                ("aws-access-key-id", id.clone()),
                ("aws-secret-access-key", secret.clone())
            ],
            "{text}"
        );
    }
    // Not on the next line, not a hex digest, not without the key id rule.
    let sha1 = hex(&r.bytes(20));
    for text in [
        format!("{id}\n{secret}"),
        format!("{id} {sha1}"),
        format!("{id}\\n{secret}"),
    ] {
        assert_eq!(rules_hit(&s, &text), vec!["aws-access-key-id"], "{text}");
    }
    let no_id = Snapshot::build(
        vec![],
        common::keyring(),
        &Config {
            detectors: DetectorConfig {
                disabled_rules: vec!["aws-access-key-id".into()],
                ..Default::default()
            },
            ..Config::default()
        },
    )
    .unwrap();
    assert!(rules_hit(&no_id, &format!("{id} {secret}")).is_empty());
}

/// Values after a key name or inside a URL: the specific format wins, and a token in a URL's
/// user part is found as well as the password.
#[test]
fn values_inside_assignments_and_urls() {
    let s = detector_snapshot(false);
    let mut r = Rng::new(6);
    let gh = format!("ghp_{}", r.string(common::fixtures::BASE62, 36));
    let pw = r.string(common::fixtures::BASE62, 20);
    assert_eq!(
        hits_with_text(&s, &format!("postgres://{gh}:{pw}@db/x")),
        vec![
            ("github-token", gh.clone()),
            ("database-url-password", pw.clone())
        ]
    );
    let generic = Snapshot::build(
        vec![],
        common::keyring(),
        &Config {
            detectors: DetectorConfig {
                enabled_rules: vec!["generic-secret-assignment".into()],
                ..Default::default()
            },
            ..Config::default()
        },
    )
    .unwrap();
    assert_eq!(
        hits_with_text(&generic, &format!("GITHUB_TOKEN={gh}")),
        vec![("github-token", gh.clone())]
    );
    let lit = format!("Xk9#{}", r.string(common::fixtures::BASE62, 12));
    for text in [
        format!("password = \"{lit}\""),
        format!("DB_PASSWORD={lit}\n"),
        format!("  client_secret: '{lit}'"),
        format!(r#"{{\"api_key\": \"{lit}\"}}"#),
    ] {
        assert_eq!(
            hits_with_text(&generic, &text),
            vec![("generic-secret-assignment", lit.clone())],
            "{text}"
        );
        // Off by default.
        assert!(rules_hit(&s, &text).is_empty(), "{text}");
    }
}

/// Look-alikes that must stay: documentation stand-ins, variables, identifiers, digests.
#[test]
fn near_misses() {
    let mut r = Rng::new(8);
    let hexl = "0123456789abcdef";
    let generic = Snapshot::build(
        vec![],
        common::keyring(),
        &Config {
            detectors: DetectorConfig {
                enabled_rules: vec!["generic-secret-assignment".into()],
                ..Default::default()
            },
            ..Config::default()
        },
    )
    .unwrap();
    let texts = vec![
        "postgres://user:password@localhost:5432/app".to_string(),
        "postgres://user:${DB_PASSWORD}@db/app".to_string(),
        "mysql://root:<password>@127.0.0.1/db".to_string(),
        "redis://:$REDIS_PASSWORD@cache:6379".to_string(),
        "postgres://app:****@db/app".to_string(),
        "postgres://db.internal:5432/app".to_string(),
        "mongodb://reader@mongo:27017".to_string(),
        "redis://localhost:6379/0".to_string(),
        "aws_secret_access_key = os.environ[\"AWS_SECRET_ACCESS_KEY\"]".to_string(),
        "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}".to_string(),
        "secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY".to_string(),
        format!("TWILIO_ACCOUNT_SID=AC{}", r.string(hexl, 32)),
        "TWILIO_AUTH_TOKEN=your_auth_token".to_string(),
        "model = self.hf_hub_download_from_the_model_repository".to_string(),
        format!("dapi{}", r.string("0123456789", 32)),
        "secret_key = settings.SECRET_KEY".to_string(),
        "password = getpass.getpass(prompt)".to_string(),
        "token = request.headers.get(\"Authorization\")".to_string(),
        "max_tokens: 4096, \"token_type\": \"Bearer\"".to_string(),
        "password: changeme".to_string(),
        "api_key = \"${API_KEY}\"".to_string(),
        "secret = base64.b64decode(blob)".to_string(),
        "glob(\"**/*.rs\") glance global glcbt glsa_x".to_string(),
        "disk_usage task_runner risk_score mask_layer sk_learn".to_string(),
        "SharedAccessKeyName=RootManageSharedAccessKey;".to_string(),
        "AccountName=acct;AccountKey=REPLACE_ME;".to_string(),
    ];
    for t in &texts {
        assert!(
            hits_with_text(&generic, t).is_empty(),
            "{t}: {:?}",
            hits_with_text(&generic, t)
        );
    }
}

/// Text an agent sends all the time: prose, code, logs, hashes, UUIDs, base64 data, paths.
fn corpus() -> String {
    let mut r = Rng::new(7);
    let mut c = common::fixtures::gen_stream_text(3, 200_000, &[], 0);
    for _ in 0..2000 {
        let sha1 = hex(&r.bytes(20));
        let sha256 = hex(&r.bytes(32));
        let u = hex(&r.bytes(16));
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &u[..8],
            &u[8..12],
            &u[12..16],
            &u[16..20],
            &u[20..]
        );
        c.push_str(&format!("commit {sha1} sha256:{sha256} id={uuid} "));
        c.push_str(
            "/usr/lib/x86_64-linux-gnu/libssl.so.3 src/components/HTTPRequestHandlerFactory.ts ",
        );
        c.push_str(
            "AbstractSingletonProxyFactoryBean getElementsByClassName XMLHttpRequestEventTarget ",
        );
        c.push_str("ask-anything task-runner desk-lamp sk-learn AKIA-docs ghp_short eyJhbGc ");
    }
    c.push_str(include_str!("../src/restore.rs"));
    c.push_str(include_str!("../src/matcher.rs"));
    c.push_str(include_str!("../src/redactor.rs"));
    c
}

#[test]
fn false_positive_corpus() {
    let c = corpus();
    let body = String::from_utf8(gen_body(3, 400_000, &[]).0).unwrap();
    let rules = detector_snapshot(false);
    let hits = rules_hit(&rules, &format!("{c}{body}"));
    // Pattern rules: zero false positives on the corpus (source files included).
    assert!(hits.is_empty(), "pattern rules fired: {hits:?}");
    // Entropy (opt-in): silent on prose, code, hashes, UUIDs and paths.
    let ent = detector_snapshot(true);
    let mut quiet = Vec::new();
    let mut out = Vec::new();
    ent.redactor()
        .redact_with(c.as_bytes(), &mut out, &mut |h| {
            if let Hit::Detected { start, end, .. } = h {
                quiet.push(c[start..end].to_string());
            }
        })
        .unwrap();
    assert!(quiet.is_empty(), "entropy hits on the corpus: {quiet:?}");
    // Base64 data of random bytes does trip it, which is why entropy is off by default; the rate
    // on an agent request body with embedded blobs stays bounded.
    let n = rules_hit(&ent, &body).len();
    let per_mb = n as f64 / (body.len() as f64 / 1e6);
    assert!(per_mb < 2000.0, "{n} entropy hits ({per_mb:.0}/MB)");
}

#[test]
fn entropy_catches_random_tokens() {
    let s = detector_snapshot(true);
    let mut r = Rng::new(9);
    let tok = r.string(common::fixtures::BASE62, 40);
    assert_eq!(
        rules_hit(&s, &format!("secret = {tok};")),
        vec![ENTROPY_RULE]
    );
    assert!(rules_hit(&s, &format!("commit {}", hex(&r.bytes(20)))).is_empty());
}

/// The repository's own documentation, specs and source (test fixtures excepted) as a corpus of
/// normal text and code: the default rules find nothing in it beyond the fake credentials
/// listed in `DELIBERATE`. `SCRIM_DETECTOR_CORPUS=<dir>`
/// scans another tree instead and prints every hit without failing.
#[test]
fn repository_corpus() {
    let custom = std::env::var("SCRIM_DETECTOR_CORPUS").ok();
    let root = std::path::PathBuf::from(
        custom
            .clone()
            .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../..").to_string()),
    );
    let root = root.canonicalize().unwrap_or(root);
    let s = detector_snapshot(false);
    let mut files = Vec::new();
    walk(&root, &mut files);
    let (mut bytes, mut found) = (0usize, Vec::new());
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        bytes += text.len();
        // Forward slashes on every platform, as DELIBERATE lists them.
        let rel = f
            .strip_prefix(&root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        let mut out = Vec::new();
        s.redactor()
            .redact_with(text.as_bytes(), &mut out, &mut |h| {
                if let Hit::Detected { rule, start, .. } = h {
                    if custom.is_none() && DELIBERATE.contains(&(rel.as_str(), rule)) {
                        return;
                    }
                    let line = text[..start].matches('\n').count() + 1;
                    found.push(format!("{rel}:{line} {rule}"));
                }
            })
            .unwrap();
    }
    eprintln!(
        "detector corpus: {} files, {} bytes, {} hits",
        files.len(),
        bytes,
        found.len()
    );
    for h in &found {
        eprintln!("  {h}");
    }
    assert!(
        custom.is_some() || bytes > 1_000_000,
        "corpus too small: {bytes} bytes"
    );
    assert!(
        custom.is_some() || found.is_empty(),
        "default rules fired on the repository"
    );
}

/// Files that hold fake credentials on purpose: test values inside source files, documented
/// examples and a throwaway database password of the load test. Each is a correct detection.
const DELIBERATE: &[(&str, &str)] = &[
    (".gitleaks.toml", "private-key"),
    (".gitleaks.toml", "aws-access-key-id"),
    ("bench/redact-bench/rust/src/lib.rs", "github-token"),
    ("dataplane/crates/scrim-dataplane/src/identity.rs", "jwt"),
    (
        "dataplane/crates/scrim-dataplane/src/snapshot.rs",
        "github-token",
    ),
    ("dataplane/crates/scrim-llm/src/token.rs", "private-key"),
    (
        "dataplane/crates/scrim-redact/src/guard_tx.rs",
        "private-key",
    ),
    ("dataplane/crates/scrim-toolproxy/src/decide.rs", "jwt"),
    (
        "dataplane/crates/scrim-toolproxy/src/sigv4.rs",
        "aws-access-key-id",
    ),
    ("docs/ca.md", "private-key"),
    ("internal/leak/seed.go", "private-key"),
    ("openspec/specs/redaction/spec.md", "github-token"),
    (
        "openspec/changes/archive/2026-11-24-scrim-v1/specs/redaction/spec.md",
        "github-token",
    ),
    (
        "openspec/specs/secret-stores/spec.md",
        "database-url-password",
    ),
    (
        "openspec/changes/archive/2026-11-24-scrim-v1/specs/secret-stores/spec.md",
        "database-url-password",
    ),
    ("test/load/orchestrate.go", "database-url-password"),
];

/// Text files under `dir`, skipping build output, vendored and generated trees, and the files
/// that hold token-shaped test values on purpose.
fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    const SKIP_DIRS: &[&str] = &[
        ".git",
        "target",
        "node_modules",
        ".worktrees",
        "testdata",
        "fixtures",
        "results",
        "gen",
        "fuzz",
        "proptest-regressions",
        "tests",
    ];
    const SKIP_FILES: &[&str] = &[
        "detect.rs",
        "shape.rs",
        "detectors.rs",
        "go.sum",
        "Cargo.lock",
        "CHANGELOG.md",
    ];
    const EXT: &[&str] = &[
        "rs", "go", "md", "yaml", "yml", "toml", "json", "sh", "proto", "txt", "tpl",
    ];
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') || name == ".github" {
                walk(&p, out);
            }
            continue;
        }
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if EXT.contains(&ext)
            && !SKIP_FILES.contains(&name.as_str())
            && !name.ends_with("_test.go")
            && !name.ends_with(".pb.go")
            && e.metadata().map(|m| m.len() < 4 << 20).unwrap_or(false)
        {
            out.push(p);
        }
    }
}

/// The control plane validates `redaction.detectors.*` against `internal/daemon/detectors.json`:
/// it lists exactly these rules, in this order, with the same defaults.
#[test]
fn rule_list_shared_with_the_control_plane() {
    let v: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../internal/daemon/detectors.json"
    )))
    .unwrap();
    let rules: Vec<(String, bool)> = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                r["default"].as_bool().unwrap(),
            )
        })
        .collect();
    let off = default_off_rule_names();
    let ours: Vec<(String, bool)> = builtin_rule_names()
        .into_iter()
        .map(|n| (n.to_string(), !off.contains(&n)))
        .collect();
    assert_eq!(rules, ours);
}

fn entropy_snapshot(e: EntropyConfig) -> Snapshot {
    let cfg = Config {
        detectors: DetectorConfig {
            rules_enabled: false,
            entropy: Some(e),
            ..Default::default()
        },
        ..Config::default()
    };
    Snapshot::build(vec![], common::keyring(), &cfg).unwrap()
}

/// Entropy hits on the repository corpus and the generated agent bodies, per context, printed
/// for docs/configuration.md. The key-name context stays below one hit per megabyte of source
/// and finds nothing in agent bodies; every token is much noisier.
#[test]
fn entropy_false_positive_rates() {
    let root = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."));
    let mut files = Vec::new();
    walk(&root, &mut files);
    let mut repo = String::new();
    for f in &files {
        if let Ok(t) = std::fs::read_to_string(f) {
            repo.push_str(&t);
            repo.push('\n');
        }
    }
    let body = String::from_utf8(gen_body(3, 2_000_000, &[]).0).unwrap();
    let synthetic = corpus();
    let mut rates = Vec::new();
    for (name, e) in [
        ("key-name", EntropyConfig::default()),
        ("any", EntropyConfig::any_context()),
    ] {
        let s = entropy_snapshot(e);
        for (what, text) in [
            ("repository", &repo),
            ("bodies", &body),
            ("synthetic", &synthetic),
        ] {
            let mut hits = Vec::new();
            let mut out = Vec::new();
            s.redactor()
                .redact_with(text.as_bytes(), &mut out, &mut |h| {
                    if let Hit::Detected { start, end, .. } = h {
                        hits.push({
                            let a = start.saturating_sub(30);
                            let a = (0..=a)
                                .rev()
                                .find(|&k| text.is_char_boundary(k))
                                .unwrap_or(0);
                            text[a..end].to_string()
                        });
                    }
                })
                .unwrap();
            let per_mb = hits.len() as f64 / (text.len() as f64 / 1e6);
            eprintln!(
                "entropy {name:>8} on {what:<10} {:>9} bytes: {:>5} hits, {per_mb:>8.2}/MB {:?}",
                text.len(),
                hits.len(),
                &hits[..hits.len().min(16)]
            );
            rates.push((name, what, per_mb));
        }
    }
    for (name, what, per_mb) in rates {
        if name == "key-name" {
            let bound = if what == "repository" { 1.0 } else { 0.0 };
            assert!(
                per_mb <= bound,
                "key-name entropy on {what}: {per_mb:.2}/MB"
            );
        }
    }
}

/// The key-name context: values after a key name that says secret, in the forms code, config,
/// shells and HTTP write them; not values a client must send back, paths or references.
#[test]
fn entropy_key_names() {
    let s = entropy_snapshot(EntropyConfig::default());
    let mut r = Rng::new(31);
    let pw = format!("Zq7!{}", r.string(common::fixtures::BASE62, 16));
    let tok = r.string(common::fixtures::BASE62, 24);
    for t in [
        format!("SESSION_SECRET={pw}\n"),
        format!("export DB_PASSWORD='{pw}'"),
        format!(r#"{{"api_key": "{pw}"}}"#),
        format!(r#"{{\"client_secret\":\"{pw}\"}}"#),
        format!("password := \"{pw}\""),
        format!("'signing_key' => '{pw}',"),
        format!("Authorization: Bearer {tok}\r\n"),
        format!("mysql --password {pw} -h db"),
        format!("encryptionKey: {pw}"),
    ] {
        let want = if t.contains(&pw) { &pw } else { &tok };
        assert_eq!(
            hits_with_text(&s, &t),
            vec![(ENTROPY_RULE, want.clone())],
            "{t}"
        );
    }
    for t in [
        format!(r#"{{"nextPageToken": "{tok}"}}"#),
        format!(r#"{{"csrf_token": "{tok}"}}"#),
        format!("password = os.environ[\"{tok}\"]"),
        format!("api_key = settings.{tok}"),
        format!("secret = make_{tok}()"),
        format!("token = ${{{tok}}}"),
        format!("username = {tok}"),
        format!("the value {tok} again"),
        "password: correcthorsebatterystaple".to_string(),
        "secret_ref: /var/run/secrets/kubernetes.io/serviceaccount/token".to_string(),
        "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request".to_string(),
        "git push https://x-access-token:SCRIM_GITHUB_TOKEN@github.com/o/r".to_string(),
        format!("token: {}", hex(&r.bytes(20))),
    ] {
        assert!(
            hits_with_text(&s, &t).is_empty(),
            "{t}: {:?}",
            hits_with_text(&s, &t)
        );
    }
}

/// Encoded forms of a rule match: the characters that encode it are replaced, the text around
/// them is kept, and `encoded: false` turns it off.
#[test]
fn encoded_forms_of_rule_matches() {
    let on = detector_snapshot(false);
    let off = Snapshot::build(
        vec![],
        common::keyring(),
        &Config {
            detectors: DetectorConfig {
                encoded: false,
                ..Default::default()
            },
            ..Config::default()
        },
    )
    .unwrap();
    let mut r = Rng::new(5);
    let ghp = format!("ghp_{}", r.string(common::fixtures::BASE62, 36));
    let aws = format!("Ab3/{}+x", r.string(common::fixtures::BASE62, 34));
    let env = format!("SERVICE=billing\nGITHUB_TOKEN={ghp}\nLOG_LEVEL=debug\n");
    let pct = |s: &str| -> String {
        s.bytes()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
                    (c as char).to_string()
                } else {
                    format!("%{c:02X}")
                }
            })
            .collect()
    };
    let cases: Vec<(String, &str)> = vec![
        // kubectl get secret -o yaml
        (
            format!("data:\n  token: {}\n", b64(ghp.as_bytes(), false, true)),
            "github-token",
        ),
        // base64 of a whole .env file, URL-safe and unpadded
        (b64(env.as_bytes(), true, false), "github-token"),
        // JSON-escaped line break before the run
        (
            format!(r#"{{"c":"secret:\n{}"}}"#, b64(ghp.as_bytes(), false, true)),
            "github-token",
        ),
        (format!("value={}", hex(ghp.as_bytes())), "github-token"),
        (format!("value=0x{}", hex(ghp.as_bytes())), "github-token"),
        (
            format!("q=1&{}&x=2", pct(&format!("aws_secret_access_key={aws}"))),
            "aws-secret-access-key",
        ),
    ];
    for (text, rule) in &cases {
        let h = hits_with_text(&on, text);
        assert_eq!(h.len(), 1, "{text}: {h:?}");
        assert_eq!(h[0].0, *rule, "{text}");
        let mut out = Vec::new();
        on.redactor().redact(text.as_bytes(), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains(&format!("⟦scrim:det-{rule}:")), "{out}");
        // Nothing the encoding of the token leaves decodes back to it.
        let h = hits_with_text(&on, &out);
        assert!(h.is_empty(), "{out}: {h:?}");
        assert!(hits_with_text(&off, text).is_empty(), "off: {text}");
    }
    // Around the token, the text stays: a kubernetes secret keeps its keys.
    let text = format!(
        "data:\n  token: {}\n  user: YWRtaW4=\n",
        b64(ghp.as_bytes(), false, true)
    );
    let mut out = Vec::new();
    on.redactor().redact(text.as_bytes(), &mut out).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.starts_with("data:\n  token: ") && out.ends_with("\n  user: YWRtaW4=\n"),
        "{out}"
    );
    // Base64 and hex of text with no token, and of binary data, stay as they are.
    for text in [
        b64(
            b"the quick brown fox jumps over the lazy dog, twice over",
            false,
            true,
        ),
        hex(b"the quick brown fox jumps over the lazy dog"),
        b64(&r.bytes(3000), false, true),
        "https://example.com/search?q=api%20key%20rotation&lang=en".to_string(),
    ] {
        assert!(hits_with_text(&on, &text).is_empty(), "{text}");
    }
}
