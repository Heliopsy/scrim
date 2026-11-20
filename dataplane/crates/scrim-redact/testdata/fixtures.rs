//! Deterministic fixture generator shared by tests, benches and fuzz seeds.
//!
//! A Rust port of `bench/redact-bench/fixtures/gen`: the same secret kinds and weights, the same
//! request body shape (system prompt, tools, user/assistant/tool-result turns with prose, code,
//! logs, env files and base64 blobs) and the same hit forms and hit rate (one per 4,096 bytes).
//! The byte streams differ from the Go generator's (different PRNG); the conditions match.
#![allow(
    dead_code,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unreachable_pub
)]

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x5DEE_CE66_D1CE_4E5B)
    }
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    pub fn f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    pub fn string(&mut self, alpha: &str, n: usize) -> String {
        let a = alpha.as_bytes();
        (0..n).map(|_| a[self.below(a.len())] as char).collect()
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

pub const BASE62: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const B64STD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE32UP: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PW: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*/\"\\";
const NON_ASCII: &[&str] = &["é", "ü", "ß", "€", "ø", "ñ", "Ж", "😀"];

pub fn b64(data: &[u8], url: bool, pad: bool) -> String {
    let a = if url { B64URL } else { B64STD }.as_bytes();
    let mut out = String::new();
    for ch in data.chunks(3) {
        let x = (u32::from(ch[0]) << 16)
            | (u32::from(*ch.get(1).unwrap_or(&0)) << 8)
            | u32::from(*ch.get(2).unwrap_or(&0));
        for q in 0..=ch.len() {
            out.push(a[((x >> (18 - 6 * q)) & 63) as usize] as char);
        }
        if pad {
            for _ in ch.len()..3 {
                out.push('=');
            }
        }
    }
    out
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn json_escape(s: &str, slash: bool, uni: bool) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '/' if slash => o.push_str("\\/"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c if uni && (c as u32) >= 0x80 => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    o.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => o.push(c),
        }
    }
    o
}

pub fn url_encode(s: &str) -> String {
    let mut o = String::new();
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
            o.push(c as char);
        } else {
            o.push_str(&format!("%{c:02X}"));
        }
    }
    o
}

const KINDS: &[&str] = &[
    "ghp",
    "github_pat",
    "sk-ant",
    "akia",
    "aws_secret",
    "b62_32",
    "b62_48",
    "b62_64",
    "jwt",
    "pem",
    "password",
];
const SMALL_KINDS: &[&str] = &[
    "ghp",
    "github_pat",
    "sk-ant",
    "akia",
    "aws_secret",
    "b62_32",
    "b62_64",
    "jwt",
    "pem",
    "password",
];
const WEIGHTS: &[usize] = &[150, 100, 100, 100, 100, 85, 85, 80, 80, 20, 100];

pub fn gen_secret(r: &mut Rng, kind: &str) -> String {
    match kind {
        "ghp" => format!("ghp_{}", r.string(BASE62, 36)),
        "github_pat" => format!(
            "github_pat_{}_{}",
            r.string(BASE62, 22),
            r.string(BASE62, 59)
        ),
        "sk-ant" => format!("sk-ant-api03-{}AA", r.string(B64URL, 91)),
        "akia" => format!("AKIA{}", r.string(BASE32UP, 16)),
        "aws_secret" => r.string(B64STD, 40),
        "b62_32" => r.string(BASE62, 32),
        "b62_48" => r.string(BASE62, 48),
        "b62_64" => r.string(BASE62, 64),
        "jwt" => {
            let h = b64(br#"{"alg":"HS256","typ":"JWT"}"#, true, false);
            let p = format!(
                r#"{{"sub":"user-{}","iat":{},"scope":"{}"}}"#,
                r.below(1_000_000),
                1_700_000_000 + r.below(100_000_000),
                r.string(BASE62, 12)
            );
            let s = r.bytes(32);
            format!(
                "{h}.{}.{}",
                b64(p.as_bytes(), true, false),
                b64(&s, true, false)
            )
        }
        "pem" => {
            let body = b64(&r.bytes(1218), false, true);
            let mut s = String::from("-----BEGIN PRIVATE KEY-----\n");
            for c in body.as_bytes().chunks(64) {
                s.push_str(std::str::from_utf8(c).unwrap());
                s.push('\n');
            }
            s.push_str("-----END PRIVATE KEY-----");
            s
        }
        "password" => {
            let mut s: Vec<char> = r.string(PW, 8).chars().collect();
            if r.below(5) == 0 {
                let i = r.below(8);
                s[i] = r.pick(NON_ASCII).chars().next().unwrap();
            }
            s.into_iter().collect()
        }
        _ => unreachable!(),
    }
}

pub fn gen_secrets(seed: u64, n: usize) -> Vec<String> {
    let mut r = Rng::new(seed);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < n {
        let kind = if n <= SMALL_KINDS.len() {
            SMALL_KINDS[i % SMALL_KINDS.len()]
        } else {
            let mut x = r.below(1000);
            let mut k = 0;
            while x >= WEIGHTS[k] {
                x -= WEIGHTS[k];
                k += 1;
            }
            KINDS[k]
        };
        i += 1;
        let s = gen_secret(&mut r, kind);
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

const WORDS: &str = "the a to of and in is it that for on with as be this are was not by from at or an have function return error value config request response server client token key file path line build test deploy cluster service handler context buffer stream event json parse encode decode retry timeout cache index query update delete create read write open close start stop run check verify proxy upstream header body chunk message content block delta text tool input output result status";
const IDENTS: &str = "ctx req resp buf err cfg srv conn rows item items opts params data payload user session handler router logger client cache store queue worker pool batch result value key name";
const HIT_FORMS: &[&str] = &[
    "json",
    "json",
    "json",
    "json",
    "json_slash",
    "json_u",
    "b64",
    "b64",
    "b64",
    "b64url",
    "hex",
    "url",
    "url",
];

struct Body<'a> {
    r: Rng,
    words: Vec<&'static str>,
    idents: Vec<&'static str>,
    secrets: &'a [String],
    hit_rate: f64,
    buf: String,
    pub hits: usize,
}

/// (text, raw): raw text is inserted as is, other text is JSON-escaped by the writer.
type Seg = (String, bool);

impl Body<'_> {
    fn word(&mut self) -> &'static str {
        self.words[self.r.below(self.words.len())]
    }
    fn ident(&mut self) -> &'static str {
        self.idents[self.r.below(self.idents.len())]
    }
    fn sentence(&mut self) -> String {
        let n = 6 + self.r.below(14);
        let mut s = (0..n).map(|_| self.word()).collect::<Vec<_>>().join(" ");
        if self.r.below(10) == 0 {
            s.push_str(r#" (naïve → "quoted" path C:\tmp\x)"#);
        }
        let mut c = s.chars();
        let first = c.next().unwrap().to_ascii_uppercase();
        format!("{first}{}. ", c.as_str())
    }
    fn code_line(&mut self) -> String {
        let ind = "\t".repeat(self.r.below(4));
        match self.r.below(6) {
            0 => format!("{ind}if {} != nil {{\n", self.ident()),
            1 => format!(
                "{ind}{}, err := {}.{}({}, \"{}\")\n",
                self.ident(),
                self.ident(),
                self.word(),
                self.ident(),
                self.word()
            ),
            2 => format!(
                "{ind}return fmt.Errorf(\"{} {}: %w\", err)\n",
                self.word(),
                self.word()
            ),
            3 => format!("{ind}// {}\n", self.sentence()),
            4 => format!(
                "{ind}def {}_{}(self, {}=None):\n",
                self.word(),
                self.ident(),
                self.ident()
            ),
            _ => format!(
                "{ind}{}[{}] = {{\"{}\": {}, \"{}\": \"{}\"}}\n",
                self.ident(),
                self.r.below(100),
                self.word(),
                self.r.below(100_000),
                self.ident(),
                self.word()
            ),
        }
    }
    fn log_line(&mut self) -> String {
        let lv = *self.r.pick(&["INFO", "DEBUG", "WARN", "ERROR"]);
        let id = hex(&self.r.bytes(8));
        format!(
            "2026-11-{:02}T{:02}:{:02}:{:02}.{:03}Z {lv} [{}] req_id={id} {} latency_ms={}\n",
            1 + self.r.below(28),
            self.r.below(24),
            self.r.below(60),
            self.r.below(60),
            self.r.below(1000),
            self.ident(),
            self.sentence(),
            self.r.below(5000)
        )
    }
    fn env_line(&mut self) -> String {
        let k = format!("{}_{}", self.word(), self.ident()).to_uppercase();
        match self.r.below(4) {
            0 => format!("{k}={}\n", self.r.below(65536)),
            1 => format!(
                "{k}=https://{}.internal.example:{}/{}\n",
                self.word(),
                1000 + self.r.below(9000),
                self.word()
            ),
            2 => format!("{k}={}\n", hex(&self.r.bytes(16))),
            _ => format!(
                "{k}={}\n",
                self.r.pick(&["true", "false", "debug", "production"])
            ),
        }
    }
    fn blob_line(&mut self) -> String {
        let n = 45 + self.r.below(300);
        format!("{}\n", b64(&self.r.bytes(n), false, true))
    }
    fn hit(&mut self) -> Vec<Seg> {
        self.hits += 1;
        let s = self.secrets[self.r.below(self.secrets.len())].clone();
        match *self.r.pick(HIT_FORMS) {
            "json" => {
                let ctx = *self.r.pick(&[
                    "export API_TOKEN=",
                    "Authorization: Bearer ",
                    r#"{"api_key": ""#,
                    "password: ",
                    "  token = ",
                ]);
                vec![(ctx.into(), false), (s, false), ("\n".into(), false)]
            }
            "json_slash" => vec![
                (r#""secret":""#.into(), false),
                (json_escape(&s, true, false), true),
                ("\"\n".into(), false),
            ],
            "json_u" => vec![
                ("key=".into(), false),
                (json_escape(&s, false, true), true),
                ("\n".into(), false),
            ],
            f @ ("b64" | "b64url") => {
                let mut env = String::new();
                for _ in 0..self.r.below(4) {
                    env.push_str(&self.env_line());
                }
                env.push_str(&format!("SECRET_VALUE={s}\n"));
                for _ in 0..self.r.below(4) {
                    env.push_str(&self.env_line());
                }
                vec![
                    ("$ base64 -w0 .env\n".into(), false),
                    (b64(env.as_bytes(), f == "b64url", true), true),
                    ("\n".into(), false),
                ]
            }
            "hex" => vec![
                ("$ printf %s \"$KEY\" | xxd -p -c0\n".into(), false),
                (hex(s.as_bytes()), true),
                ("\n".into(), false),
            ],
            _ => vec![
                (
                    "curl -s 'https://api.example.com/v1/auth?client=cli&token=".into(),
                    false,
                ),
                (url_encode(&s), true),
                ("&x=1'\n".into(), false),
            ],
        }
    }
    fn content(&mut self, n: usize, flavour: usize) -> Vec<Seg> {
        let mut segs = Vec::new();
        let mut total = 0;
        while total < n {
            let l = match flavour {
                0 => {
                    let mut l = self.sentence();
                    if self.r.below(6) == 0 {
                        l.push_str("\n\n");
                    }
                    l
                }
                1 => self.code_line(),
                2 => self.log_line(),
                3 => self.env_line(),
                _ => {
                    if self.r.below(3) == 0 {
                        self.blob_line()
                    } else {
                        self.log_line()
                    }
                }
            };
            total += l.len();
            let roll = self.hit_rate > 0.0 && self.r.f64() < l.len() as f64 * self.hit_rate;
            segs.push((l, false));
            if roll {
                for h in self.hit() {
                    total += h.0.len();
                    segs.push(h);
                }
            }
        }
        segs
    }
    fn str(&mut self, segs: Vec<Seg>) {
        self.buf.push('"');
        for (s, raw) in segs {
            if raw {
                self.buf.push_str(&s);
            } else {
                self.buf.push_str(&json_escape(&s, false, false));
            }
        }
        self.buf.push('"');
    }
}

/// A request body of about `target` bytes. With `secrets` non-empty, about one hit per 4 KiB.
/// Returns the body and the number of hits inserted.
pub fn gen_body(seed: u64, target: usize, secrets: &[String]) -> (Vec<u8>, usize) {
    let mut g = Body {
        r: Rng::new(seed),
        words: WORDS.split(' ').collect(),
        idents: IDENTS.split(' ').collect(),
        secrets,
        hit_rate: if secrets.is_empty() {
            0.0
        } else {
            1.0 / 4096.0
        },
        buf: String::with_capacity(target + 65536),
        hits: 0,
    };
    g.buf.push_str(r#"{"model":"claude-sonnet-4-5","max_tokens":32000,"stream":true,"system":[{"type":"text","text":"#);
    let c = g.content(6000, 0);
    g.str(c);
    g.buf
        .push_str(r#","cache_control":{"type":"ephemeral"}}],"tools":["#);
    for (i, name) in ["Bash", "Read", "Edit", "Grep"].iter().enumerate() {
        if i > 0 {
            g.buf.push(',');
        }
        g.buf
            .push_str(&format!(r#"{{"name":"{name}","description":"#));
        let s = format!("{}{}", g.sentence(), g.sentence());
        g.str(vec![(s, false)]);
        g.buf.push_str(r#","input_schema":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}"#);
    }
    g.buf.push_str(r#"],"messages":["#);
    let mut first = true;
    while g.buf.len() < target.saturating_sub(2048) {
        if !first {
            g.buf.push(',');
        }
        first = false;
        g.buf
            .push_str(r#"{"role":"user","content":[{"type":"text","text":"#);
        let n = 100 + g.r.below(1500);
        let c = g.content(n, 0);
        g.str(c);
        g.buf.push_str("}]},");
        let id = format!("toolu_01{}", g.r.string(BASE62, 22));
        g.buf
            .push_str(r#"{"role":"assistant","content":[{"type":"text","text":"#);
        let n = 100 + g.r.below(800);
        let c = g.content(n, 0);
        g.str(c);
        g.buf.push_str(&format!(
            r#"}},{{"type":"tool_use","id":"{id}","name":"Bash","input":{{"command":"#
        ));
        let n = 40 + g.r.below(300);
        let c = g.content(n, 3);
        g.str(c);
        g.buf.push_str("}}]},");
        g.buf.push_str(&format!(
            r#"{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"{id}","content":"#
        ));
        let n = 500 + g.r.below(12000);
        let f = 1 + g.r.below(4);
        let c = g.content(n, f);
        g.str(c);
        g.buf.push_str("}]}");
    }
    g.buf.push_str("]}");
    (g.buf.into_bytes(), g.hits)
}

/// Prose of about `n` bytes with `placeholders` sprinkled in, for restore benchmarks.
pub fn gen_stream_text(seed: u64, n: usize, placeholders: &[String], every: usize) -> String {
    let mut g = Body {
        r: Rng::new(seed),
        words: WORDS.split(' ').collect(),
        idents: IDENTS.split(' ').collect(),
        secrets: &[],
        hit_rate: 0.0,
        buf: String::new(),
        hits: 0,
    };
    let mut s = String::with_capacity(n + 128);
    let mut since = 0;
    while s.len() < n {
        let l = g.sentence();
        since += l.len();
        s.push_str(&l);
        if !placeholders.is_empty() && since >= every {
            since = 0;
            s.push_str(g.r.pick(placeholders));
            s.push(' ');
        }
    }
    s
}

/// Realistic chunk sizes for streamed deltas: mostly 1 to 40 bytes, occasionally larger.
pub fn gen_chunks(seed: u64, total: usize) -> Vec<usize> {
    let mut r = Rng::new(seed);
    let mut v = Vec::new();
    let mut left = total;
    while left > 0 {
        let n = if r.below(20) == 0 {
            40 + r.below(200)
        } else {
            1 + r.below(40)
        };
        let n = n.min(left);
        v.push(n);
        left -= n;
    }
    v
}
