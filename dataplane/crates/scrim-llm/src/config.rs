// SPDX-License-Identifier: AGPL-3.0-only

//! Proxy configuration.
//!
//! The control plane owns the configuration file, environment and flags (configuration spec);
//! the data plane receives the resolved values. Field names follow the canonical keys under
//! `proxy.` in kebab case, so a YAML or JSON fragment of the effective configuration
//! deserialises directly.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::codec::Api;

/// Which provider family a route serves. The API within the family follows from the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// Anthropic: Messages on paths ending in `/messages` or `/messages/count_tokens`.
    Anthropic,
    /// `OpenAI`: Chat Completions on `/chat/completions`, Responses on `/responses` and
    /// `/responses/compact`.
    Openai,
    /// Google Gemini API: `generateContent`, `streamGenerateContent` and `countTokens` on
    /// paths ending in `:<method>`.
    Gemini,
    /// Amazon Bedrock runtime: Anthropic Messages bodies on `/model/{id}/invoke` and
    /// `/model/{id}/invoke-with-response-stream`, Converse on `/model/{id}/converse` and
    /// `/model/{id}/converse-stream`, and the Anthropic body inside `/model/{id}/count-tokens`.
    Bedrock,
}

impl Provider {
    /// The provider's name in policy rules (`provider`): `anthropic`, `openai` or `gemini`.
    pub fn name(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Openai => "openai",
            Provider::Gemini => "gemini",
            Provider::Bedrock => "bedrock",
        }
    }

    /// Query parameters that carry the agent's own provider credential (the Gemini API's
    /// `key`). They are forwarded untouched, like the credential headers in
    /// [`crate::head::PASSTHROUGH`], and masked in captures.
    pub fn query_credentials(self) -> &'static [&'static str] {
        match self {
            Provider::Gemini => &["key"],
            Provider::Anthropic | Provider::Openai | Provider::Bedrock => &[],
        }
    }

    /// The API a request speaks, from its method and the path after the route prefix.
    pub fn api_for(self, method: &http::Method, path: &str) -> Api {
        if method != http::Method::POST {
            return Api::Generic;
        }
        let path = path.trim_end_matches('/');
        match self {
            Provider::Anthropic
                if path.ends_with("/messages") || path.ends_with("/messages/count_tokens") =>
            {
                Api::AnthropicMessages
            }
            Provider::Openai if path.ends_with("/chat/completions") => Api::OpenAiChat,
            Provider::Openai
                if path.ends_with("/responses") || path.ends_with("/responses/compact") =>
            {
                Api::OpenAiResponses
            }
            Provider::Gemini if crate::codec::gemini::is_gemini_method(path) => Api::Gemini,
            Provider::Bedrock => match bedrock_action(path) {
                Some("invoke" | "invoke-with-response-stream") => Api::AnthropicMessages,
                Some("converse" | "converse-stream") => Api::BedrockConverse,
                _ => Api::Generic,
            },
            _ => Api::Generic,
        }
    }
}

/// The action of a Bedrock runtime path, `/model/{modelId}/{action}`. The model id is one
/// segment (percent-encoded on the wire when it holds `/` or `:`).
pub fn bedrock_action(path: &str) -> Option<&str> {
    let rest = path.trim_end_matches('/');
    let (head, action) = rest.rsplit_once('/')?;
    let (head, model) = head.rsplit_once('/')?;
    let at_model = head == "/model" || head.ends_with("/model");
    (at_model && !model.is_empty()).then_some(action)
}

/// What to do when a chained upstream cannot be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnUnavailable {
    /// Refuse the request (default).
    #[default]
    Fail,
    /// Send the already-redacted request to the provider directly and audit the skip.
    Direct,
}

/// A chained upstream, such as a context-compression proxy. It receives the redacted request in
/// place of the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ChainConfig {
    /// Base URL of the chained proxy (`http` or `https`).
    pub url: String,
    /// Behaviour when it is unreachable.
    #[serde(default)]
    pub on_unavailable: OnUnavailable,
}

/// One route: requests whose path starts with `prefix` go to `upstream`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RouteConfig {
    /// Route name, used in audit entries and errors.
    pub name: String,
    /// Path prefix, matched on whole segments (`/anthropic` matches `/anthropic/v1/messages`,
    /// not `/anthropic2`).
    pub prefix: String,
    /// Provider base URL. The path after the prefix is appended.
    pub upstream: String,
    /// Provider family.
    pub provider: Provider,
    /// Remove the prefix before appending the path to the upstream (default `true`).
    #[serde(default = "yes")]
    pub strip_prefix: bool,
    /// Optional chained upstream.
    #[serde(default)]
    pub chain: Option<ChainConfig>,
    /// Provider host names this route serves when traffic arrives through the forward proxy
    /// or a transparent listener, with an origin-form path and no prefix (for example
    /// `api.anthropic.com`). Matched case-insensitively on the host alone.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Authentication the route adds itself with credentials scrim holds, replacing whatever
    /// the agent sent (cloud provider routes). A route with authentication cannot be chained.
    #[serde(default)]
    pub auth: Option<crate::auth::AuthConfig>,
}

fn yes() -> bool {
    true
}

/// Byte limits. The memory held per stream is at most
/// `max-event + open blocks * (placeholder max length - 1) + max-buffered-tool-input`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct Limits {
    /// Largest request body accepted; larger bodies are refused with 413 (`proxy.limits.max-request-body`).
    pub max_request_body: usize,
    /// Largest non-streaming JSON response restored in memory; larger ones pass through
    /// unresolved (`proxy.limits.max-response-body`).
    pub max_response_body: usize,
    /// Largest single SSE event parsed; a larger one passes through unresolved
    /// (`proxy.limits.max-event`).
    pub max_event: usize,
    /// Tool-call arguments held per stream for policies that need complete arguments
    /// (`proxy.limits.max-buffered-tool-input`).
    pub max_buffered_tool_input: usize,
    /// Bodies at least this large are redacted on the blocking pool instead of the I/O thread
    /// (`proxy.limits.offload-threshold`).
    pub offload_threshold: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_body: 32 << 20,
            max_response_body: 32 << 20,
            max_event: 16 << 20,
            max_buffered_tool_input: 1 << 20,
            offload_threshold: 1 << 20,
        }
    }
}

/// Capture mode (leak-assurance spec): every outgoing request and the response as received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CaptureConfig {
    /// Directory; created with mode 0700 if missing, refused if accessible to others.
    pub dir: PathBuf,
    /// Delete captures older than this many seconds (`proxy.capture.retention`, default 7 days).
    #[serde(default = "week")]
    pub retention_secs: u64,
}

fn week() -> u64 {
    7 * 24 * 3600
}

/// Trust roots for upstream TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Roots {
    /// Mozilla roots compiled in (webpki-roots).
    Webpki,
    /// The operating system's store.
    Native,
    /// Both (default).
    #[default]
    Both,
}

/// Upstream TLS settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Root set.
    pub roots: Roots,
    /// Extra PEM bundle to trust, for corporate proxies and tests.
    pub extra_ca_file: Option<PathBuf>,
}

/// Everything the proxy needs besides the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ProxyConfig {
    /// Routes; longest matching prefix wins.
    pub routes: Vec<RouteConfig>,
    /// Limits.
    pub limits: Limits,
    /// Capture mode, off when absent.
    pub capture: Option<CaptureConfig>,
    /// Upstream TLS.
    pub tls: TlsConfig,
    /// Upstream connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Idle upstream connections kept per host.
    pub pool_max_idle_per_host: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            routes: default_routes(),
            limits: Limits::default(),
            capture: None,
            tls: TlsConfig::default(),
            connect_timeout_ms: 10_000,
            pool_max_idle_per_host: 32,
        }
    }
}

impl ProxyConfig {
    /// Connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }
}

/// `/anthropic` to `https://api.anthropic.com`, `/openai` to `https://api.openai.com` and
/// `/gemini` to `https://generativelanguage.googleapis.com`.
///
/// Agents use base URLs such as `ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic`,
/// `OPENAI_BASE_URL=http://127.0.0.1:9790/openai/v1` and
/// `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:9790/gemini`.
pub fn default_routes() -> Vec<RouteConfig> {
    vec![
        RouteConfig {
            name: "anthropic".into(),
            prefix: "/anthropic".into(),
            upstream: "https://api.anthropic.com".into(),
            provider: Provider::Anthropic,
            strip_prefix: true,
            chain: None,
            hosts: vec!["api.anthropic.com".into()],
            auth: None,
        },
        RouteConfig {
            name: "openai".into(),
            prefix: "/openai".into(),
            upstream: "https://api.openai.com".into(),
            provider: Provider::Openai,
            strip_prefix: true,
            chain: None,
            hosts: vec!["api.openai.com".into()],
            auth: None,
        },
        RouteConfig {
            name: "gemini".into(),
            prefix: "/gemini".into(),
            upstream: "https://generativelanguage.googleapis.com".into(),
            provider: Provider::Gemini,
            strip_prefix: true,
            chain: None,
            hosts: vec!["generativelanguage.googleapis.com".into()],
            auth: None,
        },
        // Codex signed in with a ChatGPT account: the Responses API at
        // /backend-api/codex/responses, other backend paths redacted as generic JSON.
        RouteConfig {
            name: "chatgpt".into(),
            prefix: "/chatgpt".into(),
            upstream: "https://chatgpt.com".into(),
            provider: Provider::Openai,
            strip_prefix: true,
            chain: None,
            hosts: vec!["chatgpt.com".into()],
            auth: None,
        },
        // The same session's traffic on ab.chatgpt.com. Its API shape is not documented; no path
        // there is a Responses call, so every body is redacted as generic JSON.
        RouteConfig {
            name: "chatgpt-ab".into(),
            prefix: "/chatgpt-ab".into(),
            upstream: "https://ab.chatgpt.com".into(),
            provider: Provider::Openai,
            strip_prefix: true,
            chain: None,
            hosts: vec!["ab.chatgpt.com".into()],
            auth: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_detection() {
        let p = http::Method::POST;
        assert_eq!(
            Provider::Anthropic.api_for(&p, "/v1/messages"),
            Api::AnthropicMessages
        );
        assert_eq!(
            Provider::Anthropic.api_for(&p, "/v1/messages/count_tokens"),
            Api::AnthropicMessages
        );
        assert_eq!(
            Provider::Anthropic.api_for(&p, "/v1/complete"),
            Api::Generic
        );
        assert_eq!(
            Provider::Anthropic.api_for(&http::Method::GET, "/v1/messages"),
            Api::Generic
        );
        assert_eq!(
            Provider::Openai.api_for(&p, "/v1/chat/completions"),
            Api::OpenAiChat
        );
        assert_eq!(
            Provider::Openai.api_for(&p, "/v1/responses"),
            Api::OpenAiResponses
        );
        assert_eq!(
            Provider::Openai.api_for(&p, "/v1/responses/compact"),
            Api::OpenAiResponses
        );
        assert_eq!(Provider::Openai.api_for(&p, "/v1/embeddings"), Api::Generic);
        assert_eq!(
            Provider::Gemini.api_for(&p, "/v1beta/models/gemini-2.5-pro:generateContent"),
            Api::Gemini
        );
        assert_eq!(
            Provider::Gemini.api_for(&p, "/v1beta/models/gemini-2.5-pro:streamGenerateContent"),
            Api::Gemini
        );
        assert_eq!(
            Provider::Gemini.api_for(&p, "/v1beta/models/gemini-2.5-pro:countTokens"),
            Api::Gemini
        );
        assert_eq!(
            Provider::Gemini.api_for(&p, "/v1beta/models/text-embedding-004:embedContent"),
            Api::Generic
        );
        assert_eq!(
            Provider::Gemini.api_for(
                &http::Method::GET,
                "/v1beta/models/gemini-2.5-pro:generateContent"
            ),
            Api::Generic
        );
        assert_eq!(
            Provider::Openai.api_for(&p, "/v1beta/models/gemini-2.5-pro:generateContent"),
            Api::Generic
        );
        // ChatGPT backend (Codex signed in with ChatGPT).
        assert_eq!(
            Provider::Openai.api_for(&p, "/backend-api/codex/responses"),
            Api::OpenAiResponses
        );
        assert_eq!(
            Provider::Openai.api_for(&p, "/backend-api/codex/analytics-events/events"),
            Api::Generic
        );
    }

    #[test]
    fn bedrock_paths() {
        let p = http::Method::POST;
        let b = Provider::Bedrock;
        for (path, api) in [
            (
                "/model/us.anthropic.claude-x-v1%3A0/invoke",
                Api::AnthropicMessages,
            ),
            (
                "/model/m/invoke-with-response-stream",
                Api::AnthropicMessages,
            ),
            (
                "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Aapplication-inference-profile%2Fx/converse",
                Api::BedrockConverse,
            ),
            ("/model/m/converse-stream", Api::BedrockConverse),
            ("/model/m/count-tokens", Api::Generic),
            ("/model//invoke", Api::Generic),
            ("/invoke", Api::Generic),
            ("/guardrail/g/version/1/apply", Api::Generic),
        ] {
            assert_eq!(b.api_for(&p, path), api, "{path}");
        }
        assert_eq!(
            bedrock_action("/model/m/count-tokens"),
            Some("count-tokens")
        );
        assert_eq!(
            b.api_for(&http::Method::GET, "/model/m/invoke"),
            Api::Generic
        );
    }

    #[test]
    fn deserialises_kebab_case() {
        let c: ProxyConfig = serde_json::from_str(
            r#"{"routes":[{"name":"a","prefix":"/a","upstream":"http://x","provider":"anthropic",
                "chain":{"url":"http://c","on-unavailable":"direct"}}],
                "limits":{"max-event":1024},"capture":{"dir":"/tmp/c"},"connect-timeout-ms":5}"#,
        )
        .unwrap();
        assert_eq!(
            c.routes[0].chain.as_ref().unwrap().on_unavailable,
            OnUnavailable::Direct
        );
        assert!(c.routes[0].strip_prefix);
        assert_eq!(c.limits.max_event, 1024);
        assert_eq!(
            c.limits.max_request_body,
            Limits::default().max_request_body
        );
        assert_eq!(c.capture.unwrap().retention_secs, 7 * 24 * 3600);
        assert!(serde_json::from_str::<ProxyConfig>(r#"{"bogus":1}"#).is_err());
    }
}
