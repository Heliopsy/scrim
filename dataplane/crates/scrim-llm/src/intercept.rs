// SPDX-License-Identifier: AGPL-3.0-only

//! Forward-proxy integration: model provider hosts reached through the tool proxy
//! (`HTTPS_PROXY`) are handed to this crate's engine.
//!
//! The tool proxy (`scrim-toolproxy`) terminates `CONNECT` with scrim's CA and asks its
//! [`InterceptHandler`] whether it owns the destination. [`LlmIntercept`] claims every host listed
//! in a route's [`hosts`](crate::config::RouteConfig::hosts) and runs the request through
//! [`Proxy::handle_for_host`]: the same redaction, guard, capture, chaining and restore as the
//! base-URL listener. Wiring in the data plane binary:
//!
//! ```ignore
//! let llm = Arc::new(scrim_llm::Proxy::new(cfg, snapshots, audit)?);
//! let tools = scrim_toolproxy::ToolProxy::builder()
//!     .intercept(Arc::new(scrim_llm::intercept::LlmIntercept::new(llm.clone())))
//!     .build()?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{Request, Response};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use scrim_toolproxy::{Destination, InterceptHandler};

use crate::body::ProxyBody;
use crate::proxy::Proxy;

/// Hands provider hosts from the tool proxy to the LLM proxy.
#[derive(Debug, Clone)]
pub struct LlmIntercept {
    proxy: Arc<Proxy>,
}

impl LlmIntercept {
    /// Wraps the LLM proxy.
    pub fn new(proxy: Arc<Proxy>) -> Self {
        Self { proxy }
    }
}

impl InterceptHandler for LlmIntercept {
    fn claims(&self, dest: &Destination) -> bool {
        self.proxy.claims_host(&dest.host)
    }

    fn handle(
        &self,
        dest: Destination,
        req: Request<scrim_toolproxy::ProxyBody>,
    ) -> Pin<Box<dyn Future<Output = Response<scrim_toolproxy::ProxyBody>> + Send>> {
        let proxy = self.proxy.clone();
        // A concrete error type keeps the future provably Send (a `Box<dyn Error>` error type
        // trips a higher-ranked lifetime limitation in the compiler).
        let req = req.map(Incoming);
        Box::pin(async move {
            let resp: Response<ProxyBody> = proxy.handle_for_host(&dest.host, req).await;
            resp
        })
    }
}

/// The tool proxy's request body with a concrete error type.
struct Incoming(scrim_toolproxy::ProxyBody);

impl Body for Incoming {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        Pin::new(&mut self.0)
            .poll_frame(cx)
            .map(|f| f.map(|r| r.map_err(std::io::Error::other)))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}
