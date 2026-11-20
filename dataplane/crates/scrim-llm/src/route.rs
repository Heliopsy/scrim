// SPDX-License-Identifier: AGPL-3.0-only

//! Routing by path prefix.

use crate::config::{ChainConfig, Provider, RouteConfig};

/// Invalid route configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// The prefix does not start with `/`.
    #[error("route {0}: prefix must start with '/'")]
    Prefix(String),
    /// The upstream or chain URL is not an absolute http(s) URL.
    #[error("route {0}: {1} is not an absolute http or https URL")]
    Url(String, &'static str),
    /// Two routes claim the same provider host.
    #[error("routes {0} and {1} both claim host {2}")]
    DuplicateHost(String, String, String),
    /// Two routes share a prefix.
    #[error("routes {0} and {1} share the same prefix")]
    Duplicate(String, String),
}

/// A validated route.
#[derive(Debug, Clone)]
pub struct Route {
    /// Name.
    pub name: String,
    prefix: String,
    /// Provider base URI.
    pub upstream: http::Uri,
    /// Provider family.
    pub provider: Provider,
    strip_prefix: bool,
    /// Chained upstream and its base URI.
    pub chain: Option<(ChainConfig, http::Uri)>,
    hosts: Vec<String>,
}

fn parse_base(name: &str, url: &str, what: &'static str) -> Result<http::Uri, RouteError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| RouteError::Url(name.into(), what))?;
    match (uri.scheme_str(), uri.authority()) {
        (Some("http" | "https"), Some(_)) if uri.query().is_none() => Ok(uri),
        _ => Err(RouteError::Url(name.into(), what)),
    }
}

impl Route {
    /// The upstream URI for a request path (after the prefix) and query.
    pub fn target(base: &http::Uri, rest: &str, query: Option<&str>) -> http::Uri {
        let base_path = base.path().trim_end_matches('/');
        let mut pq = String::with_capacity(base_path.len() + rest.len() + 16);
        pq.push_str(base_path);
        if !rest.starts_with('/') {
            pq.push('/');
        }
        pq.push_str(rest);
        if let Some(q) = query {
            pq.push('?');
            pq.push_str(q);
        }
        let mut parts = base.clone().into_parts();
        // The path came from a valid request URI and the base from a validated URI.
        parts.path_and_query = pq.parse().ok();
        http::Uri::from_parts(parts).unwrap_or_else(|_| base.clone())
    }
}

/// Routes ordered for longest-prefix matching.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Vec<Route>,
}

impl RouteTable {
    /// Validates and orders `configs`.
    pub fn new(configs: &[RouteConfig]) -> Result<Self, RouteError> {
        let mut routes = Vec::with_capacity(configs.len());
        for c in configs {
            if !c.prefix.starts_with('/') {
                return Err(RouteError::Prefix(c.name.clone()));
            }
            let prefix = c.prefix.trim_end_matches('/').to_string();
            if let Some(other) = routes.iter().find(|r: &&Route| r.prefix == prefix) {
                return Err(RouteError::Duplicate(other.name.clone(), c.name.clone()));
            }
            let upstream = parse_base(&c.name, &c.upstream, "upstream")?;
            let chain = match &c.chain {
                Some(ch) => Some((ch.clone(), parse_base(&c.name, &ch.url, "chain url")?)),
                None => None,
            };
            routes.push(Route {
                name: c.name.clone(),
                prefix,
                upstream,
                provider: c.provider,
                strip_prefix: c.strip_prefix,
                chain,
                hosts: c.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
            });
        }
        for (i, a) in routes.iter().enumerate() {
            for b in &routes[i + 1..] {
                if let Some(h) = a.hosts.iter().find(|h| b.hosts.contains(h)) {
                    return Err(RouteError::DuplicateHost(
                        a.name.clone(),
                        b.name.clone(),
                        h.clone(),
                    ));
                }
            }
        }
        routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
        Ok(Self { routes })
    }

    /// Finds the route that claims provider host `host` (forward-proxy and transparent
    /// traffic). The whole request path is forwarded.
    pub fn find_host(&self, host: &str) -> Option<&Route> {
        let host = host.trim_end_matches('.');
        self.routes
            .iter()
            .find(|r| r.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
    }

    /// Finds the route for `path` and returns it with the path to forward.
    pub fn find<'p>(&self, path: &'p str) -> Option<(&Route, &'p str)> {
        self.routes.iter().find_map(|r| {
            let rest = if r.prefix.is_empty() {
                Some(path)
            } else {
                path.strip_prefix(r.prefix.as_str())
            }?;
            if !(rest.is_empty() || rest.starts_with('/')) {
                return None;
            }
            Some((r, if r.strip_prefix { rest } else { path }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_routes;

    #[test]
    fn longest_prefix_on_segments() {
        let mut cfg = default_routes();
        cfg.push(RouteConfig {
            name: "special".into(),
            prefix: "/anthropic/special".into(),
            upstream: "http://127.0.0.1:1/base/".into(),
            provider: Provider::Anthropic,
            strip_prefix: true,
            chain: None,
            hosts: vec![],
        });
        let t = RouteTable::new(&cfg).unwrap();
        let (r, rest) = t.find("/anthropic/v1/messages").unwrap();
        assert_eq!((r.name.as_str(), rest), ("anthropic", "/v1/messages"));
        let (r, rest) = t.find("/anthropic/special/v1/messages").unwrap();
        assert_eq!((r.name.as_str(), rest), ("special", "/v1/messages"));
        assert!(t.find("/anthropicx/v1/messages").is_none());
        assert!(t.find("/v1/messages").is_none());
        let u = Route::target(&r.upstream, rest, Some("beta=true"));
        assert_eq!(
            u.to_string(),
            "http://127.0.0.1:1/base/v1/messages?beta=true"
        );
    }

    #[test]
    fn no_strip_keeps_path() {
        let cfg = vec![RouteConfig {
            name: "root".into(),
            prefix: "/v1/messages".into(),
            upstream: "https://api.anthropic.com".into(),
            provider: Provider::Anthropic,
            strip_prefix: false,
            chain: None,
            hosts: vec![],
        }];
        let t = RouteTable::new(&cfg).unwrap();
        assert_eq!(t.find("/v1/messages").unwrap().1, "/v1/messages");
    }

    #[test]
    fn host_routes() {
        let t = RouteTable::new(&default_routes()).unwrap();
        assert_eq!(t.find_host("API.Anthropic.com").unwrap().name, "anthropic");
        assert_eq!(t.find_host("api.openai.com.").unwrap().name, "openai");
        assert!(t.find_host("example.com").is_none());
        let mut c = default_routes();
        c[1].hosts = vec!["api.anthropic.com".into()];
        assert!(matches!(
            RouteTable::new(&c),
            Err(RouteError::DuplicateHost(..))
        ));
    }

    #[test]
    fn validation() {
        let mut c = default_routes();
        c[0].prefix = "anthropic".into();
        assert!(matches!(RouteTable::new(&c), Err(RouteError::Prefix(_))));
        let mut c = default_routes();
        c[0].upstream = "ftp://x".into();
        assert!(matches!(RouteTable::new(&c), Err(RouteError::Url(..))));
        let mut c = default_routes();
        c[1].prefix = "/anthropic/".into();
        assert!(matches!(
            RouteTable::new(&c),
            Err(RouteError::Duplicate(..))
        ));
        let mut c = default_routes();
        c[0].chain = Some(ChainConfig {
            url: "not a url".into(),
            on_unavailable: crate::config::OnUnavailable::default(),
        });
        assert!(RouteTable::new(&c).is_err());
    }
}
