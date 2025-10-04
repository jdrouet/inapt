use std::{borrow::Cow, sync::Arc};

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use reqwest_tracing::TracingMiddleware;

pub(crate) mod entity;
mod method;
mod releases;

pub struct Config {
    base_url: Cow<'static, str>,
    max_retry: u32,
    token: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            base_url: crate::with_env_or("GITHUB_BASE_URL", "https://api.github.com"),
            token: crate::maybe_env("GITHUB_TOKEN"),
            max_retry: crate::with_env_as_or("GITHUB_MAX_RETRY", 5)?,
        })
    }

    pub fn build(self) -> anyhow::Result<Client> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/vnd.github+json"),
        );
        if let Some(token) = self.token {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))?,
            );
        }
        headers.insert("User-Agent", HeaderValue::from_static("inapt"));
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(20))
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()?;
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(self.max_retry);
        let inner = reqwest_middleware::ClientBuilder::new(client)
            // Trace HTTP requests. See the tracing crate to make use of these traces.
            .with(TracingMiddleware::default())
            // Retry failed requests.
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        let base_url = Arc::from(self.base_url);
        Ok(Client { base_url, inner })
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    base_url: Arc<str>,
    inner: reqwest_middleware::ClientWithMiddleware,
}
