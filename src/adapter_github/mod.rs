use std::{borrow::Cow, sync::Arc};

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest_middleware::Extension;
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use reqwest_tracing::OtelPathNames;

pub(crate) mod entity;
mod method;
mod middleware;
mod releases;

#[derive(serde::Deserialize)]
pub struct Config {
    #[serde(default = "Config::default_base_url")]
    base_url: Cow<'static, str>,
    #[serde(default = "Config::default_max_retry")]
    max_retry: u32,
    #[serde(default = "Config::default_timeout")]
    timeout: u64,
    #[serde(default)]
    token: Option<String>,
}

impl Config {
    pub const fn default_base_url() -> Cow<'static, str> {
        Cow::Borrowed("https://api.github.com")
    }
    pub const fn default_max_retry() -> u32 {
        5
    }
    pub const fn default_timeout() -> u64 {
        60
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
            .timeout(std::time::Duration::from_secs(self.timeout))
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()?;
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(self.max_retry);
        let inner = reqwest_middleware::ClientBuilder::new(client)
            // Trace HTTP requests. See the tracing crate to make use of these traces.
            .with(middleware::TracingMiddleware)
            // Retry failed requests.
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .with_init(Extension(OtelPathNames::known_paths([
                "/repos/{repo_owner}/{repo_name}/releases",
                "/{repo_owner}/{repo_name}/releases/download/{release}/{filename}",
            ])?))
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
