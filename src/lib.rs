use std::{borrow::Cow, marker::PhantomData, sync::Arc};

use anyhow::Context;

use crate::{adapter_deb::DebReader, domain::AptRepositoryService};

mod adapter_deb;
mod adapter_github;
mod adapter_http_server;
mod adapter_storage;
mod adapter_worker;
mod domain;

fn maybe_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn with_env_or<T>(name: &str, default_value: T) -> Cow<'static, str>
where
    T: Into<Cow<'static, str>>,
{
    std::env::var(name)
        .ok()
        .map(Cow::Owned)
        .unwrap_or_else(|| default_value.into())
}

fn with_env_as_or<T>(name: &str, default_value: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    let Ok(value) = std::env::var(name) else {
        return Ok(default_value);
    };
    value
        .parse::<T>()
        .with_context(|| format!("unable to parse value from {name:?}"))
}

fn with_env_as_many(name: &str, delim: &str) -> Vec<String> {
    let Ok(value) = std::env::var(name) else {
        tracing::warn!("no repository configured");
        return Vec::default();
    };
    value
        .split(delim)
        .map(|item| item.trim().to_string())
        .collect()
}

pub struct Config {
    config: domain::Config,
    github: adapter_github::Config,
    http_server: adapter_http_server::Config,
    storage: adapter_storage::Config,
    worker: adapter_worker::Config,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Ok(Self {
            config: domain::Config::from_env()?,
            github: adapter_github::Config::from_env()?,
            http_server: adapter_http_server::Config::from_env()?,
            storage: adapter_storage::Config::from_env()?,
            worker: adapter_worker::Config::from_env()?,
        })
    }

    pub fn build(self) -> anyhow::Result<Application> {
        let release_storage = self.storage.build()?;
        let github = self.github.build()?;
        let apt_repository_service = AptRepositoryService {
            package_source: github.clone(),
            release_storage,
            config: Arc::from(self.config),
            clock: PhantomData::<chrono::Utc>,
            deb_extractor: DebReader,
        };
        Ok(Application {
            github,
            http_server: self
                .http_server
                .builder()?
                .with_apt_repository(apt_repository_service.clone())
                .build()?,
            worker: self
                .worker
                .builder()
                .with_apt_repository(apt_repository_service)
                .build()?,
        })
    }
}

pub struct Application {
    #[allow(unused, reason = "preparation")]
    github: adapter_github::Client,
    http_server: adapter_http_server::Server,
    worker: adapter_worker::Worker,
}

impl Application {
    pub async fn run(self) -> anyhow::Result<()> {
        self.http_server.run().await?;
        self.worker.shutdown().await
    }
}
