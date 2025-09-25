use std::sync::Arc;

use anyhow::Context;

use crate::domain::AptRepositoryService;

mod adapter_github;
mod adapter_http_server;
mod adapter_worker;
mod domain;

fn with_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("unable to find {name:?}"))
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

pub struct Config {
    github: adapter_github::Config,
    http_server: adapter_http_server::Config,
    worker: adapter_worker::Config,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Ok(Self {
            github: adapter_github::Config::from_env()?,
            http_server: adapter_http_server::Config::from_env()?,
            worker: adapter_worker::Config::from_env()?,
        })
    }

    pub fn build(self) -> anyhow::Result<Application> {
        let github = self.github.build()?;
        let apt_repository_service = AptRepositoryService {
            package_source: github.clone(),
            repositories: Arc::from(["jdrouet/mrml".to_string(), "helix-editor/helix".to_string()]),
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
