use std::{marker::PhantomData, sync::Arc};

use anyhow::Context;

use crate::{adapter_deb::DebReader, domain::AptRepositoryService};

mod adapter_deb;
mod adapter_github;
mod adapter_http_server;
mod adapter_pgp;
mod adapter_storage;
mod adapter_worker;
mod domain;

pub mod tracing;

#[derive(serde::Deserialize)]
pub struct Config {
    #[serde(rename = "core")]
    config: domain::Config,
    github: adapter_github::Config,
    http_server: adapter_http_server::Config,
    pgp_cipher: adapter_pgp::Config,
    storage: adapter_storage::Config,
    worker: adapter_worker::Config,
}

impl Config {
    pub fn from_path(path: impl Into<std::path::PathBuf>) -> anyhow::Result<Self> {
        let content = std::fs::read(path.into()).context("unable to read file")?;
        Ok(toml::from_slice(&content)?)
    }

    pub fn build(self) -> anyhow::Result<Application> {
        let storage = self.storage.build()?;
        let github = self.github.build()?;
        let apt_repository_service = AptRepositoryService {
            package_source: github.clone(),
            release_storage: storage.clone(),
            config: Arc::from(self.config),
            clock: PhantomData::<chrono::Utc>,
            deb_extractor: DebReader,
            pgp_cipher: self.pgp_cipher.build()?,
            release_tracker: storage.clone(),
            package_store: storage,
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
