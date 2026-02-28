use std::{marker::PhantomData, sync::Arc};

use anyhow::Context;

use crate::{
    adapter_apk::ApkReader, adapter_deb::DebReader, domain::ApkRepositoryService,
    domain::AptRepositoryService,
};

mod adapter_apk;
mod adapter_deb;
mod adapter_github;
mod adapter_http_server;
mod adapter_pgp;
mod adapter_rsa;
mod adapter_sqlite;
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
    rsa_signer: adapter_rsa::Config,
    sqlite: adapter_sqlite::Config,
    worker: adapter_worker::Config,
}

impl Config {
    pub fn from_path(path: impl Into<std::path::PathBuf>) -> anyhow::Result<Self> {
        let content = std::fs::read(path.into()).context("unable to read file")?;
        Ok(toml::from_slice(&content)?)
    }

    pub async fn build(self) -> anyhow::Result<Application> {
        let storage = self.sqlite.build().await?;
        let github = self.github.build()?;
        let config = Arc::from(self.config);
        let apt_repository_service = AptRepositoryService {
            package_source: github.clone(),
            release_storage: storage.clone(),
            config: config.clone(),
            clock: PhantomData::<chrono::Utc>,
            deb_extractor: DebReader,
            pgp_cipher: self.pgp_cipher.build()?,
            release_tracker: storage.clone(),
            package_store: storage.clone(),
        };
        let apk_repository_service = ApkRepositoryService {
            config,
            package_source: github.clone(),
            apk_extractor: ApkReader,
            rsa_signer: self.rsa_signer.build()?,
            release_tracker: storage.clone(),
            apk_package_store: storage.clone(),
        };
        Ok(Application {
            github,
            http_server: self
                .http_server
                .builder()?
                .with_apt_repository(apt_repository_service.clone())
                .with_apk_repository(apk_repository_service)
                .with_health_checker(storage)
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
    #[expect(unused, reason = "preparation")]
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
