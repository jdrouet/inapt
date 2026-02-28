use std::time::Duration;

use anyhow::Context;

#[derive(serde::Deserialize)]
pub struct Config {
    #[serde(default = "Config::default_interval")]
    interval: u64,
}

impl Config {
    pub const fn default_interval() -> u64 {
        60 * 60 * 12 // 12h
    }

    pub fn builder<AR, APK>(self) -> WorkerBuilder<AR, APK> {
        WorkerBuilder {
            apt_repository: None,
            apk_repository: None,
            interval: Duration::from_secs(self.interval),
        }
    }
}

pub struct WorkerBuilder<AR, APK> {
    apt_repository: Option<AR>,
    apk_repository: Option<APK>,
    interval: Duration,
}

impl<AR, APK> WorkerBuilder<AR, APK>
where
    AR: crate::domain::prelude::AptRepositoryWriter,
    APK: crate::domain::prelude::ApkRepositoryWriter,
{
    pub fn with_apt_repository(self, service: AR) -> Self {
        Self {
            apt_repository: Some(service),
            ..self
        }
    }

    pub fn with_apk_repository(self, service: APK) -> Self {
        Self {
            apk_repository: Some(service),
            ..self
        }
    }

    pub fn build(self) -> anyhow::Result<Worker> {
        let runner = Runner {
            apt_repository: self
                .apt_repository
                .ok_or_else(|| anyhow::anyhow!("apt repository not specified"))?,
            apk_repository: self
                .apk_repository
                .ok_or_else(|| anyhow::anyhow!("apk repository not specified"))?,
            interval: self.interval,
        };
        let runner = tokio::spawn(runner.run());

        Ok(Worker { runner })
    }
}

#[derive(Debug)]
pub struct Worker {
    runner: tokio::task::JoinHandle<()>,
}

impl Worker {
    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.runner.abort();
        self.runner.await.context("worker didn't stop gracefully")
    }
}

struct Runner<AR, APK> {
    apt_repository: AR,
    apk_repository: APK,
    interval: Duration,
}

impl<AR, APK> Runner<AR, APK>
where
    AR: crate::domain::prelude::AptRepositoryWriter,
    APK: crate::domain::prelude::ApkRepositoryWriter,
{
    async fn run(self) {
        tracing::info!("starting worker");
        let mut interval = tokio::time::interval(self.interval);
        let mut failures = 0u64;
        loop {
            let _ = interval.tick().await;
            tracing::info!("starting synchro");

            let mut has_error = false;

            match self.apt_repository.synchronize().await {
                Ok(_) => tracing::info!("apt synchro completed"),
                Err(err) => {
                    has_error = true;
                    tracing::error!(error = ?err, "apt synchro failed");
                }
            }

            match self.apk_repository.synchronize().await {
                Ok(_) => tracing::info!("apk synchro completed"),
                Err(err) => {
                    has_error = true;
                    tracing::error!(error = ?err, "apk synchro failed");
                }
            }

            if has_error {
                failures += 1;
                let wait = failures * 30;
                tracing::error!(wait, "synchro failed, retrying later");
                interval.reset_after(Duration::from_secs(wait));
            } else {
                failures = 0;
                tracing::info!("synchro completed");
            }
        }
    }
}
