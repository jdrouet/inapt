use std::time::Duration;

use anyhow::Context;

pub struct Config {
    interval: u64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            interval: crate::with_env_as_or("WORKER_INTERVAL_SYNC", 60 * 60 * 60)?,
        })
    }

    pub fn builder<AR>(self) -> WorkerBuilder<AR> {
        WorkerBuilder {
            apt_repository: None,
            interval: Duration::from_secs(self.interval),
        }
    }
}

pub struct WorkerBuilder<AR> {
    apt_repository: Option<AR>,
    interval: Duration,
}

impl<AR> WorkerBuilder<AR>
where
    AR: crate::domain::prelude::AptRepositoryWriter,
{
    pub fn with_apt_repository(self, service: AR) -> Self {
        Self {
            apt_repository: Some(service),
            interval: self.interval,
        }
    }

    pub fn build(self) -> anyhow::Result<Worker> {
        let runner = Runner {
            apt_repository: self
                .apt_repository
                .ok_or_else(|| anyhow::anyhow!("apt repository not specified"))?,
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

struct Runner<AR> {
    apt_repository: AR,
    interval: Duration,
}

impl<AR> Runner<AR>
where
    AR: crate::domain::prelude::AptRepositoryWriter,
{
    async fn run(self) {
        tracing::info!("starting worker");
        let mut interval = tokio::time::interval(self.interval);
        let mut failures = 0u64;
        loop {
            let _ = interval.tick().await;
            tracing::info!("starting synchro");
            match self.apt_repository.synchronize().await {
                Ok(_) => {
                    failures = 0;
                    tracing::info!("synchro completed");
                }
                Err(err) => {
                    failures += 1;
                    let wait = failures * 30;
                    tracing::error!(error = ?err, wait, "synchro failed, retrying later");
                    interval.reset_after(Duration::from_secs(wait));
                }
            }
        }
    }
}
