use std::{io::Write, sync::Arc};

use anyhow::Context;
use tokio::sync::RwLock;

use crate::domain::entity::{Package, ReleaseMetadata};

const fn default_true() -> bool {
    true
}

#[derive(Debug, serde::Deserialize)]
pub struct Config {
    path: std::path::PathBuf,
    #[serde(default = "default_true")]
    ignore_errors: bool,
}

impl Config {
    pub fn build(self) -> anyhow::Result<MemoryStorage> {
        if !self.path.exists() {
            return Ok(MemoryStorage::new(self.path));
        }
        match Inner::read(&self.path) {
            Ok(inner) => Ok(MemoryStorage::from(inner)),
            Err(err) if self.ignore_errors => {
                tracing::warn!(error = ?err, "unable to load last value, ignoring");
                Ok(MemoryStorage::new(self.path))
            }
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug)]
struct Inner {
    path: std::path::PathBuf,
    value: Option<ReleaseMetadata>,
}

impl Inner {
    fn read(path: &std::path::Path) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path).context("unable to open storage file")?;
        let value: ReleaseMetadata =
            serde_json::from_reader(file).context("unable to deserialize storage file")?;
        Ok(Inner {
            path: std::path::PathBuf::from(path),
            value: Some(value),
        })
    }

    fn persist(&self) -> anyhow::Result<()> {
        if let Some(ref value) = self.value {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&self.path)
                .context("unable to open storage file")?;
            serde_json::to_writer(&mut file, value).context("unable to write to storage file")?;
            file.flush()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MemoryStorage(Arc<RwLock<Inner>>);

impl From<Inner> for MemoryStorage {
    fn from(value: Inner) -> Self {
        MemoryStorage(Arc::new(RwLock::new(value)))
    }
}

impl MemoryStorage {
    fn new(path: impl Into<std::path::PathBuf>) -> Self {
        MemoryStorage(Arc::new(RwLock::new(Inner {
            path: path.into(),
            value: None,
        })))
    }
}

impl crate::domain::prelude::ReleaseStore for MemoryStorage {
    async fn insert_release(&self, entry: ReleaseMetadata) {
        let mut writer = self.0.write().await;
        writer.value.replace(entry);
        if let Err(err) = writer.persist() {
            tracing::error!(error = ?err, "unable to persist on disk");
            eprintln!("unable to persist on disk: {err:?}");
        }
    }

    async fn find_latest_release(&self) -> Option<ReleaseMetadata> {
        self.0.read().await.value.clone()
    }
}

// Temporary placeholder implementations - will be replaced by SQLite adapter
impl crate::domain::prelude::ReleaseTracker for MemoryStorage {
    async fn is_release_scanned(
        &self,
        _repo_owner: &str,
        _repo_name: &str,
        _release_id: u64,
    ) -> anyhow::Result<bool> {
        // For now, always return false to maintain existing behavior
        Ok(false)
    }

    async fn mark_release_scanned(
        &self,
        _repo_owner: &str,
        _repo_name: &str,
        _release_id: u64,
    ) -> anyhow::Result<()> {
        // No-op for now
        Ok(())
    }
}

impl crate::domain::prelude::PackageStore for MemoryStorage {
    async fn insert_package(&self, _package: &Package) -> anyhow::Result<()> {
        // No-op for now - packages are stored via ReleaseMetadata
        Ok(())
    }

    async fn find_package_by_asset_id(&self, asset_id: u64) -> Option<Package> {
        self.0
            .read()
            .await
            .value
            .iter()
            .flat_map(|meta| meta.architectures.iter())
            .flat_map(|arch| arch.packages.iter())
            .find(|pkg| pkg.asset.asset_id == asset_id)
            .cloned()
    }

    async fn list_all_packages(&self) -> anyhow::Result<Vec<Package>> {
        Ok(self
            .0
            .read()
            .await
            .value
            .iter()
            .flat_map(|meta| meta.architectures.iter())
            .flat_map(|arch| arch.packages.iter())
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::prelude::ReleaseStore;

    #[tokio::test]
    async fn should_insert_and_fetch_data() {
        let storage_file = temp_file::empty();
        let storage = super::MemoryStorage::new(storage_file.path());
        storage
            .insert_release(crate::domain::entity::ReleaseMetadata {
                origin: "origin".into(),
                label: "label".into(),
                suite: "suite".into(),
                version: "version".into(),
                codename: "codename".into(),
                date: chrono::DateTime::from_timestamp_nanos(0),
                architectures: vec![],
                components: vec![],
                description: "whatever".into(),
            })
            .await;
        let res = storage.find_latest_release().await.unwrap();
        assert_eq!(res.origin, "origin");
        drop(storage);
        // should have written on disk
        let storage = super::Config {
            path: storage_file.path().into(),
            ignore_errors: false,
        }
        .build()
        .unwrap();
        let res = storage.find_latest_release().await.unwrap();
        assert_eq!(res.origin, "origin");
    }
}
