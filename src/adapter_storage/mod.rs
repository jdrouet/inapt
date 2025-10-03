use std::sync::Arc;

use tokio::sync::RwLock;

use crate::domain::entity::{DebAsset, Package, ReleaseMetadata};

#[derive(Clone, Debug, Default)]
pub struct MemoryStorage(Arc<RwLock<Option<ReleaseMetadata>>>);

impl crate::domain::prelude::ReleaseStore for MemoryStorage {
    async fn insert_release(&self, entry: ReleaseMetadata) {
        self.0.write().await.replace(entry);
    }

    async fn find_package_by_asset(&self, asset: &DebAsset) -> Option<Package> {
        self.0
            .read()
            .await
            .iter()
            .flat_map(|meta| meta.architectures.iter())
            .flat_map(|arch| arch.packages.iter())
            .find(|pkg| pkg.asset.asset_id == asset.asset_id)
            .cloned()
    }

    async fn find_latest_release(&self) -> Option<ReleaseMetadata> {
        self.0.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::prelude::ReleaseStore;

    #[tokio::test]
    async fn should_insert_and_fetch_data() {
        let storage = super::MemoryStorage::default();
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
    }
}
