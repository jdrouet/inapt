use std::sync::Arc;

use tokio::sync::RwLock;

use crate::domain::entity::ReleaseMetadata;

#[derive(Clone, Debug, Default)]
pub struct MemoryStorage(Arc<RwLock<Option<ReleaseMetadata>>>);

impl crate::domain::prelude::ReleaseStore for MemoryStorage {
    async fn insert(&self, entry: ReleaseMetadata) {
        self.0.write().await.replace(entry);
    }

    async fn fetch(&self) -> Option<ReleaseMetadata> {
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
            .insert(crate::domain::entity::ReleaseMetadata {
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
        let res = storage.fetch().await.unwrap();
        assert_eq!(res.origin, "origin");
    }
}
