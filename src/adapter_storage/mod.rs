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
