use super::entity::*;

pub trait AptRepositoryWriter: Send + Sync + 'static {
    fn synchronize(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// Represents a logical APT repository (suite/component/arch).
pub trait AptRepositoryReader: Send + Sync + 'static {
    /// List all available packages for a given architecture.
    fn list_packages(
        &self,
        arch: &str,
    ) -> impl Future<Output = anyhow::Result<Vec<Package>>> + Send;

    /// Get the Release metadata for the repository.
    fn release_metadata(&self) -> impl Future<Output = anyhow::Result<ReleaseMetadata>> + Send;

    /// Get the Packages file content for a given architecture.
    fn packages_file(&self, arch: &str) -> impl Future<Output = anyhow::Result<String>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub AptRepositoryService {}

    impl Clone for AptRepositoryService {
        fn clone(&self) -> Self;
    }

    impl AptRepositoryReader for AptRepositoryService {
        /// List all available packages for a given architecture.
        fn list_packages(
            &self,
            arch: &str,
        ) -> impl Future<Output = anyhow::Result<Vec<Package>>> + Send;

        /// Get the Release metadata for the repository.
        fn release_metadata(&self) -> impl Future<Output = anyhow::Result<ReleaseMetadata>> + Send;

        /// Get the Packages file content for a given architecture.
        fn packages_file(&self, arch: &str) -> impl Future<Output = anyhow::Result<String>> + Send;
    }
}

/// Extracts control metadata from a .deb file.
pub trait DebMetadataExtractor: Send + Sync + 'static {
    /// Given a .deb file (as bytes or path), extract control fields.
    fn extract_metadata(
        &self,
        deb_data: &[u8],
    ) -> impl Future<Output = anyhow::Result<PackageMetadata>> + Send;
}

/// Abstracts the source of .deb packages (e.g., GitHub Releases).
pub trait PackageSource: Send + Sync + 'static {
    /// List all .deb assets for a repo.
    fn list_deb_assets(
        &self,
        repo: &str,
    ) -> impl Future<Output = anyhow::Result<Vec<DebAsset>>> + Send;

    /// Download a .deb asset.
    fn fetch_deb(
        &self,
        asset: &DebAsset,
    ) -> impl Future<Output = anyhow::Result<temp_file::TempFile>> + Send;
}

/// Caches package metadata and assets.
pub trait MetadataCache: Send + Sync + 'static {
    /// Get cached metadata, or None if expired/missing.
    fn get(&self, key: &str) -> impl Future<Output = Option<PackageMetadata>> + Send;

    /// Store metadata with a TTL.
    fn set(
        &mut self,
        key: &str,
        value: PackageMetadata,
        ttl_secs: u64,
    ) -> impl Future<Output = ()> + Send;
}
