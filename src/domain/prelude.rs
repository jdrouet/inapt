use chrono::{DateTime, Utc};

use super::entity::*;

pub trait AptRepositoryWriter: Send + Sync + 'static {
    fn synchronize(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum GetReleaseFileError {
    #[error("release file not found")]
    NotFound,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Represents a logical APT repository (suite/component/arch).
pub trait AptRepositoryReader: Send + Sync + 'static {
    /// List all available packages for a given architecture.
    fn list_packages(
        &self,
        arch: &str,
    ) -> impl Future<Output = anyhow::Result<Vec<Package>>> + Send;

    /// Get the Release metadata for the repository.
    fn release_metadata(
        &self,
    ) -> impl Future<Output = Result<ReleaseMetadata, GetReleaseFileError>> + Send;

    /// Get the Packages file content for a given architecture.
    fn packages_file(&self, arch: &str) -> impl Future<Output = anyhow::Result<String>> + Send {
        async {
            let list = self.list_packages(arch).await?;
            Ok(list
                .into_iter()
                .map(|package| package.serialize().to_string())
                .collect::<Vec<_>>()
                .join("\n"))
        }
    }

    /// Get the package for a given package name and filename
    fn package(
        &self,
        name: &str,
        filename: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Package>>> + Send;
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
        fn release_metadata(&self) -> impl Future<Output = Result<ReleaseMetadata, GetReleaseFileError>> + Send;

        /// Get the Packages file content for a given architecture.
        fn packages_file(&self, arch: &str) -> impl Future<Output = anyhow::Result<String>> + Send;

        /// Get the package for a given package name and filename
        fn package(
            &self,
            name: &str,
            filename: &str,
        ) -> impl Future<Output = anyhow::Result<Option<Package>>> + Send;
    }
}

/// Extracts control metadata from a .deb file.
pub trait DebMetadataExtractor: Send + Sync + 'static {
    /// Given a .deb file, extract control fields.
    fn extract_metadata(
        &self,
        path: &std::path::Path,
    ) -> impl Future<Output = anyhow::Result<PackageMetadata>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub DebMetadataExtractor {}

    impl Clone for DebMetadataExtractor {
        fn clone(&self) -> Self;
    }

    impl DebMetadataExtractor for DebMetadataExtractor {
        fn extract_metadata(
            &self,
            path: &std::path::Path,
        ) -> impl Future<Output = anyhow::Result<PackageMetadata>> + Send;
    }
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

#[cfg(test)]
mockall::mock! {
    pub PackageSource {}

    impl Clone for PackageSource {
        fn clone(&self) -> Self;
    }

    impl PackageSource for PackageSource {
        fn list_deb_assets(
            &self,
            repo: &str,
        ) -> impl Future<Output = anyhow::Result<Vec<DebAsset>>> + Send;
        fn fetch_deb(
            &self,
            asset: &DebAsset,
        ) -> impl Future<Output = anyhow::Result<temp_file::TempFile>> + Send;
    }
}

/// Caches package metadata and assets.
pub trait ReleaseStore: Send + Sync + 'static {
    fn insert_release(&self, entry: ReleaseMetadata) -> impl Future<Output = ()> + Send;
    fn find_package_by_asset(
        &self,
        asset: &DebAsset,
    ) -> impl Future<Output = Option<Package>> + Send;
    fn find_latest_release(&self) -> impl Future<Output = Option<ReleaseMetadata>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub ReleaseStore {}

    impl Clone for ReleaseStore {
        fn clone(&self) -> Self;
    }

    impl ReleaseStore for ReleaseStore {
        fn insert_release(&self, entry: ReleaseMetadata) -> impl Future<Output = ()> + Send;
        fn find_package_by_asset(&self, asset: &DebAsset) -> impl Future<Output = Option<Package>> + Send;
        fn find_latest_release(&self) -> impl Future<Output = Option<ReleaseMetadata>> + Send;
    }
}

pub trait Clock: Send + Sync + 'static {
    fn now() -> DateTime<Utc>;
}

impl Clock for chrono::Utc {
    fn now() -> DateTime<Utc> {
        Utc::now()
    }
}

#[cfg(test)]
mockall::mock! {
    pub Clock {}

    impl Clock for Clock {
        fn now() -> chrono::DateTime<chrono::Utc>;
    }
}
