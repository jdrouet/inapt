use chrono::{DateTime, Utc};

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
    fn release_metadata(
        &self,
    ) -> impl Future<Output = anyhow::Result<Option<ReleaseMetadata>>> + Send;

    /// Get the signed Packages file content for a given architecture.
    fn signed_release_metadata(
        &self,
    ) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;

    /// Get the signature of the Release file.
    fn release_gpg_signature(&self) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;

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

    /// Get the Translation-en file content.
    /// Returns the translation entries for all unique packages across all architectures.
    fn translation_file(&self) -> impl Future<Output = anyhow::Result<String>> + Send;

    /// Get the package for a given package name and filename
    fn package(
        &self,
        name: &str,
        filename: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Package>>> + Send;

    /// Find architecture metadata by hash (SHA256) for by-hash support.
    /// Returns the architecture name if the hash matches either plain or compressed Packages file.
    fn find_architecture_by_hash(
        &self,
        hash: &str,
    ) -> impl Future<Output = anyhow::Result<Option<ArchitectureHashMatch>>> + Send;
}

/// Represents a match found when looking up an architecture by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchitectureHashMatch {
    /// The architecture name (e.g., "amd64", "arm64")
    pub architecture: String,
    /// Whether the hash matched the compressed (.gz) variant
    pub compressed: bool,
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
        fn release_metadata(&self) -> impl Future<Output = anyhow::Result<Option<ReleaseMetadata>>> + Send;

        /// Get the signed Packages file content for a given architecture.
        fn signed_release_metadata(&self) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;

        /// Get the signature of the Release file.
        fn release_gpg_signature(&self) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;

        /// Get the Packages file content for a given architecture.
        fn packages_file(&self, arch: &str) -> impl Future<Output = anyhow::Result<String>> + Send;

        /// Get the Translation-en file content.
        fn translation_file(&self) -> impl Future<Output = anyhow::Result<String>> + Send;

        /// Get the package for a given package name and filename
        fn package(
            &self,
            name: &str,
            filename: &str,
        ) -> impl Future<Output = anyhow::Result<Option<Package>>> + Send;

        /// Find architecture metadata by hash (SHA256) for by-hash support.
        fn find_architecture_by_hash(
            &self,
            hash: &str,
        ) -> impl Future<Output = anyhow::Result<Option<ArchitectureHashMatch>>> + Send;
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
    /// Download a .deb asset.
    fn fetch_deb(
        &self,
        asset: &DebAsset,
    ) -> impl Future<Output = anyhow::Result<temp_file::TempFile>> + Send;

    /// Stream releases with their .deb assets for incremental processing.
    fn stream_releases_with_assets(
        &self,
        repo: &str,
    ) -> impl Future<Output = anyhow::Result<Vec<ReleaseWithAssets>>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub PackageSource {}

    impl Clone for PackageSource {
        fn clone(&self) -> Self;
    }

    impl PackageSource for PackageSource {
        fn fetch_deb(
            &self,
            asset: &DebAsset,
        ) -> impl Future<Output = anyhow::Result<temp_file::TempFile>> + Send;
        fn stream_releases_with_assets(
            &self,
            repo: &str,
        ) -> impl Future<Output = anyhow::Result<Vec<ReleaseWithAssets>>> + Send;
    }
}

/// Caches package metadata and assets.
pub trait ReleaseStore: Send + Sync + 'static {
    fn insert_release(&self, entry: ReleaseMetadata) -> impl Future<Output = ()> + Send;
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
        fn find_latest_release(&self) -> impl Future<Output = Option<ReleaseMetadata>> + Send;
    }
}

/// Tracks which GitHub releases have been scanned.
pub trait ReleaseTracker: Send + Sync + 'static {
    /// Check if a release has already been scanned.
    fn is_release_scanned(
        &self,
        repo_owner: &str,
        repo_name: &str,
        release_id: u64,
    ) -> impl Future<Output = anyhow::Result<bool>> + Send;

    /// Mark a release as scanned.
    fn mark_release_scanned(
        &self,
        repo_owner: &str,
        repo_name: &str,
        release_id: u64,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub ReleaseTracker {}

    impl Clone for ReleaseTracker {
        fn clone(&self) -> Self;
    }

    impl ReleaseTracker for ReleaseTracker {
        fn is_release_scanned(
            &self,
            repo_owner: &str,
            repo_name: &str,
            release_id: u64,
        ) -> impl Future<Output = anyhow::Result<bool>> + Send;

        fn mark_release_scanned(
            &self,
            repo_owner: &str,
            repo_name: &str,
            release_id: u64,
        ) -> impl Future<Output = anyhow::Result<()>> + Send;
    }
}

/// Stores individual packages for incremental updates.
pub trait PackageStore: Send + Sync + 'static {
    /// Insert a package into storage.
    fn insert_package(&self, package: &Package) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Find a package by its asset ID.
    fn find_package_by_asset_id(
        &self,
        asset_id: u64,
    ) -> impl Future<Output = Option<Package>> + Send;

    /// Get all packages for building ReleaseMetadata.
    fn list_all_packages(&self) -> impl Future<Output = anyhow::Result<Vec<Package>>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub PackageStore {}

    impl Clone for PackageStore {
        fn clone(&self) -> Self;
    }

    impl PackageStore for PackageStore {
        fn insert_package(&self, package: &Package) -> impl Future<Output = anyhow::Result<()>> + Send;

        fn find_package_by_asset_id(
            &self,
            asset_id: u64,
        ) -> impl Future<Output = Option<Package>> + Send;

        fn list_all_packages(&self) -> impl Future<Output = anyhow::Result<Vec<Package>>> + Send;
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

pub trait PGPCipher: Send + Sync + 'static {
    fn sign(&self, data: &str) -> anyhow::Result<String>;
}

#[cfg(test)]
mockall::mock! {
    pub PGPCipher {}

    impl PGPCipher for PGPCipher {
        fn sign(&self, data: &str) -> anyhow::Result<String>;
    }
}
