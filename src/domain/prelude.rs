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

/// Identifies a GitHub release by its owner, name, and ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReleaseIdentifier {
    pub repo_owner: String,
    pub repo_name: String,
    pub release_id: u64,
}

/// Tracks which GitHub releases have been scanned.
pub trait ReleaseTracker: Send + Sync + 'static {
    /// Check which releases from a batch have already been scanned.
    /// Returns a set of release IDs that have been scanned.
    fn filter_scanned_releases(
        &self,
        releases: &[ReleaseIdentifier],
    ) -> impl Future<Output = anyhow::Result<std::collections::HashSet<u64>>> + Send;

    /// Mark multiple releases as scanned in a single batch operation.
    fn mark_releases_scanned(
        &self,
        releases: &[ReleaseIdentifier],
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub ReleaseTracker {}

    impl Clone for ReleaseTracker {
        fn clone(&self) -> Self;
    }

    impl ReleaseTracker for ReleaseTracker {
        fn filter_scanned_releases(
            &self,
            releases: &[ReleaseIdentifier],
        ) -> impl Future<Output = anyhow::Result<std::collections::HashSet<u64>>> + Send;

        fn mark_releases_scanned(
            &self,
            releases: &[ReleaseIdentifier],
        ) -> impl Future<Output = anyhow::Result<()>> + Send;
    }
}

/// Stores individual packages for incremental updates.
pub trait PackageStore: Send + Sync + 'static {
    /// Insert multiple packages into storage in a single batch operation.
    fn insert_packages(
        &self,
        packages: &[Package],
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

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
        fn insert_packages(
            &self,
            packages: &[Package],
        ) -> impl Future<Output = anyhow::Result<()>> + Send;

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

/// Synchronizes APK packages from upstream sources.
#[expect(dead_code, reason = "APK support trait (#60), implemented in #65")]
pub trait ApkRepositoryWriter: Send + Sync + 'static {
    fn synchronize(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// Serves an APK repository (APKINDEX and package lookups).
#[expect(dead_code, reason = "APK support trait (#60), implemented in #65")]
pub trait ApkRepositoryReader: Send + Sync + 'static {
    /// Get the signed APKINDEX.tar.gz content for a given architecture.
    fn apk_index(&self, arch: &str) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// Find an APK package by architecture and filename for download redirect.
    fn apk_package(
        &self,
        arch: &str,
        filename: &str,
    ) -> impl Future<Output = anyhow::Result<Option<ApkPackage>>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub ApkRepositoryService {}

    impl Clone for ApkRepositoryService {
        fn clone(&self) -> Self;
    }

    impl ApkRepositoryReader for ApkRepositoryService {
        fn apk_index(&self, arch: &str) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

        fn apk_package(
            &self,
            arch: &str,
            filename: &str,
        ) -> impl Future<Output = anyhow::Result<Option<ApkPackage>>> + Send;
    }
}

/// Extracts metadata from an `.apk` file's `.PKGINFO`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "APK support trait (#60), wired in #67")
)]
pub trait ApkMetadataExtractor: Send + Sync + 'static {
    /// Given an `.apk` file, extract package metadata.
    fn extract_metadata(
        &self,
        path: &std::path::Path,
    ) -> impl Future<Output = anyhow::Result<ApkMetadata>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub ApkMetadataExtractor {}

    impl Clone for ApkMetadataExtractor {
        fn clone(&self) -> Self;
    }

    impl ApkMetadataExtractor for ApkMetadataExtractor {
        fn extract_metadata(
            &self,
            path: &std::path::Path,
        ) -> impl Future<Output = anyhow::Result<ApkMetadata>> + Send;
    }
}

/// Stores APK packages for incremental updates.
#[expect(dead_code, reason = "APK support trait (#60), implemented in #64")]
pub trait ApkPackageStore: Send + Sync + 'static {
    /// Insert multiple APK packages in a single batch operation.
    fn insert_apk_packages(
        &self,
        packages: &[ApkPackage],
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Find an APK package by its GitHub asset ID.
    fn find_apk_package_by_asset_id(
        &self,
        asset_id: u64,
    ) -> impl Future<Output = Option<ApkPackage>> + Send;

    /// Get all APK packages for building the APKINDEX.
    fn list_all_apk_packages(&self)
    -> impl Future<Output = anyhow::Result<Vec<ApkPackage>>> + Send;
}

#[cfg(test)]
mockall::mock! {
    pub ApkPackageStore {}

    impl Clone for ApkPackageStore {
        fn clone(&self) -> Self;
    }

    impl ApkPackageStore for ApkPackageStore {
        fn insert_apk_packages(
            &self,
            packages: &[ApkPackage],
        ) -> impl Future<Output = anyhow::Result<()>> + Send;

        fn find_apk_package_by_asset_id(
            &self,
            asset_id: u64,
        ) -> impl Future<Output = Option<ApkPackage>> + Send;

        fn list_all_apk_packages(
            &self,
        ) -> impl Future<Output = anyhow::Result<Vec<ApkPackage>>> + Send;
    }
}

/// Signs data with an RSA key for APK repository index signing.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "APK support trait (#60), wired in #60")
)]
pub trait RsaSigner: Send + Sync + 'static {
    /// Sign raw bytes and return the RSA signature.
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// The key filename used in the `.SIGN.RSA.{name}` tar entry.
    fn key_name(&self) -> &str;
}

#[cfg(test)]
mockall::mock! {
    pub RsaSigner {}

    impl RsaSigner for RsaSigner {
        fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
        fn key_name(&self) -> &str;
    }
}
