use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    io::Write,
    marker::PhantomData,
    sync::Arc,
};

use flate2::{Compression, write::GzEncoder};

use sha2::Digest;

pub(crate) mod entity;
pub(crate) mod prelude;

#[derive(Debug, serde::Deserialize)]
pub struct Config {
    // Origin: Debian
    #[serde(default = "Config::default_origin")]
    pub origin: Cow<'static, str>,
    // Label: Debian
    #[serde(default = "Config::default_label")]
    pub label: Cow<'static, str>,
    // Suite: stable
    #[serde(default = "Config::default_suite")]
    pub suite: Cow<'static, str>,
    // Version: 12.5
    #[serde(default = "Config::default_version")]
    pub version: Cow<'static, str>,
    // Codename: bookworm
    #[serde(default = "Config::default_codename")]
    pub codename: Cow<'static, str>,
    // Date: Tue, 04 Jun 2024 12:34:56 UTC
    // pub date: String,
    // Architectures: amd64 arm64
    // Components: main contrib non-free
    // Description: Debian 12.5 Release
    #[serde(default = "Config::default_description")]
    pub description: Cow<'static, str>,
    #[serde(default)]
    pub repositories: Vec<String>,
}

impl Config {
    pub const fn default_origin() -> Cow<'static, str> {
        Cow::Borrowed("GitHub releases")
    }
    pub const fn default_label() -> Cow<'static, str> {
        Cow::Borrowed("Debian")
    }
    pub const fn default_suite() -> Cow<'static, str> {
        Cow::Borrowed("Stable")
    }
    pub const fn default_version() -> Cow<'static, str> {
        Cow::Borrowed("0.1.0")
    }
    pub const fn default_codename() -> Cow<'static, str> {
        Cow::Borrowed("cucumber")
    }
    pub const fn default_description() -> Cow<'static, str> {
        Cow::Borrowed("GitHub releases proxy")
    }
}

#[derive(Clone, Debug)]
pub struct AptRepositoryService<C, PS, RS, DE, PGP, RT, PKS> {
    pub config: Arc<Config>,
    pub clock: PhantomData<C>,
    pub package_source: PS,
    pub release_storage: RS,
    pub deb_extractor: DE,
    pub pgp_cipher: PGP,
    pub release_tracker: RT,
    pub package_store: PKS,
}

impl<C, PS, RS, DE, PGP, RT, PKS> prelude::AptRepositoryReader
    for AptRepositoryService<C, PS, RS, DE, PGP, RT, PKS>
where
    C: Send + Sync + 'static,
    PS: Send + Sync + 'static,
    RS: crate::domain::prelude::ReleaseStore,
    DE: Send + Sync + 'static,
    PGP: crate::domain::prelude::PGPCipher,
    RT: Send + Sync + 'static,
    PKS: Send + Sync + 'static,
{
    async fn list_packages(&self, arch: &str) -> anyhow::Result<Vec<entity::Package>> {
        let Some(received) = self.release_storage.find_latest_release().await else {
            return Ok(Vec::new());
        };
        Ok(received
            .architectures
            .iter()
            .filter(|item| item.name == arch)
            .flat_map(|item| item.packages.iter())
            .cloned()
            .collect())
    }

    async fn release_metadata(&self) -> anyhow::Result<Option<entity::ReleaseMetadata>> {
        Ok(self.release_storage.find_latest_release().await)
    }

    /// Get the signed Packages file content for a given architecture.
    async fn signed_release_metadata(&self) -> anyhow::Result<Option<String>> {
        let Some(metadata) = self.release_metadata().await? else {
            return Ok(None);
        };

        let metadata = metadata.serialize().to_string();
        let signature = self.pgp_cipher.sign(metadata.as_str())?;
        Ok(Some(format!("{metadata}\n\n{signature}\n")))
    }

    async fn release_gpg_signature(&self) -> anyhow::Result<Option<String>> {
        let Some(metadata) = self.release_metadata().await? else {
            return Ok(None);
        };

        let metadata = metadata.serialize().to_string();
        let signature = self.pgp_cipher.sign(metadata.as_str())?;
        Ok(Some(signature))
    }

    async fn package(&self, name: &str, filename: &str) -> anyhow::Result<Option<entity::Package>> {
        let Some(received) = self.release_storage.find_latest_release().await else {
            return Ok(None);
        };
        Ok(received
            .architectures
            .iter()
            .flat_map(|item| item.packages.iter())
            .find(|item| item.metadata.control.package == name && item.asset.filename == filename)
            .cloned())
    }

    async fn find_architecture_by_hash(
        &self,
        hash: &str,
    ) -> anyhow::Result<Option<prelude::ArchitectureHashMatch>> {
        let Some(received) = self.release_storage.find_latest_release().await else {
            return Ok(None);
        };
        for arch in &received.architectures {
            if arch.plain_sha256 == hash {
                return Ok(Some(prelude::ArchitectureHashMatch {
                    architecture: arch.name.clone(),
                    compressed: false,
                }));
            }
            if arch.compressed_sha256 == hash {
                return Ok(Some(prelude::ArchitectureHashMatch {
                    architecture: arch.name.clone(),
                    compressed: true,
                }));
            }
        }
        Ok(None)
    }

    async fn translation_file(&self) -> anyhow::Result<String> {
        let Some(received) = self.release_storage.find_latest_release().await else {
            return Ok(String::new());
        };

        // Collect unique packages by name (deduplicate across architectures)
        let mut seen_packages: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut entries = Vec::new();

        for arch in &received.architectures {
            for package in &arch.packages {
                let pkg_name = &package.metadata.control.package;
                if seen_packages.insert(pkg_name.clone()) {
                    entries.push(entity::TranslationEntry {
                        package: pkg_name.clone(),
                        description_md5: package.metadata.control.description_md5(),
                        description: package.metadata.control.description.clone(),
                    });
                }
            }
        }

        // Sort entries by package name for consistent output
        entries.sort_by(|a, b| a.package.cmp(&b.package));

        Ok(entries
            .into_iter()
            .map(|entry| entry.to_string())
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

impl<C, PS, RS, DE, PGP, RT, PKS> AptRepositoryService<C, PS, RS, DE, PGP, RT, PKS>
where
    C: prelude::Clock,
    PS: prelude::PackageSource,
    RS: prelude::ReleaseStore,
    DE: prelude::DebMetadataExtractor,
    PGP: prelude::PGPCipher,
    RT: prelude::ReleaseTracker,
    PKS: prelude::PackageStore,
{
    #[tracing::instrument(
        skip(self),
        fields(
            repo.owner = asset.repo_owner,
            repo.name = asset.repo_name,
            filename = asset.filename,
        ),
        err(Debug),
    )]
    async fn handle_package(
        &self,
        asset: entity::DebAsset,
    ) -> anyhow::Result<Option<entity::Package>> {
        // Check if package is already stored
        if let Some(package) = self
            .package_store
            .find_package_by_asset_id(asset.asset_id)
            .await
        {
            tracing::debug!("package already known, using cached value");
            return Ok(Some(package));
        }
        let deb_file = self.package_source.fetch_deb(&asset).await?;
        match self.deb_extractor.extract_metadata(deb_file.path()).await {
            Ok(metadata) => Ok(Some(entity::Package { metadata, asset })),
            Err(err) => {
                tracing::warn!(error = ?err, "unable to extract metadata");
                Ok(None)
            }
        }
    }

    #[tracing::instrument(skip(self), err(Debug))]
    async fn synchronize_repo(&self, repo: &str) -> anyhow::Result<()> {
        tracing::info!("streaming releases for incremental sync");
        let releases = self
            .package_source
            .stream_releases_with_assets(repo)
            .await?;

        if releases.is_empty() {
            return Ok(());
        }

        // Collect all release identifiers for batch filtering
        let release_identifiers: Vec<prelude::ReleaseIdentifier> = releases
            .iter()
            .map(|r| prelude::ReleaseIdentifier {
                repo_owner: r.repo_owner.clone(),
                repo_name: r.repo_name.clone(),
                release_id: r.release_id,
            })
            .collect();

        // Batch query: find which releases are already scanned
        let scanned_release_ids = self
            .release_tracker
            .filter_scanned_releases(&release_identifiers)
            .await?;

        // Filter to only unscanned releases
        let unscanned_releases: Vec<_> = releases
            .into_iter()
            .filter(|r| !scanned_release_ids.contains(&r.release_id))
            .collect();

        if unscanned_releases.is_empty() {
            tracing::debug!("all releases already scanned, nothing to do");
            return Ok(());
        }

        tracing::info!(
            unscanned_count = unscanned_releases.len(),
            "processing unscanned releases"
        );

        // Collect identifiers for releases we're about to process
        let releases_to_mark: Vec<prelude::ReleaseIdentifier> = unscanned_releases
            .iter()
            .map(|r| prelude::ReleaseIdentifier {
                repo_owner: r.repo_owner.clone(),
                repo_name: r.repo_name.clone(),
                release_id: r.release_id,
            })
            .collect();

        // Mark releases as scanned first (required for foreign key constraint on packages)
        self.release_tracker
            .mark_releases_scanned(&releases_to_mark)
            .await?;

        // Process all assets and collect packages
        let mut packages_to_insert = Vec::new();
        for release in unscanned_releases {
            tracing::info!(
                release_id = release.release_id,
                assets = release.assets.len(),
                "processing release"
            );

            for asset in release.assets {
                if let Some(package) = self.handle_package(asset).await? {
                    packages_to_insert.push(package);
                }
            }
        }

        // Batch insert all packages
        if !packages_to_insert.is_empty() {
            self.package_store
                .insert_packages(&packages_to_insert)
                .await?;
        }

        Ok(())
    }
}

impl<C, PS, RS, DE, PGP, RT, PKS> prelude::AptRepositoryWriter
    for AptRepositoryService<C, PS, RS, DE, PGP, RT, PKS>
where
    C: prelude::Clock,
    PS: prelude::PackageSource,
    RS: prelude::ReleaseStore,
    DE: prelude::DebMetadataExtractor,
    PGP: prelude::PGPCipher,
    RT: prelude::ReleaseTracker,
    PKS: prelude::PackageStore,
{
    #[tracing::instrument(skip(self), err(Debug))]
    async fn synchronize(&self) -> anyhow::Result<()> {
        // Sync all repos incrementally
        let mut errors = Vec::with_capacity(self.config.repositories.len());
        for repo in self.config.repositories.iter() {
            if let Err(err) = self.synchronize_repo(repo.as_str()).await {
                errors.push(err);
            }
        }

        // Rebuild release metadata from all stored packages
        let all_packages = self.package_store.list_all_packages().await?;
        let mut builder = ReleaseMetadataBuilder::new(self.config.clone());
        for package in all_packages {
            builder.insert(package);
        }
        let release = builder.build::<C>()?;

        if errors.is_empty() {
            self.release_storage.insert_release(release).await;
            Ok(())
        } else {
            Err(anyhow::anyhow!("synchronization failed"))
        }
    }
}

#[derive(Debug)]
struct ReleaseMetadataBuilder {
    config: Arc<Config>,
    architectures: HashMap<String, ArchitectureMetadataBuilder>,
}

impl ReleaseMetadataBuilder {
    fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            architectures: Default::default(),
        }
    }

    fn insert(&mut self, package: entity::Package) {
        self.architectures
            .entry(package.metadata.control.architecture.clone())
            .or_default()
            .insert(package);
    }

    fn build<C: prelude::Clock>(self) -> anyhow::Result<entity::ReleaseMetadata> {
        let architectures: Vec<entity::ArchitectureMetadata> = self
            .architectures
            .into_iter()
            .map(|(name, values)| values.build(name))
            .collect::<Result<_, _>>()?;

        // Build translation metadata from all packages
        let translation = Self::build_translation_metadata(&architectures)?;

        Ok(entity::ReleaseMetadata {
            origin: self.config.origin.clone(),
            label: self.config.label.clone(),
            suite: self.config.suite.clone(),
            version: self.config.version.clone(),
            codename: self.config.codename.clone(),
            date: C::now(),
            architectures,
            components: vec!["main".into()],
            description: self.config.description.clone(),
            translation,
        })
    }

    fn build_translation_metadata(
        architectures: &[entity::ArchitectureMetadata],
    ) -> anyhow::Result<entity::TranslationMetadata> {
        use sha2::Digest;

        // Collect unique packages by name (deduplicate across architectures)
        let mut seen_packages: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut entries = Vec::new();

        for arch in architectures {
            for package in &arch.packages {
                let pkg_name = &package.metadata.control.package;
                if seen_packages.insert(pkg_name.clone()) {
                    entries.push(entity::TranslationEntry {
                        package: pkg_name.clone(),
                        description_md5: package.metadata.control.description_md5(),
                        description: package.metadata.control.description.clone(),
                    });
                }
            }
        }

        // Sort entries by package name for consistent output
        entries.sort_by(|a, b| a.package.cmp(&b.package));

        // Build the translation file content
        let content = entries
            .into_iter()
            .map(|entry| entry.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        // Compute hashes
        let plain_md5 = hex::encode(md5::Md5::digest(content.as_bytes()));
        let plain_sha256 = hex::encode(sha2::Sha256::digest(content.as_bytes()));
        let plain_size = content.len() as u64;

        // Compress and compute compressed hashes
        let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gz_encoder.write_all(content.as_bytes())?;
        let compressed = gz_encoder.finish()?;

        let compressed_md5 = hex::encode(md5::Md5::digest(&compressed));
        let compressed_sha256 = hex::encode(sha2::Sha256::digest(&compressed));
        let compressed_size = compressed.len() as u64;

        Ok(entity::TranslationMetadata {
            plain_md5,
            plain_sha256,
            plain_size,
            compressed_md5,
            compressed_sha256,
            compressed_size,
        })
    }
}

#[derive(Debug, Default)]
struct ArchitectureMetadataBuilder {
    packages: BTreeMap<String, BTreeMap<String, entity::Package>>,
}

impl ArchitectureMetadataBuilder {
    fn insert(&mut self, package: entity::Package) {
        let packages = self
            .packages
            .entry(package.metadata.control.package.clone())
            .or_default();
        packages.insert(package.metadata.control.version.clone(), package);
    }

    fn build(self, name: String) -> anyhow::Result<entity::ArchitectureMetadata> {
        let mut plain_sha256_hasher = sha2::Sha256::new();
        let mut plain_md5_hasher = md5::Md5::new();
        let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());

        let mut plain_size = 0u64;

        let mut packages = Vec::new();
        for (index, package) in self
            .packages
            .into_values()
            .flat_map(|versions| versions.into_values())
            .enumerate()
        {
            if index > 0 {
                let _ = plain_sha256_hasher.write(b"\n")?;
                let _ = plain_md5_hasher.write(b"\n")?;
                let _ = gz_encoder.write(b"\n")?;
                plain_size += 1;
            }
            let display = package.serialize().to_string();
            plain_size += display.len() as u64;
            let _ = plain_sha256_hasher.write(display.as_bytes())?;
            let _ = plain_md5_hasher.write(display.as_bytes())?;
            let _ = gz_encoder.write(display.as_bytes())?;
            packages.push(package);
        }

        let plain_sha256_hasher = plain_sha256_hasher.finalize();
        let plain_md5_hasher = plain_md5_hasher.finalize();

        let compressed = gz_encoder.finish()?;
        let compressed_md5_hasher = md5::Md5::digest(&compressed);
        let compressed_sha256_hasher = sha2::Sha256::digest(&compressed);

        Ok(entity::ArchitectureMetadata {
            name,
            plain_md5: hex::encode(plain_md5_hasher),
            plain_sha256: hex::encode(plain_sha256_hasher),
            plain_size,
            compressed_md5: hex::encode(compressed_md5_hasher),
            compressed_sha256: hex::encode(compressed_sha256_hasher),
            compressed_size: compressed.len() as u64,
            packages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{DebAsset, FileMetadata, Package, PackageControl, PackageMetadata};
    use crate::domain::prelude::{
        AptRepositoryWriter, MockDebMetadataExtractor, MockPGPCipher, MockPackageSource,
        MockPackageStore, MockReleaseStore, MockReleaseTracker,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    struct UniqueClock;

    impl super::prelude::Clock for UniqueClock {
        fn now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(949453322, 0).unwrap()
        }
    }

    #[test]
    fn should_build_realease_metadata() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });
        let mut builder = ReleaseMetadataBuilder::new(config);
        builder.insert(entity::Package {
            metadata: PackageMetadata {
                control: PackageControl {
                    package: "libcaca".into(),
                    version: "1.1.1".into(),
                    section: Some("section".into()),
                    priority: "priority".into(),
                    architecture: "amd64".into(),
                    maintainer: "notme".into(),
                    description: vec!["description".into()],
                    others: Default::default(),
                },
                file: FileMetadata {
                    size: 512,
                    sha256: "shasha".into(),
                },
            },
            asset: DebAsset {
                repo_owner: "owner".into(),
                repo_name: "name".into(),
                release_id: 1234,
                asset_id: 1234,
                filename: "foo.deb".into(),
                url: "http://example.com/foo.deb".into(),
                size: 123456,
                sha256: Some("sha256".into()),
            },
        });
        let release_metadata = builder.build::<UniqueClock>().unwrap();
        assert!(!release_metadata.architectures.is_empty());
        similar_asserts::assert_eq!(
            release_metadata.serialize().to_string(),
            r#"Origin: TestOrigin
Label: TestLabel
Suite: test
Version: 0.1.0
Codename: testcode
Components: main
Date: Wed, 2 Feb 2000 01:02:02 +0000
Acquire-By-Hash: yes
Description: Test repo

MD5Sum:
 24494e2b696b17a2eb93c60ba0c748f5 194 main/binary-amd64/Packages
 91d18c5b19270aa56499f4acc31cd4b9 163 main/binary-amd64/Packages.gz
 4560b9c7df212c1581d534d4a0155574 95 main/i18n/Translation-en
 03ba6610c12e09a7f056d6f226897523 96 main/i18n/Translation-en.gz

SHA256:
 8540b64a3eb6bc9b0484d834ff12807404e36bb772ac4e2a670ac9cbbea25835 194 main/binary-amd64/Packages
 50d369648988d47ab31354996318e48efb94480e7691c330bd2eae22da8b2a11 163 main/binary-amd64/Packages.gz
 019bd63f026628d1fcea9640c827b81b62cf4b8663221786ff1115dde1c30067 95 main/i18n/Translation-en
 2b3d9c8e6b3c453c2cf5a460a6ba325bcf41c8c8917c5026dd84221e57c68aac 96 main/i18n/Translation-en.gz
"#
        );
    }

    #[tokio::test]
    async fn should_do_synchronize_successfully() {
        use crate::domain::entity::ReleaseWithAssets;

        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["owner/testrepo".to_string()],
        });

        let mut mock_package_source = MockPackageSource::new();
        mock_package_source
            .expect_stream_releases_with_assets()
            .returning(|_repo| {
                Box::pin(async {
                    Ok(vec![ReleaseWithAssets {
                        release_id: 1,
                        repo_owner: "owner".to_string(),
                        repo_name: "testrepo".to_string(),
                        assets: vec![
                            DebAsset {
                                repo_owner: "owner".to_string(),
                                repo_name: "testrepo".to_string(),
                                release_id: 1,
                                asset_id: 1,
                                filename: "pkg_1.0.0_amd64.deb".to_string(),
                                url: "http://example.com/pkg_1.0.0_amd64.deb".to_string(),
                                size: 1234,
                                sha256: Some("deadbeef".to_string()),
                            },
                            DebAsset {
                                repo_owner: "owner".to_string(),
                                repo_name: "testrepo".to_string(),
                                release_id: 1,
                                asset_id: 2,
                                filename: "pkg_1.0.0_arm64.deb".to_string(),
                                url: "http://example.com/pkg_1.0.0_arm64.deb".to_string(),
                                size: 1234,
                                sha256: Some("deadbit".to_string()),
                            },
                        ],
                    }])
                })
            });
        mock_package_source
            .expect_fetch_deb()
            .returning(|_asset| Box::pin(async { Ok(temp_file::empty()) }));

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_insert_release()
            .returning(|_entry| Box::pin(async {}));

        let mut mock_release_tracker = MockReleaseTracker::new();
        // No releases are scanned yet
        mock_release_tracker
            .expect_filter_scanned_releases()
            .returning(|_| Box::pin(async { Ok(std::collections::HashSet::new()) }));
        mock_release_tracker
            .expect_mark_releases_scanned()
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut mock_package_store = MockPackageStore::new();
        // Asset 2 is already cached
        mock_package_store
            .expect_find_package_by_asset_id()
            .withf(|id| *id == 2)
            .returning(|_| {
                Box::pin(async {
                    Some(Package {
                        metadata: PackageMetadata {
                            control: PackageControl {
                                package: "pkg".to_string(),
                                version: "1.0.0".to_string(),
                                section: Some("main".to_string()),
                                priority: "optional".to_string(),
                                architecture: "arm64".to_string(),
                                maintainer: "Tester <test@example.com>".to_string(),
                                description: vec!["A test package".to_string()],
                                others: HashMap::new(),
                            },
                            file: FileMetadata {
                                size: 1234,
                                sha256: "deadbit".to_string(),
                            },
                        },
                        asset: DebAsset {
                            repo_owner: "owner".to_string(),
                            repo_name: "testrepo".to_string(),
                            release_id: 1,
                            asset_id: 2,
                            filename: "pkg_1.0.0_arm64.deb".to_string(),
                            url: "http://example.com/pkg_1.0.0_arm64.deb".to_string(),
                            size: 1234,
                            sha256: Some("deadbit".to_string()),
                        },
                    })
                })
            });
        // Asset 1 is not cached
        mock_package_store
            .expect_find_package_by_asset_id()
            .withf(|id| *id == 1)
            .returning(|_| Box::pin(async { None }));
        mock_package_store
            .expect_insert_packages()
            .returning(|_| Box::pin(async { Ok(()) }));
        mock_package_store
            .expect_list_all_packages()
            .returning(|| Box::pin(async { Ok(vec![]) }));

        let mut mock_deb_extractor = MockDebMetadataExtractor::new();
        mock_deb_extractor
            .expect_extract_metadata()
            .returning(|_path| {
                Box::pin(async {
                    Ok(PackageMetadata {
                        control: PackageControl {
                            package: "pkg".to_string(),
                            version: "1.0.0".to_string(),
                            section: Some("main".to_string()),
                            priority: "optional".to_string(),
                            architecture: "amd64".to_string(),
                            maintainer: "Tester <test@example.com>".to_string(),
                            description: vec!["A test package".to_string()],
                            others: HashMap::new(),
                        },
                        file: FileMetadata {
                            size: 1234,
                            sha256: "deadbeef".to_string(),
                        },
                    })
                })
            });

        let mut service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: mock_package_source,
            release_storage: mock_release_store,
            deb_extractor: mock_deb_extractor,
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: mock_release_tracker,
            package_store: mock_package_store,
        };
        let result = AptRepositoryWriter::synchronize(&service).await;
        assert!(result.is_ok());
        service.deb_extractor.checkpoint();
        service.package_source.checkpoint();
        service.release_storage.checkpoint();
    }

    #[tokio::test]
    async fn should_do_synchronize_with_error() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["owner/testrepo".to_string()],
        });

        let mut mock_package_source = MockPackageSource::new();
        mock_package_source
            .expect_stream_releases_with_assets()
            .returning(|_repo| Box::pin(async { Err(anyhow::anyhow!("fail")) }));

        let mock_release_store = MockReleaseStore::new();

        let mut mock_package_store = MockPackageStore::new();
        mock_package_store
            .expect_list_all_packages()
            .returning(|| Box::pin(async { Ok(vec![]) }));

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: mock_package_source,
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: mock_package_store,
        };
        let result = AptRepositoryWriter::synchronize(&service).await;
        assert!(result.is_err());
    }

    // AptRepositoryReader tests

    #[tokio::test]
    async fn should_do_list_packages_successfully() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        let package = crate::domain::entity::Package {
            metadata: PackageMetadata {
                control: PackageControl {
                    package: "pkg".to_string(),
                    version: "1.0.0".to_string(),
                    section: Some("main".to_string()),
                    priority: "optional".to_string(),
                    architecture: "amd64".to_string(),
                    maintainer: "Tester <test@example.com>".to_string(),
                    description: vec!["A test package".to_string()],
                    others: HashMap::new(),
                },
                file: FileMetadata {
                    size: 1234,
                    sha256: "deadbeef".to_string(),
                },
            },
            asset: DebAsset {
                repo_owner: "owner".to_string(),
                repo_name: "testrepo".to_string(),
                release_id: 1,
                asset_id: 1,
                filename: "pkg_1.0.0_amd64.deb".to_string(),
                url: "http://example.com/pkg_1.0.0_amd64.deb".to_string(),
                size: 1234,
                sha256: Some("deadbeef".to_string()),
            },
        };
        let arch_meta = crate::domain::entity::ArchitectureMetadata {
            name: "amd64".to_string(),
            plain_md5: "md5".to_string(),
            plain_sha256: "sha256".to_string(),
            plain_size: 1,
            compressed_md5: "md5".to_string(),
            compressed_sha256: "sha256".to_string(),
            compressed_size: 1,
            packages: vec![package.clone()],
        };
        let release_meta = crate::domain::entity::ReleaseMetadata {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            date: chrono::Utc::now(),
            architectures: vec![arch_meta],
            components: vec!["main".to_string()],
            description: "Test repo".into(),
            translation: Default::default(),
        };
        mock_release_store
            .expect_find_latest_release()
            .returning(move || {
                let release_meta = release_meta.clone();
                Box::pin(async move { Some(release_meta) })
            });

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };
        let result =
            crate::domain::prelude::AptRepositoryReader::list_packages(&service, "amd64").await;
        assert!(result.is_ok());
        let pkgs = result.unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].metadata.control.package, "pkg");
    }

    #[tokio::test]
    async fn should_do_list_packages_empty() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_find_latest_release()
            .returning(|| Box::pin(async { None }));

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };
        let result =
            crate::domain::prelude::AptRepositoryReader::list_packages(&service, "amd64").await;
        assert!(result.is_ok());
        let pkgs = result.unwrap();
        assert_eq!(pkgs.len(), 0);
    }

    #[tokio::test]
    async fn should_do_release_metadata_successfully() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        let release_meta = crate::domain::entity::ReleaseMetadata {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            date: chrono::Utc::now(),
            architectures: vec![],
            components: vec!["main".to_string()],
            description: "Test repo".into(),
            translation: Default::default(),
        };
        mock_release_store
            .expect_find_latest_release()
            .returning(move || {
                let release_meta = release_meta.clone();
                Box::pin(async move { Some(release_meta) })
            });

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };
        let result = crate::domain::prelude::AptRepositoryReader::release_metadata(&service).await;
        assert!(result.is_ok());
        let meta = result.unwrap().unwrap();
        assert_eq!(meta.origin, "TestOrigin");
    }

    #[tokio::test]
    async fn should_do_release_metadata_not_found() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_find_latest_release()
            .returning(|| Box::pin(async { None }));

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };
        let result = crate::domain::prelude::AptRepositoryReader::release_metadata(&service).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn should_do_release_gpg_signature_successfully() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        let release_meta = crate::domain::entity::ReleaseMetadata {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            date: chrono::Utc::now(),
            architectures: vec![],
            components: vec!["main".to_string()],
            description: "Test repo".into(),
            translation: Default::default(),
        };
        mock_release_store
            .expect_find_latest_release()
            .returning(move || {
                let release_meta = release_meta.clone();
                Box::pin(async move { Some(release_meta) })
            });

        let mut mock_pgp_cipher = MockPGPCipher::new();
        mock_pgp_cipher
            .expect_sign()
            .returning(|_| Ok("SIGNATURE".to_string()));

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: mock_pgp_cipher,
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };
        let result =
            crate::domain::prelude::AptRepositoryReader::release_gpg_signature(&service).await;
        assert!(result.is_ok());
        let signature = result.unwrap().unwrap();
        assert_eq!(signature, "SIGNATURE");
    }

    #[tokio::test]
    async fn should_do_release_gpg_signature_not_found() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_find_latest_release()
            .returning(|| Box::pin(async { None }));

        let mock_pgp_cipher = MockPGPCipher::new();

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: mock_pgp_cipher,
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };
        let result =
            crate::domain::prelude::AptRepositoryReader::release_gpg_signature(&service).await;
        assert!(matches!(result, Ok(None)));
    }

    // Incremental synchronization tests

    #[tokio::test]
    async fn should_skip_already_scanned_releases() {
        use crate::domain::entity::ReleaseWithAssets;

        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["owner/repo".to_string()],
        });

        let mut mock_package_source = MockPackageSource::new();
        // Return two releases: one already scanned (id=1), one new (id=2)
        mock_package_source
            .expect_stream_releases_with_assets()
            .returning(|_repo| {
                Box::pin(async {
                    Ok(vec![
                        ReleaseWithAssets {
                            release_id: 1,
                            repo_owner: "owner".to_string(),
                            repo_name: "repo".to_string(),
                            assets: vec![DebAsset {
                                repo_owner: "owner".to_string(),
                                repo_name: "repo".to_string(),
                                release_id: 1,
                                asset_id: 100,
                                filename: "pkg_1.0.0_amd64.deb".to_string(),
                                url: "http://example.com/pkg_1.0.0_amd64.deb".to_string(),
                                size: 1234,
                                sha256: None,
                            }],
                        },
                        ReleaseWithAssets {
                            release_id: 2,
                            repo_owner: "owner".to_string(),
                            repo_name: "repo".to_string(),
                            assets: vec![DebAsset {
                                repo_owner: "owner".to_string(),
                                repo_name: "repo".to_string(),
                                release_id: 2,
                                asset_id: 200,
                                filename: "pkg_2.0.0_amd64.deb".to_string(),
                                url: "http://example.com/pkg_2.0.0_amd64.deb".to_string(),
                                size: 1234,
                                sha256: None,
                            }],
                        },
                    ])
                })
            });
        // fetch_deb should only be called once (for release 2)
        mock_package_source
            .expect_fetch_deb()
            .times(1)
            .returning(|_asset| Box::pin(async { Ok(temp_file::empty()) }));

        let mut mock_release_tracker = MockReleaseTracker::new();
        // Release 1 is already scanned, release 2 is not
        mock_release_tracker
            .expect_filter_scanned_releases()
            .returning(|_| {
                // Return release 1 as already scanned
                let mut scanned = std::collections::HashSet::new();
                scanned.insert(1u64);
                Box::pin(async move { Ok(scanned) })
            });
        // mark_releases_scanned should only be called for release 2
        mock_release_tracker
            .expect_mark_releases_scanned()
            .withf(|releases| releases.len() == 1 && releases[0].release_id == 2)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut mock_package_store = MockPackageStore::new();
        // find_package_by_asset_id should be called for the new package (release 2, asset 200)
        mock_package_store
            .expect_find_package_by_asset_id()
            .withf(|id| *id == 200)
            .times(1)
            .returning(|_| Box::pin(async { None }));
        // insert_packages should only be called for the new package
        mock_package_store
            .expect_insert_packages()
            .withf(|packages| packages.len() == 1)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));
        mock_package_store
            .expect_list_all_packages()
            .returning(|| Box::pin(async { Ok(vec![]) }));

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_insert_release()
            .returning(|_| Box::pin(async {}));

        let mut mock_deb_extractor = MockDebMetadataExtractor::new();
        mock_deb_extractor
            .expect_extract_metadata()
            .returning(|_path| {
                Box::pin(async {
                    Ok(PackageMetadata {
                        control: PackageControl {
                            package: "pkg".to_string(),
                            version: "2.0.0".to_string(),
                            section: Some("main".to_string()),
                            priority: "optional".to_string(),
                            architecture: "amd64".to_string(),
                            maintainer: "Tester <test@example.com>".to_string(),
                            description: vec!["A test package".to_string()],
                            others: HashMap::new(),
                        },
                        file: FileMetadata {
                            size: 1234,
                            sha256: "deadbeef".to_string(),
                        },
                    })
                })
            });

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: mock_package_source,
            release_storage: mock_release_store,
            deb_extractor: mock_deb_extractor,
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: mock_release_tracker,
            package_store: mock_package_store,
        };

        let result = AptRepositoryWriter::synchronize(&service).await;
        assert!(result.is_ok());
        // The assertions are in the mock expectations (times(1))
    }

    #[tokio::test]
    async fn should_rebuild_metadata_from_stored_packages() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["owner/repo".to_string()],
        });

        let mut mock_package_source = MockPackageSource::new();
        mock_package_source
            .expect_stream_releases_with_assets()
            .returning(|_repo| Box::pin(async { Ok(vec![]) }));

        let mock_release_tracker = MockReleaseTracker::new();
        // No expectations needed - no releases to process

        let mut mock_package_store = MockPackageStore::new();
        // Return some existing packages
        mock_package_store.expect_list_all_packages().returning(|| {
            Box::pin(async {
                Ok(vec![Package {
                    metadata: PackageMetadata {
                        control: PackageControl {
                            package: "existing-pkg".to_string(),
                            version: "1.0.0".to_string(),
                            section: Some("main".to_string()),
                            priority: "optional".to_string(),
                            architecture: "amd64".to_string(),
                            maintainer: "Tester <test@example.com>".to_string(),
                            description: vec!["An existing package".to_string()],
                            others: HashMap::new(),
                        },
                        file: FileMetadata {
                            size: 1234,
                            sha256: "existingsha".to_string(),
                        },
                    },
                    asset: DebAsset {
                        repo_owner: "owner".to_string(),
                        repo_name: "repo".to_string(),
                        release_id: 1,
                        asset_id: 100,
                        filename: "existing-pkg_1.0.0_amd64.deb".to_string(),
                        url: "http://example.com/existing-pkg_1.0.0_amd64.deb".to_string(),
                        size: 1234,
                        sha256: None,
                    },
                }])
            })
        });

        let mut mock_release_store = MockReleaseStore::new();
        // Verify that insert_release is called with metadata built from stored packages
        mock_release_store
            .expect_insert_release()
            .withf(|release| {
                release.architectures.len() == 1
                    && release.architectures[0].packages.len() == 1
                    && release.architectures[0].packages[0]
                        .metadata
                        .control
                        .package
                        == "existing-pkg"
            })
            .times(1)
            .returning(|_| Box::pin(async {}));

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: mock_package_source,
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: mock_release_tracker,
            package_store: mock_package_store,
        };

        // This test will fail until we implement incremental sync
        let _result = AptRepositoryWriter::synchronize(&service).await;
    }

    // find_architecture_by_hash tests

    #[tokio::test]
    async fn should_find_architecture_by_plain_hash() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        let arch_meta = crate::domain::entity::ArchitectureMetadata {
            name: "amd64".to_string(),
            plain_md5: "plainmd5".to_string(),
            plain_sha256: "plainsha256".to_string(),
            plain_size: 100,
            compressed_md5: "compressedmd5".to_string(),
            compressed_sha256: "compressedsha256".to_string(),
            compressed_size: 50,
            packages: vec![],
        };
        let release_meta = crate::domain::entity::ReleaseMetadata {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            date: chrono::Utc::now(),
            architectures: vec![arch_meta],
            components: vec!["main".to_string()],
            description: "Test repo".into(),
            translation: Default::default(),
        };
        mock_release_store
            .expect_find_latest_release()
            .returning(move || {
                let release_meta = release_meta.clone();
                Box::pin(async move { Some(release_meta) })
            });

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };

        let result = crate::domain::prelude::AptRepositoryReader::find_architecture_by_hash(
            &service,
            "plainsha256",
        )
        .await;
        assert!(result.is_ok());
        let hash_match = result.unwrap().unwrap();
        assert_eq!(hash_match.architecture, "amd64");
        assert!(!hash_match.compressed);
    }

    #[tokio::test]
    async fn should_find_architecture_by_compressed_hash() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        let arch_meta = crate::domain::entity::ArchitectureMetadata {
            name: "arm64".to_string(),
            plain_md5: "plainmd5".to_string(),
            plain_sha256: "plainsha256".to_string(),
            plain_size: 100,
            compressed_md5: "compressedmd5".to_string(),
            compressed_sha256: "compressedsha256".to_string(),
            compressed_size: 50,
            packages: vec![],
        };
        let release_meta = crate::domain::entity::ReleaseMetadata {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            date: chrono::Utc::now(),
            architectures: vec![arch_meta],
            components: vec!["main".to_string()],
            description: "Test repo".into(),
            translation: Default::default(),
        };
        mock_release_store
            .expect_find_latest_release()
            .returning(move || {
                let release_meta = release_meta.clone();
                Box::pin(async move { Some(release_meta) })
            });

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };

        let result = crate::domain::prelude::AptRepositoryReader::find_architecture_by_hash(
            &service,
            "compressedsha256",
        )
        .await;
        assert!(result.is_ok());
        let hash_match = result.unwrap().unwrap();
        assert_eq!(hash_match.architecture, "arm64");
        assert!(hash_match.compressed);
    }

    #[tokio::test]
    async fn should_return_none_for_unknown_hash() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        let arch_meta = crate::domain::entity::ArchitectureMetadata {
            name: "amd64".to_string(),
            plain_md5: "plainmd5".to_string(),
            plain_sha256: "plainsha256".to_string(),
            plain_size: 100,
            compressed_md5: "compressedmd5".to_string(),
            compressed_sha256: "compressedsha256".to_string(),
            compressed_size: 50,
            packages: vec![],
        };
        let release_meta = crate::domain::entity::ReleaseMetadata {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            date: chrono::Utc::now(),
            architectures: vec![arch_meta],
            components: vec!["main".to_string()],
            description: "Test repo".into(),
            translation: Default::default(),
        };
        mock_release_store
            .expect_find_latest_release()
            .returning(move || {
                let release_meta = release_meta.clone();
                Box::pin(async move { Some(release_meta) })
            });

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };

        let result = crate::domain::prelude::AptRepositoryReader::find_architecture_by_hash(
            &service,
            "unknownhash",
        )
        .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn should_return_none_when_no_release() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_find_latest_release()
            .returning(|| Box::pin(async { None }));

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: MockPackageSource::new(),
            release_storage: mock_release_store,
            deb_extractor: MockDebMetadataExtractor::new(),
            pgp_cipher: MockPGPCipher::new(),
            release_tracker: MockReleaseTracker::new(),
            package_store: MockPackageStore::new(),
        };

        let result = crate::domain::prelude::AptRepositoryReader::find_architecture_by_hash(
            &service, "anyhash",
        )
        .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
