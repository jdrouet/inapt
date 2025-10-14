use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    io::Write,
    marker::PhantomData,
    sync::Arc,
};

use flate2::{Compression, write::GzEncoder};
use futures::{StreamExt, TryStreamExt};
use sha2::Digest;

pub(crate) mod entity;
pub(crate) mod prelude;

#[derive(Debug)]
pub struct Config {
    // Origin: Debian
    pub origin: Cow<'static, str>,
    // Label: Debian
    pub label: Cow<'static, str>,
    // Suite: stable
    pub suite: Cow<'static, str>,
    // Version: 12.5
    pub version: Cow<'static, str>,
    // Codename: bookworm
    pub codename: Cow<'static, str>,
    // Date: Tue, 04 Jun 2024 12:34:56 UTC
    // pub date: String,
    // Architectures: amd64 arm64
    // Components: main contrib non-free
    pub description: Cow<'static, str>,
    // Description: Debian 12.5 Release
    pub repositories: Vec<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            origin: crate::with_env_or("REPO_ORIGIN", "GitHub releases"),
            label: crate::with_env_or("REPO_LABEL", "Debian"),
            suite: crate::with_env_or("REPO_SUITE", "stable"),
            version: crate::with_env_or("REPO_VERSION", env!("CARGO_PKG_VERSION")),
            codename: crate::with_env_or("REPO_CODENAME", "cucumber"),
            description: crate::with_env_or("REPO_DESCRIPTION", "GitHub releases proxy"),
            repositories: crate::with_env_as_many("REPO_REPOSITORIES", ","),
        })
    }
}

#[derive(Clone, Debug)]
pub struct AptRepositoryService<C, PS, RS, DE, PGP> {
    pub config: Arc<Config>,
    pub clock: PhantomData<C>,
    pub package_source: PS,
    pub release_storage: RS,
    pub deb_extractor: DE,
    pub pgp_cipher: PGP,
}

impl<C, PS, RS, DE, PGP> prelude::AptRepositoryReader for AptRepositoryService<C, PS, RS, DE, PGP>
where
    C: Send + Sync + 'static,
    PS: Send + Sync + 'static,
    RS: crate::domain::prelude::ReleaseStore,
    DE: Send + Sync + 'static,
    PGP: crate::domain::prelude::PGPCipher,
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
        let signed = self.pgp_cipher.sign(metadata.as_str())?;
        Ok(Some(signed))
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
}

impl<C, PS, RS, DE, PGP> AptRepositoryService<C, PS, RS, DE, PGP>
where
    C: prelude::Clock,
    PS: prelude::PackageSource,
    RS: prelude::ReleaseStore,
    DE: prelude::DebMetadataExtractor,
    PGP: prelude::PGPCipher,
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
        if let Some(package) = self.release_storage.find_package_by_asset(&asset).await {
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
    async fn synchronize_repo(
        &self,
        repo: &str,
        builder: &mut ReleaseMetadataBuilder,
    ) -> anyhow::Result<()> {
        tracing::info!("listing assets");
        let list = self.package_source.list_deb_assets(repo).await?;
        let list = futures::stream::iter(
            list.into_iter()
                .map(|asset| async move { self.handle_package(asset).await }),
        )
        .buffer_unordered(5)
        .try_collect::<Vec<_>>()
        .await?;
        list.into_iter().for_each(|item| {
            if let Some(item) = item {
                builder.insert(item);
            }
        });
        Ok(())
    }
}

impl<C, PS, RS, DE, PGP> prelude::AptRepositoryWriter for AptRepositoryService<C, PS, RS, DE, PGP>
where
    C: prelude::Clock,
    PS: prelude::PackageSource,
    RS: prelude::ReleaseStore,
    DE: prelude::DebMetadataExtractor,
    PGP: prelude::PGPCipher,
{
    #[tracing::instrument(skip(self), err(Debug))]
    async fn synchronize(&self) -> anyhow::Result<()> {
        let mut builder = ReleaseMetadataBuilder::new(self.config.clone());
        let mut errors = Vec::with_capacity(self.config.repositories.len());
        for repo in self.config.repositories.iter() {
            if let Err(err) = self.synchronize_repo(repo.as_str(), &mut builder).await {
                errors.push(err);
            }
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
        Ok(entity::ReleaseMetadata {
            origin: self.config.origin.clone(),
            label: self.config.label.clone(),
            suite: self.config.suite.clone(),
            version: self.config.version.clone(),
            codename: self.config.codename.clone(),
            date: C::now(),
            architectures: self
                .architectures
                .into_iter()
                .map(|(name, values)| values.build(name))
                .collect::<Result<_, _>>()?,
            components: vec!["main".into()],
            description: self.config.description.clone(),
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
        MockReleaseStore,
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
Description: Test repo

MD5Sum:
 24494e2b696b17a2eb93c60ba0c748f5 194 main/binary-amd64/Packages
 91d18c5b19270aa56499f4acc31cd4b9 163 main/binary-amd64/Packages.gz

SHA256:
 8540b64a3eb6bc9b0484d834ff12807404e36bb772ac4e2a670ac9cbbea25835 194 main/binary-amd64/Packages
 50d369648988d47ab31354996318e48efb94480e7691c330bd2eae22da8b2a11 163 main/binary-amd64/Packages.gz
"#
        );
    }

    #[tokio::test]
    async fn should_do_synchronize_successfully() {
        let config = Arc::new(Config {
            origin: "TestOrigin".into(),
            label: "TestLabel".into(),
            suite: "test".into(),
            version: "0.1.0".into(),
            codename: "testcode".into(),
            description: "Test repo".into(),
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_package_source = MockPackageSource::new();
        mock_package_source
            .expect_list_deb_assets()
            .returning(|repo| {
                let repo = repo.to_string();
                Box::pin(async move {
                    Ok(vec![
                        DebAsset {
                            repo_owner: "owner".to_string(),
                            repo_name: repo.clone(),
                            release_id: 1,
                            asset_id: 1,
                            filename: "pkg_1.0.0_amd64.deb".to_string(),
                            url: "http://example.com/pkg_1.0.0_amd64.deb".to_string(),
                            size: 1234,
                            sha256: Some("deadbeef".to_string()),
                        },
                        DebAsset {
                            repo_owner: "owner".to_string(),
                            repo_name: repo.clone(),
                            release_id: 1,
                            asset_id: 2,
                            filename: "pkg_1.0.0_arm64.deb".to_string(),
                            url: "http://example.com/pkg_1.0.0_arm64.deb".to_string(),
                            size: 1234,
                            sha256: Some("deadbit".to_string()),
                        },
                    ])
                })
            });
        mock_package_source
            .expect_fetch_deb()
            .returning(|_asset| Box::pin(async { Ok(temp_file::empty()) }));

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_insert_release()
            .returning(|_entry| Box::pin(async {}));
        mock_release_store
            .expect_find_package_by_asset()
            .returning(|asset| {
                let asset = asset.clone();
                Box::pin(async move {
                    if asset.asset_id == 2 {
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
                            asset: asset.clone(),
                        })
                    } else {
                        None
                    }
                })
            });
        mock_release_store
            .expect_find_latest_release()
            .returning(|| Box::pin(async { None }));

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
            repositories: vec!["testrepo".to_string()],
        });

        let mut mock_package_source = MockPackageSource::new();
        mock_package_source
            .expect_list_deb_assets()
            .returning(|_repo| Box::pin(async { Err(anyhow::anyhow!("fail")) }));
        mock_package_source
            .expect_fetch_deb()
            .returning(|_asset| Box::pin(async { Err(anyhow::anyhow!("fail")) }));

        let mut mock_release_store = MockReleaseStore::new();
        mock_release_store
            .expect_insert_release()
            .returning(|_entry| Box::pin(async {}));
        mock_release_store
            .expect_find_latest_release()
            .returning(|| Box::pin(async { None }));

        let mut mock_deb_extractor = MockDebMetadataExtractor::new();
        mock_deb_extractor
            .expect_extract_metadata()
            .returning(|_path| Box::pin(async { Err(anyhow::anyhow!("fail")) }));

        let service = AptRepositoryService {
            config,
            clock: PhantomData::<UniqueClock>,
            package_source: mock_package_source,
            release_storage: mock_release_store,
            deb_extractor: mock_deb_extractor,
            pgp_cipher: MockPGPCipher::new(),
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
        };
        let result = crate::domain::prelude::AptRepositoryReader::release_metadata(&service).await;
        assert!(matches!(result, Ok(None)));
    }
}
