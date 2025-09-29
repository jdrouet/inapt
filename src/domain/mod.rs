use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    sync::Arc,
};

use flate2::{Compression, write::GzEncoder};
use sha2::Digest;

use crate::domain::entity::Package;

pub(crate) mod entity;
pub(crate) mod prelude;

#[derive(Debug)]
pub struct Config {
    // Origin: Debian
    pub origin: String,
    // Label: Debian
    pub label: String,
    // Suite: stable
    pub suite: String,
    // Version: 12.5
    pub version: String,
    // Codename: bookworm
    pub codename: String,
    // Date: Tue, 04 Jun 2024 12:34:56 UTC
    // pub date: String,
    // Architectures: amd64 arm64
    // Components: main contrib non-free
    pub description: String,
    // Description: Debian 12.5 Release
    pub repositories: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AptRepositoryService<PS, RS, DE> {
    pub config: Arc<Config>,
    pub package_source: PS,
    pub release_storage: RS,
    pub deb_extractor: DE,
}

impl<PS, RS, DE> prelude::AptRepositoryReader for AptRepositoryService<PS, RS, DE>
where
    PS: Send + Sync + 'static,
    RS: crate::domain::prelude::ReleaseStore,
    DE: Send + Sync + 'static,
{
    async fn list_packages(&self, arch: &str) -> anyhow::Result<Vec<entity::Package>> {
        todo!()
    }

    async fn packages_file(&self, arch: &str) -> anyhow::Result<String> {
        todo!()
    }

    async fn release_metadata(
        &self,
    ) -> Result<entity::ReleaseMetadata, prelude::GetReleaseFileError> {
        let received = self.release_storage.fetch().await;
        received.ok_or(prelude::GetReleaseFileError::NotFound)
    }
}

impl<PS, RS, DE> AptRepositoryService<PS, RS, DE>
where
    PS: crate::domain::prelude::PackageSource,
    RS: crate::domain::prelude::ReleaseStore,
    DE: crate::domain::prelude::DebMetadataExtractor,
{
    #[tracing::instrument(skip(self), err(Debug))]
    async fn synchronize_repo(&self, repo: &str) -> anyhow::Result<()> {
        let list = self.package_source.list_deb_assets(repo).await?;
        let mut builder = ReleaseMetadataBuilder::new(self.config.clone());
        for asset in list {
            let deb_file = self.package_source.fetch_deb(&asset).await?;
            let metadata = self.deb_extractor.extract_metadata(deb_file.path()).await?;
            builder.insert(entity::Package { metadata, asset });
        }
        self.release_storage.insert(builder.build()?).await;
        Ok(())
    }
}

impl<PS, RS, DE> prelude::AptRepositoryWriter for AptRepositoryService<PS, RS, DE>
where
    PS: crate::domain::prelude::PackageSource,
    RS: crate::domain::prelude::ReleaseStore,
    DE: crate::domain::prelude::DebMetadataExtractor,
{
    #[tracing::instrument(skip(self), err(Debug))]
    async fn synchronize(&self) -> anyhow::Result<()> {
        let mut errors = Vec::with_capacity(self.config.repositories.len());
        for repo in self.config.repositories.iter() {
            if let Err(err) = self.synchronize_repo(repo.as_str()).await {
                errors.push(err);
            }
        }
        if errors.is_empty() {
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

    fn insert(&mut self, package: Package) {
        self.architectures
            .entry(package.metadata.control.architecture.clone())
            .or_default()
            .insert(package);
    }

    fn build(self) -> anyhow::Result<entity::ReleaseMetadata> {
        Ok(entity::ReleaseMetadata {
            origin: self.config.origin.clone(),
            label: self.config.label.clone(),
            suite: self.config.suite.clone(),
            version: "0.1.0".into(),
            codename: self.config.codename.clone(),
            date: "now".into(),
            architectures: self
                .architectures
                .into_iter()
                .map(|(name, values)| values.build(name))
                .collect::<Result<_, _>>()?,
            components: vec!["main".into()],
            description: "Proxy to GitHub releases".into(),
        })
    }
}

#[derive(Debug, Default)]
struct ArchitectureMetadataBuilder {
    packages: BTreeMap<String, BTreeMap<String, Package>>,
}

impl ArchitectureMetadataBuilder {
    fn insert(&mut self, package: Package) {
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
                plain_sha256_hasher.write(b"\n")?;
                plain_md5_hasher.write(b"\n")?;
                gz_encoder.write(b"\n")?;
                plain_size += 1;
            }
            let display = package.metadata.serialize().to_string();
            plain_size += display.len() as u64;
            plain_sha256_hasher.write(display.as_bytes())?;
            plain_md5_hasher.write(display.as_bytes())?;
            gz_encoder.write(display.as_bytes())?;
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
