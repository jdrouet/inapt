use std::sync::Arc;

pub(crate) mod entity;
pub(crate) mod prelude;

#[derive(Clone, Debug)]
pub struct AptRepositoryService<PS> {
    pub repositories: Arc<[String]>,
    pub package_source: PS,
}

impl<PS> prelude::AptRepositoryReader for AptRepositoryService<PS>
where
    PS: Send + Sync + 'static,
{
    async fn list_packages(&self, arch: &str) -> anyhow::Result<Vec<entity::Package>> {
        todo!()
    }

    async fn packages_file(&self, arch: &str) -> anyhow::Result<String> {
        todo!()
    }

    async fn release_metadata(&self) -> anyhow::Result<entity::ReleaseMetadata> {
        todo!()
    }
}

impl<PS> AptRepositoryService<PS>
where
    PS: crate::domain::prelude::PackageSource,
{
    #[tracing::instrument(skip(self), err(Debug))]
    async fn synchronize_repo(&self, repo: &str) -> anyhow::Result<()> {
        let list = self.package_source.list_deb_assets(repo).await?;
        for asset in list {
            let deb_file = self.package_source.fetch_deb(&asset).await?;
        }
        Ok(())
    }
}

impl<PS> prelude::AptRepositoryWriter for AptRepositoryService<PS>
where
    PS: crate::domain::prelude::PackageSource,
{
    #[tracing::instrument(skip(self), err(Debug))]
    async fn synchronize(&self) -> anyhow::Result<()> {
        let mut errors = Vec::with_capacity(self.repositories.len());
        for repo in self.repositories.iter() {
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
