pub(crate) mod entity;
pub(crate) mod prelude;

#[derive(Clone, Debug)]
pub(crate) struct AptRepositoryService {}

impl prelude::AptRepository for AptRepositoryService {
    async fn list_packages(&self, _arch: &str) -> anyhow::Result<Vec<entity::Package>> {
        todo!()
    }

    async fn packages_file(&self, _arch: &str) -> anyhow::Result<String> {
        todo!()
    }

    async fn release_metadata(&self) -> anyhow::Result<entity::ReleaseMetadata> {
        todo!()
    }
}
