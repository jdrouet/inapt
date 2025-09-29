mod deb;
mod file;

#[derive(Clone, Debug)]
pub struct DebReader;

impl crate::domain::prelude::DebMetadataExtractor for DebReader {
    async fn extract_metadata(
        &self,
        path: &std::path::Path,
    ) -> anyhow::Result<crate::domain::entity::PackageMetadata> {
        Ok(crate::domain::entity::PackageMetadata {
            control: deb::from_path(path)?,
            file: file::from_path(path)?,
        })
    }
}
