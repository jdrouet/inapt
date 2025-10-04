use crate::adapter_github::entity::Repository;

impl crate::domain::prelude::PackageSource for super::Client {
    #[tracing::instrument(skip_all, fields(filename = asset.filename), err(Debug))]
    async fn fetch_deb(
        &self,
        asset: &crate::domain::entity::DebAsset,
    ) -> anyhow::Result<temp_file::TempFile> {
        use futures::StreamExt;

        let file = temp_file::empty();
        let mut tmp_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file.path())
            .await?;

        let mut byte_stream = self.inner.get(&asset.url).send().await?.bytes_stream();
        tracing::info!("downloading file");
        while let Some(item) = byte_stream.next().await {
            tokio::io::copy(&mut item?.as_ref(), &mut tmp_file).await?;
        }
        tracing::info!("download complete");

        Ok(file)
    }

    #[tracing::instrument(skip(self), err(Debug))]
    async fn list_deb_assets(
        &self,
        repo: &str,
    ) -> anyhow::Result<Vec<crate::domain::entity::DebAsset>> {
        let Some((repo_owner, repo_name)) = repo.split_once('/') else {
            anyhow::bail!("unable to get owner and repo name")
        };

        let mut result = Vec::new();
        let repo = Repository::new(repo_owner, repo_name);
        let mut release_stream = self.stream_releases(repo);
        while let Ok(Some(release)) = release_stream.next().await {
            for asset in release.assets {
                if asset.browser_download_url.ends_with(".deb") {
                    result.push(crate::domain::entity::DebAsset {
                        repo_owner: repo_owner.to_string(),
                        repo_name: repo_name.to_string(),
                        release_id: release.id,
                        asset_id: asset.id,
                        filename: asset.name,
                        size: asset.size,
                        url: asset.browser_download_url,
                        sha256: None,
                    });
                }
            }
        }
        Ok(result)
    }
}
