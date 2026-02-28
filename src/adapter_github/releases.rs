use crate::adapter_github::entity::Repository;

impl super::Client {
    /// Download a remote asset to a temporary file by URL.
    async fn download_asset(&self, url: &str) -> anyhow::Result<temp_file::TempFile> {
        use futures::StreamExt;

        let file = temp_file::empty();
        let mut tmp_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file.path())
            .await?;

        let mut byte_stream = self.inner.get(url).send().await?.bytes_stream();
        tracing::info!("downloading file");
        while let Some(item) = byte_stream.next().await {
            tokio::io::copy(&mut item?.as_ref(), &mut tmp_file).await?;
        }
        tracing::info!("download complete");

        Ok(file)
    }

    /// Parse a "owner/name" repo string into its two parts.
    fn parse_repo(repo: &str) -> anyhow::Result<(&str, &str)> {
        repo.split_once('/')
            .ok_or_else(|| anyhow::anyhow!("unable to get owner and repo name"))
    }
}

impl crate::domain::prelude::PackageSource for super::Client {
    #[tracing::instrument(skip_all, fields(filename = asset.filename), err(Debug))]
    async fn fetch_deb(
        &self,
        asset: &crate::domain::entity::DebAsset,
    ) -> anyhow::Result<temp_file::TempFile> {
        self.download_asset(&asset.url).await
    }

    #[tracing::instrument(skip(self), err(Debug))]
    async fn stream_releases_with_assets(
        &self,
        repo: &str,
    ) -> anyhow::Result<Vec<crate::domain::entity::ReleaseWithAssets>> {
        let (repo_owner, repo_name) = Self::parse_repo(repo)?;

        let mut result = Vec::new();
        let repo_ref = Repository::new(repo_owner, repo_name);
        let mut release_stream = self.stream_releases(repo_ref);
        while let Ok(Some(release)) = release_stream.next().await {
            let assets: Vec<crate::domain::entity::DebAsset> = release
                .assets
                .into_iter()
                .filter(|asset| asset.browser_download_url.ends_with(".deb"))
                .map(|asset| crate::domain::entity::DebAsset {
                    repo_owner: repo_owner.to_string(),
                    repo_name: repo_name.to_string(),
                    release_id: release.id,
                    asset_id: asset.id,
                    filename: asset.name,
                    size: asset.size,
                    url: asset.browser_download_url,
                    sha256: None,
                })
                .collect();

            result.push(crate::domain::entity::ReleaseWithAssets {
                release_id: release.id,
                repo_owner: repo_owner.to_string(),
                repo_name: repo_name.to_string(),
                assets,
            });
        }
        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(filename = asset.filename), err(Debug))]
    async fn fetch_apk(
        &self,
        asset: &crate::domain::entity::ApkAsset,
    ) -> anyhow::Result<temp_file::TempFile> {
        self.download_asset(&asset.url).await
    }

    #[tracing::instrument(skip(self), err(Debug))]
    async fn stream_apk_releases_with_assets(
        &self,
        repo: &str,
    ) -> anyhow::Result<Vec<crate::domain::entity::ApkReleaseWithAssets>> {
        let (repo_owner, repo_name) = Self::parse_repo(repo)?;

        let mut result = Vec::new();
        let repo_ref = Repository::new(repo_owner, repo_name);
        let mut release_stream = self.stream_releases(repo_ref);
        while let Ok(Some(release)) = release_stream.next().await {
            let assets: Vec<crate::domain::entity::ApkAsset> = release
                .assets
                .into_iter()
                .filter(|asset| asset.browser_download_url.ends_with(".apk"))
                .map(|asset| crate::domain::entity::ApkAsset {
                    repo_owner: repo_owner.to_string(),
                    repo_name: repo_name.to_string(),
                    release_id: release.id,
                    asset_id: asset.id,
                    filename: asset.name,
                    size: asset.size,
                    url: asset.browser_download_url,
                    sha256: None,
                })
                .collect();

            result.push(crate::domain::entity::ApkReleaseWithAssets {
                release_id: release.id,
                repo_owner: repo_owner.to_string(),
                repo_name: repo_name.to_string(),
                assets,
            });
        }
        Ok(result)
    }
}
