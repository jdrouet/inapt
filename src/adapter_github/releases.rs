impl super::Client {
    async fn list_deb_assets_per_page(
        &self,
        owner: &str,
        repo: &str,
        page: u32,
    ) -> anyhow::Result<(Vec<crate::domain::entity::DebAsset>, bool)> {
        let result = self
            .inner
            .repos(owner, repo)
            .releases()
            .list()
            .page(page)
            .per_page(100)
            .send()
            .await?;
        let has_more = result.next.is_some();
        let list = result
            .into_iter()
            .filter(|item| !item.draft && !item.prerelease)
            .flat_map(|item| {
                item.assets
                    .into_iter()
                    .filter(|asset| asset.name.ends_with(".deb"))
                    .map(move |asset| crate::domain::entity::DebAsset {
                        repo_owner: owner.to_string(),
                        repo_name: repo.to_string(),
                        release_id: item.id.into_inner(),
                        asset_id: asset.id.into_inner(),
                        filename: asset.name,
                        size: asset.size as u64,
                        url: asset.browser_download_url.to_string(),
                        sha256: None,
                    })
            })
            .collect::<Vec<_>>();
        Ok((list, has_more))
    }
}

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

        let mut byte_stream = reqwest::get(&asset.url).await?.bytes_stream();
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
        let Some((owner, repo)) = repo.split_once('/') else {
            anyhow::bail!("unable to get owner and repo name")
        };
        let mut list = Vec::with_capacity(1024);
        let mut page: u32 = 0;
        loop {
            let (found, has_more) = self.list_deb_assets_per_page(owner, repo, page).await?;
            list.extend(found.into_iter());
            page += 1;
            if !has_more {
                break;
            }
        }
        Ok(list)
    }
}
