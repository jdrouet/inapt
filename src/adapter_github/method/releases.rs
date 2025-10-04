use std::collections::VecDeque;

use anyhow::Context;

use crate::adapter_github::entity::{Pagination, Release, Repository};

const PAGE_SIZE: u32 = 10;

impl crate::adapter_github::Client {
    pub(crate) async fn list_releases(
        &self,
        repo: Repository<'_>,
        page: Pagination,
    ) -> anyhow::Result<Vec<Release>> {
        let url = format!(
            "{}/repos/{}/{}/releases",
            self.base_url, repo.owner, repo.name
        );
        let res = self
            .inner
            .get(&url)
            .query(&page)
            .send()
            .await
            .context("unable to request")?;
        res.error_for_status_ref()?;
        res.json().await.context("unable to read response")
    }

    pub(crate) fn stream_releases<'a>(&'a self, repo: Repository<'a>) -> ReleaseStreamer<'a> {
        ReleaseStreamer::new(self, repo)
    }
}

pub(crate) struct ReleaseStreamer<'a> {
    client: &'a crate::adapter_github::Client,
    repo: Repository<'a>,
    page_size: u32,
    page_index: u32,
    has_more: bool,
    cache: VecDeque<Release>,
}

impl<'a> ReleaseStreamer<'a> {
    fn new(client: &'a crate::adapter_github::Client, repo: Repository<'a>) -> Self {
        Self {
            client,
            repo,
            page_size: PAGE_SIZE,
            page_index: 0,
            has_more: true,
            cache: VecDeque::default(),
        }
    }

    async fn fetch_next_page(&mut self) -> anyhow::Result<()> {
        self.page_index += 1;
        let list = self
            .client
            .list_releases(self.repo, Pagination::new(self.page_index, self.page_size))
            .await?;
        self.has_more = !list.is_empty();
        self.cache = list
            .into_iter()
            .filter(|item| !item.draft && !item.prerelease)
            .collect();
        Ok(())
    }

    pub(crate) async fn next(&mut self) -> anyhow::Result<Option<Release>> {
        tracing::info!(has_more = self.has_more, cache = self.cache.len(), "next");
        while self.has_more || !self.cache.is_empty() {
            if let Some(item) = self.cache.pop_front() {
                return Ok(Some(item));
            }
            self.fetch_next_page().await.inspect_err(|err| {
                tracing::error!(error = ?err, "unable to fetch next page");
            })?;
        }
        Ok(None)
    }
}
