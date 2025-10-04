#[derive(Debug, serde::Deserialize)]
pub struct Asset {
    pub id: u64,
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

#[derive(Debug, serde::Deserialize)]
pub struct Release {
    pub id: u64,
    // pub name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Pagination {
    pub per_page: u32,
    pub page: u32,
}

impl Pagination {
    pub fn new(page: u32, per_page: u32) -> Self {
        Self { per_page, page }
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Repository<'a> {
    pub owner: &'a str,
    pub name: &'a str,
}

impl<'a> Repository<'a> {
    pub fn new(owner: &'a str, name: &'a str) -> Self {
        Self { owner, name }
    }
}
