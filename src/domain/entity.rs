/// Represents a Debian package in the repository.
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub metadata: PackageMetadata,
    pub asset: DebAsset,
}

/// Metadata extracted from a .deb file's control section.
#[derive(Debug, Clone)]
pub struct PackageMetadata {
    pub description: String,
    pub maintainer: String,
    pub section: String,
    pub priority: String,
    pub installed_size: Option<u64>,
    pub dependencies: Vec<String>,
    // Add more fields as needed
}

/// Metadata for the Release file.
#[derive(Debug, Clone)]
pub struct ReleaseMetadata {
    pub suite: String,
    pub component: String,
    pub architectures: Vec<String>,
    pub date: String,
    // Add more fields as needed
}

/// Represents a .deb asset (source, filename, URL, etc.).
#[derive(Debug, Clone)]
pub struct DebAsset {
    pub repo_owner: String,
    pub repo_name: String,
    pub release_id: u64,
    pub asset_id: u64,
    pub filename: String,
    pub url: String,
    pub size: u64,
    pub sha256: Option<String>,
}
