use std::sync::Arc;

use chrono::Utc;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use tokio::sync::RwLock;

use crate::domain::entity::{
    DebAsset, FileMetadata, Package, PackageControl, PackageMetadata, ReleaseMetadata,
};

#[derive(Debug, serde::Deserialize)]
pub(crate) struct Config {
    pub path: std::path::PathBuf,
}

impl Config {
    pub async fn build(self) -> anyhow::Result<SqliteStorage> {
        SqliteStorage::new(self.path).await
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SqliteStorage {
    pool: SqlitePool,
    // Cache for ReleaseMetadata to avoid rebuilding on every request
    release_cache: Arc<RwLock<Option<ReleaseMetadata>>>,
}

impl SqliteStorage {
    pub async fn new(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self {
            pool,
            release_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Invalidate the release cache when packages change
    async fn invalidate_cache(&self) {
        let mut cache = self.release_cache.write().await;
        *cache = None;
    }
}

impl crate::domain::prelude::ReleaseTracker for SqliteStorage {
    async fn is_release_scanned(
        &self,
        repo_owner: &str,
        repo_name: &str,
        release_id: u64,
    ) -> anyhow::Result<bool> {
        let result: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM github_releases WHERE repo_owner = ? AND repo_name = ? AND id = ?",
        )
        .bind(repo_owner)
        .bind(repo_name)
        .bind(release_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.is_some())
    }

    async fn mark_release_scanned(
        &self,
        repo_owner: &str,
        repo_name: &str,
        release_id: u64,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT OR IGNORE INTO github_releases (id, repo_owner, repo_name, scanned_at) VALUES (?, ?, ?, ?)",
        )
        .bind(release_id as i64)
        .bind(repo_owner)
        .bind(repo_name)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

impl crate::domain::prelude::PackageStore for SqliteStorage {
    async fn insert_package(&self, package: &Package) -> anyhow::Result<()> {
        let description_json = serde_json::to_string(&package.metadata.control.description)?;
        let others_json = serde_json::to_string(&package.metadata.control.others)?;

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO deb_assets (
                id, release_id, repo_owner, repo_name, filename, url, size, sha256,
                pkg_name, pkg_version, pkg_section, pkg_priority, pkg_architecture,
                pkg_maintainer, pkg_description, pkg_others, file_size, file_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(package.asset.asset_id as i64)
        .bind(package.asset.release_id as i64)
        .bind(&package.asset.repo_owner)
        .bind(&package.asset.repo_name)
        .bind(&package.asset.filename)
        .bind(&package.asset.url)
        .bind(package.asset.size as i64)
        .bind(&package.asset.sha256)
        .bind(&package.metadata.control.package)
        .bind(&package.metadata.control.version)
        .bind(&package.metadata.control.section)
        .bind(&package.metadata.control.priority)
        .bind(&package.metadata.control.architecture)
        .bind(&package.metadata.control.maintainer)
        .bind(&description_json)
        .bind(&others_json)
        .bind(package.metadata.file.size as i64)
        .bind(&package.metadata.file.sha256)
        .execute(&self.pool)
        .await?;

        self.invalidate_cache().await;
        Ok(())
    }

    async fn find_package_by_asset_id(&self, asset_id: u64) -> Option<Package> {
        let row = sqlx::query(
            r#"
            SELECT id, release_id, repo_owner, repo_name, filename, url, size, sha256,
                   pkg_name, pkg_version, pkg_section, pkg_priority, pkg_architecture,
                   pkg_maintainer, pkg_description, pkg_others, file_size, file_sha256
            FROM deb_assets WHERE id = ?
            "#,
        )
        .bind(asset_id as i64)
        .fetch_optional(&self.pool)
        .await
        .ok()??;

        Some(row_to_package(&row))
    }

    async fn list_all_packages(&self) -> anyhow::Result<Vec<Package>> {
        let rows = sqlx::query(
            r#"
            SELECT id, release_id, repo_owner, repo_name, filename, url, size, sha256,
                   pkg_name, pkg_version, pkg_section, pkg_priority, pkg_architecture,
                   pkg_maintainer, pkg_description, pkg_others, file_size, file_sha256
            FROM deb_assets
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_package).collect())
    }
}

impl crate::domain::prelude::ReleaseStore for SqliteStorage {
    async fn insert_release(&self, entry: ReleaseMetadata) {
        let mut cache = self.release_cache.write().await;
        *cache = Some(entry);
    }

    async fn find_latest_release(&self) -> Option<ReleaseMetadata> {
        self.release_cache.read().await.clone()
    }
}

fn row_to_package(row: &sqlx::sqlite::SqliteRow) -> Package {
    let description: String = row.get("pkg_description");
    let others: String = row.get("pkg_others");
    let section: Option<String> = row.get("pkg_section");
    let sha256: Option<String> = row.get("sha256");

    Package {
        metadata: PackageMetadata {
            control: PackageControl {
                package: row.get("pkg_name"),
                version: row.get("pkg_version"),
                section,
                priority: row.get("pkg_priority"),
                architecture: row.get("pkg_architecture"),
                maintainer: row.get("pkg_maintainer"),
                description: serde_json::from_str(&description).unwrap_or_default(),
                others: serde_json::from_str(&others).unwrap_or_default(),
            },
            file: FileMetadata {
                size: row.get::<i64, _>("file_size") as u64,
                sha256: row.get("file_sha256"),
            },
        },
        asset: DebAsset {
            repo_owner: row.get("repo_owner"),
            repo_name: row.get("repo_name"),
            release_id: row.get::<i64, _>("release_id") as u64,
            asset_id: row.get::<i64, _>("id") as u64,
            filename: row.get("filename"),
            url: row.get("url"),
            size: row.get::<i64, _>("size") as u64,
            sha256,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::domain::prelude::{PackageStore, ReleaseStore, ReleaseTracker};

    async fn create_test_storage() -> SqliteStorage {
        let temp_dir = temp_file::empty();
        let db_path = temp_dir.path().with_extension("db");
        SqliteStorage::new(&db_path).await.unwrap()
    }

    fn create_test_package(asset_id: u64, release_id: u64) -> Package {
        Package {
            metadata: PackageMetadata {
                control: PackageControl {
                    package: "test-package".to_string(),
                    version: "1.0.0".to_string(),
                    section: Some("utils".to_string()),
                    priority: "optional".to_string(),
                    architecture: "amd64".to_string(),
                    maintainer: "Test <test@example.com>".to_string(),
                    description: vec!["A test package".to_string()],
                    others: HashMap::new(),
                },
                file: FileMetadata {
                    size: 1024,
                    sha256: "abc123".to_string(),
                },
            },
            asset: DebAsset {
                repo_owner: "owner".to_string(),
                repo_name: "repo".to_string(),
                release_id,
                asset_id,
                filename: "test-package_1.0.0_amd64.deb".to_string(),
                url: "https://example.com/test.deb".to_string(),
                size: 1024,
                sha256: None,
            },
        }
    }

    #[tokio::test]
    async fn test_release_tracking() {
        let storage = create_test_storage().await;

        // Release should not be scanned initially
        let is_scanned = storage
            .is_release_scanned("owner", "repo", 123)
            .await
            .unwrap();
        assert!(!is_scanned);

        // Mark as scanned
        storage
            .mark_release_scanned("owner", "repo", 123)
            .await
            .unwrap();

        // Should now be scanned
        let is_scanned = storage
            .is_release_scanned("owner", "repo", 123)
            .await
            .unwrap();
        assert!(is_scanned);

        // Different release should not be scanned
        let is_scanned = storage
            .is_release_scanned("owner", "repo", 456)
            .await
            .unwrap();
        assert!(!is_scanned);
    }

    #[tokio::test]
    async fn test_package_storage() {
        let storage = create_test_storage().await;

        // First mark the release as scanned (creates the release record)
        storage
            .mark_release_scanned("owner", "repo", 1)
            .await
            .unwrap();

        let package = create_test_package(100, 1);

        // Insert package
        storage.insert_package(&package).await.unwrap();

        // Find by asset_id
        let found = storage.find_package_by_asset_id(100).await;
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.metadata.control.package, "test-package");
        assert_eq!(found.metadata.control.version, "1.0.0");
        assert_eq!(found.asset.asset_id, 100);

        // Not found for different asset_id
        let not_found = storage.find_package_by_asset_id(999).await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_list_all_packages() {
        let storage = create_test_storage().await;

        // First mark the releases as scanned (creates the release records)
        storage
            .mark_release_scanned("owner", "repo", 1)
            .await
            .unwrap();
        storage
            .mark_release_scanned("owner", "repo", 2)
            .await
            .unwrap();

        // Insert multiple packages
        let package1 = create_test_package(100, 1);
        let package2 = create_test_package(101, 1);
        let package3 = create_test_package(102, 2);

        storage.insert_package(&package1).await.unwrap();
        storage.insert_package(&package2).await.unwrap();
        storage.insert_package(&package3).await.unwrap();

        // List all
        let packages = storage.list_all_packages().await.unwrap();
        assert_eq!(packages.len(), 3);
    }

    #[tokio::test]
    async fn test_release_metadata_cache() {
        let storage = create_test_storage().await;

        // Initially empty
        let release = storage.find_latest_release().await;
        assert!(release.is_none());

        // Insert release metadata
        let metadata = ReleaseMetadata {
            origin: "Test".into(),
            label: "Test".into(),
            suite: "stable".into(),
            version: "1.0".into(),
            codename: "test".into(),
            date: Utc::now(),
            architectures: vec![],
            components: vec!["main".to_string()],
            description: "Test repo".into(),
        };
        storage.insert_release(metadata.clone()).await;

        // Should be cached
        let found = storage.find_latest_release().await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().origin, "Test");
    }
}
