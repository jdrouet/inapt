use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{FromRow, Row, SqlitePool};
use tokio::sync::RwLock;

use crate::domain::entity::{
    ArchitectureMetadata, DebAsset, FileMetadata, Package, PackageControl, PackageMetadata,
    ReleaseMetadata, TranslationEntry, TranslationMetadata,
};

// SQL query constants
const SQL_SELECT_LATEST_RELEASE_METADATA: &str = r#"
    SELECT id, origin, label, suite, version, codename, date, components, description
    FROM release_metadata
    ORDER BY created_at DESC
    LIMIT 1
"#;

const SQL_SELECT_ARCHITECTURE_METADATA: &str = r#"
    SELECT name, plain_md5, plain_sha256, plain_size,
           compressed_md5, compressed_sha256, compressed_size
    FROM architecture_metadata
    WHERE release_metadata_id = ?
"#;

const SQL_SELECT_PACKAGES_BY_ARCHITECTURES: &str = r#"
    SELECT id, release_id, repo_owner, repo_name, filename, url, size, sha256,
           pkg_name, pkg_version, pkg_section, pkg_priority, pkg_architecture,
           pkg_maintainer, pkg_description, pkg_others, file_size, file_sha256
    FROM deb_assets
    WHERE pkg_architecture IN (
"#;

const SQL_INSERT_RELEASE_METADATA: &str = r#"
    INSERT INTO release_metadata (origin, label, suite, version, codename, date, components, description, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"#;

const SQL_INSERT_ARCHITECTURE_METADATA: &str = "INSERT INTO architecture_metadata (release_metadata_id, name, plain_md5, plain_sha256, plain_size, compressed_md5, compressed_sha256, compressed_size) ";

const SQL_SELECT_GITHUB_RELEASE: &str =
    "SELECT id FROM github_releases WHERE repo_owner = ? AND repo_name = ? AND id = ?";

const SQL_INSERT_GITHUB_RELEASE: &str = "INSERT OR IGNORE INTO github_releases (id, repo_owner, repo_name, scanned_at) VALUES (?, ?, ?, ?)";

const SQL_INSERT_DEB_ASSET: &str = r#"
    INSERT OR REPLACE INTO deb_assets (
        id, release_id, repo_owner, repo_name, filename, url, size, sha256,
        pkg_name, pkg_version, pkg_section, pkg_priority, pkg_architecture,
        pkg_maintainer, pkg_description, pkg_others, file_size, file_sha256
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"#;

const SQL_SELECT_DEB_ASSET_BY_ID: &str = r#"
    SELECT id, release_id, repo_owner, repo_name, filename, url, size, sha256,
           pkg_name, pkg_version, pkg_section, pkg_priority, pkg_architecture,
           pkg_maintainer, pkg_description, pkg_others, file_size, file_sha256
    FROM deb_assets WHERE id = ?
"#;

const SQL_SELECT_ALL_DEB_ASSETS: &str = r#"
    SELECT id, release_id, repo_owner, repo_name, filename, url, size, sha256,
           pkg_name, pkg_version, pkg_section, pkg_priority, pkg_architecture,
           pkg_maintainer, pkg_description, pkg_others, file_size, file_sha256
    FROM deb_assets
"#;

// Wrapper type for implementing FromRow on external types
struct SqliteWrapper<T>(T);

impl<T> SqliteWrapper<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// Row data for release_metadata table
struct ReleaseMetadataRow {
    id: i64,
    origin: String,
    label: String,
    suite: String,
    version: String,
    codename: String,
    date: String,
    components: String,
    description: String,
}

impl<'r> FromRow<'r, SqliteRow> for SqliteWrapper<ReleaseMetadataRow> {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(SqliteWrapper(ReleaseMetadataRow {
            id: row.try_get("id")?,
            origin: row.try_get("origin")?,
            label: row.try_get("label")?,
            suite: row.try_get("suite")?,
            version: row.try_get("version")?,
            codename: row.try_get("codename")?,
            date: row.try_get("date")?,
            components: row.try_get("components")?,
            description: row.try_get("description")?,
        }))
    }
}

/// Row data for architecture_metadata table (without packages)
struct ArchitectureMetadataRow {
    name: String,
    plain_md5: String,
    plain_sha256: String,
    plain_size: i64,
    compressed_md5: String,
    compressed_sha256: String,
    compressed_size: i64,
}

impl<'r> FromRow<'r, SqliteRow> for SqliteWrapper<ArchitectureMetadataRow> {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(SqliteWrapper(ArchitectureMetadataRow {
            name: row.try_get("name")?,
            plain_md5: row.try_get("plain_md5")?,
            plain_sha256: row.try_get("plain_sha256")?,
            plain_size: row.try_get("plain_size")?,
            compressed_md5: row.try_get("compressed_md5")?,
            compressed_sha256: row.try_get("compressed_sha256")?,
            compressed_size: row.try_get("compressed_size")?,
        }))
    }
}

impl ArchitectureMetadataRow {
    fn into_metadata(self, packages: Vec<Package>) -> ArchitectureMetadata {
        ArchitectureMetadata {
            name: self.name,
            plain_md5: self.plain_md5,
            plain_sha256: self.plain_sha256,
            plain_size: self.plain_size as u64,
            compressed_md5: self.compressed_md5,
            compressed_sha256: self.compressed_sha256,
            compressed_size: self.compressed_size as u64,
            packages,
        }
    }
}

impl<'r> FromRow<'r, SqliteRow> for SqliteWrapper<Package> {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let description: String = row.try_get("pkg_description")?;
        let others: String = row.try_get("pkg_others")?;

        Ok(SqliteWrapper(Package {
            metadata: PackageMetadata {
                control: PackageControl {
                    package: row.try_get("pkg_name")?,
                    version: row.try_get("pkg_version")?,
                    section: row.try_get("pkg_section")?,
                    priority: row.try_get("pkg_priority")?,
                    architecture: row.try_get("pkg_architecture")?,
                    maintainer: row.try_get("pkg_maintainer")?,
                    description: serde_json::from_str(&description).unwrap_or_default(),
                    others: serde_json::from_str(&others).unwrap_or_default(),
                },
                file: FileMetadata {
                    size: row.try_get::<i64, _>("file_size")? as u64,
                    sha256: row.try_get("file_sha256")?,
                },
            },
            asset: DebAsset {
                repo_owner: row.try_get("repo_owner")?,
                repo_name: row.try_get("repo_name")?,
                release_id: row.try_get::<i64, _>("release_id")? as u64,
                asset_id: row.try_get::<i64, _>("id")? as u64,
                filename: row.try_get("filename")?,
                url: row.try_get("url")?,
                size: row.try_get::<i64, _>("size")? as u64,
                sha256: row.try_get("sha256")?,
            },
        }))
    }
}

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

        // Load cached release metadata from database
        let cached_release = Self::load_latest_release_from_db(&pool).await?;

        Ok(Self {
            pool,
            release_cache: Arc::new(RwLock::new(cached_release)),
        })
    }

    /// Invalidate the release cache when packages change
    async fn invalidate_cache(&self) {
        let mut cache = self.release_cache.write().await;
        *cache = None;
    }

    /// Fetch the latest release metadata row from the database
    #[tracing::instrument(
        skip(pool),
        fields(
            db.system = "sqlite",
            db.statement = SQL_SELECT_LATEST_RELEASE_METADATA,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn fetch_latest_release_metadata_row(
        pool: &SqlitePool,
    ) -> anyhow::Result<Option<ReleaseMetadataRow>> {
        let result = sqlx::query_as::<_, SqliteWrapper<ReleaseMetadataRow>>(
            SQL_SELECT_LATEST_RELEASE_METADATA,
        )
        .fetch_optional(pool)
        .await?;

        Ok(result.map(|w| w.into_inner()))
    }

    /// Fetch architecture metadata rows for a given release
    #[tracing::instrument(
        skip(pool),
        fields(
            db.system = "sqlite",
            db.statement = SQL_SELECT_ARCHITECTURE_METADATA,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn fetch_architecture_metadata_rows(
        pool: &SqlitePool,
        release_metadata_id: i64,
    ) -> anyhow::Result<Vec<ArchitectureMetadataRow>> {
        let rows: Vec<SqliteWrapper<ArchitectureMetadataRow>> =
            sqlx::query_as(SQL_SELECT_ARCHITECTURE_METADATA)
                .bind(release_metadata_id)
                .fetch_all(pool)
                .await?;

        Ok(rows.into_iter().map(|w| w.into_inner()).collect())
    }

    /// Fetch packages for the given architectures
    #[tracing::instrument(
        skip(pool, arch_names),
        fields(
            db.system = "sqlite",
            db.statement = SQL_SELECT_PACKAGES_BY_ARCHITECTURES,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn fetch_packages_by_architectures(
        pool: &SqlitePool,
        arch_names: &[&str],
    ) -> anyhow::Result<HashMap<String, Vec<Package>>> {
        if arch_names.is_empty() {
            return Ok(HashMap::new());
        }

        let mut query_builder = sqlx::QueryBuilder::new(SQL_SELECT_PACKAGES_BY_ARCHITECTURES);

        let mut separated = query_builder.separated(", ");
        for name in arch_names {
            separated.push_bind(*name);
        }
        separated.push_unseparated(")");

        let all_packages: Vec<SqliteWrapper<Package>> =
            query_builder.build_query_as().fetch_all(pool).await?;

        let mut map: HashMap<String, Vec<Package>> = HashMap::new();
        for pkg in all_packages {
            let pkg = pkg.into_inner();
            map.entry(pkg.metadata.control.architecture.clone())
                .or_default()
                .push(pkg);
        }
        Ok(map)
    }

    /// Load the latest release metadata from the database
    async fn load_latest_release_from_db(
        pool: &SqlitePool,
    ) -> anyhow::Result<Option<ReleaseMetadata>> {
        // Get the latest release_metadata row
        let Some(release_row) = Self::fetch_latest_release_metadata_row(pool).await? else {
            return Ok(None);
        };

        // Get architecture metadata for this release
        let arch_rows = Self::fetch_architecture_metadata_rows(pool, release_row.id).await?;

        // Load all packages for all architectures in a single query
        let arch_names: Vec<&str> = arch_rows.iter().map(|r| r.name.as_str()).collect();
        let packages_by_arch = Self::fetch_packages_by_architectures(pool, &arch_names).await?;

        // Build architectures with their packages
        let architectures: Vec<ArchitectureMetadata> = arch_rows
            .into_iter()
            .map(|row| {
                let packages = packages_by_arch.get(&row.name).cloned().unwrap_or_default();
                row.into_metadata(packages)
            })
            .collect();

        let date = chrono::DateTime::parse_from_rfc3339(&release_row.date)
            .map_err(|e| anyhow::anyhow!("invalid date format in database: {e}"))?
            .with_timezone(&Utc);

        // Compute translation metadata from architectures
        let translation = Self::compute_translation_metadata(&architectures);

        Ok(Some(ReleaseMetadata {
            origin: Cow::Owned(release_row.origin),
            label: Cow::Owned(release_row.label),
            suite: Cow::Owned(release_row.suite),
            version: Cow::Owned(release_row.version),
            codename: Cow::Owned(release_row.codename),
            date,
            architectures,
            components: serde_json::from_str(&release_row.components)?,
            description: Cow::Owned(release_row.description),
            translation,
        }))
    }

    /// Insert release metadata row into the database
    #[tracing::instrument(
        skip(pool, entry, now),
        fields(
            db.system = "sqlite",
            db.statement = SQL_INSERT_RELEASE_METADATA,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn insert_release_metadata_row(
        pool: &SqlitePool,
        entry: &ReleaseMetadata,
        now: &str,
    ) -> anyhow::Result<i64> {
        let components_json = serde_json::to_string(&entry.components)?;

        let result = sqlx::query(SQL_INSERT_RELEASE_METADATA)
            .bind(entry.origin.as_ref())
            .bind(entry.label.as_ref())
            .bind(entry.suite.as_ref())
            .bind(entry.version.as_ref())
            .bind(entry.codename.as_ref())
            .bind(entry.date.to_rfc3339())
            .bind(&components_json)
            .bind(entry.description.as_ref())
            .bind(now)
            .execute(pool)
            .await?;

        Ok(result.last_insert_rowid())
    }

    /// Insert architecture metadata rows into the database
    #[tracing::instrument(
        skip(pool, architectures),
        fields(
            db.system = "sqlite",
            db.statement = SQL_INSERT_ARCHITECTURE_METADATA,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn insert_architecture_metadata_rows(
        pool: &SqlitePool,
        release_metadata_id: i64,
        architectures: &[ArchitectureMetadata],
    ) -> anyhow::Result<()> {
        if architectures.is_empty() {
            return Ok(());
        }

        let mut query_builder = sqlx::QueryBuilder::new(SQL_INSERT_ARCHITECTURE_METADATA);

        query_builder.push_values(architectures, |mut b, arch| {
            b.push_bind(release_metadata_id)
                .push_bind(&arch.name)
                .push_bind(&arch.plain_md5)
                .push_bind(&arch.plain_sha256)
                .push_bind(arch.plain_size as i64)
                .push_bind(&arch.compressed_md5)
                .push_bind(&arch.compressed_sha256)
                .push_bind(arch.compressed_size as i64);
        });

        query_builder.build().execute(pool).await?;

        Ok(())
    }

    /// Save release metadata to the database
    async fn save_release_to_db(&self, entry: &ReleaseMetadata) -> anyhow::Result<i64> {
        let now = Utc::now().to_rfc3339();

        // Insert release_metadata
        let release_id = Self::insert_release_metadata_row(&self.pool, entry, &now).await?;

        // Batch insert architecture_metadata
        Self::insert_architecture_metadata_rows(&self.pool, release_id, &entry.architectures)
            .await?;

        Ok(release_id)
    }

    /// Compute translation metadata from architectures.
    fn compute_translation_metadata(architectures: &[ArchitectureMetadata]) -> TranslationMetadata {
        use flate2::write::GzEncoder;
        use md5::Digest;
        use std::collections::HashSet;
        use std::io::Write;

        // Collect unique packages by name (deduplicate across architectures)
        let mut seen_packages: HashSet<String> = HashSet::new();
        let mut entries = Vec::new();

        for arch in architectures {
            for package in &arch.packages {
                let pkg_name = &package.metadata.control.package;
                if seen_packages.insert(pkg_name.clone()) {
                    entries.push(TranslationEntry {
                        package: pkg_name.clone(),
                        description_md5: package.metadata.control.description_md5(),
                        description: package.metadata.control.description.clone(),
                    });
                }
            }
        }

        // Sort entries by package name for consistent output
        entries.sort_by(|a, b| a.package.cmp(&b.package));

        // Build the translation file content
        let content = entries
            .into_iter()
            .map(|entry| entry.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        // Compute hashes
        let plain_md5 = hex::encode(md5::Md5::digest(content.as_bytes()));
        let plain_sha256 = hex::encode(sha2::Sha256::digest(content.as_bytes()));
        let plain_size = content.len() as u64;

        // Compress and compute compressed hashes
        let mut gz_encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        let _ = gz_encoder.write_all(content.as_bytes());
        let compressed = gz_encoder.finish().unwrap_or_default();

        let compressed_md5 = hex::encode(md5::Md5::digest(&compressed));
        let compressed_sha256 = hex::encode(sha2::Sha256::digest(&compressed));
        let compressed_size = compressed.len() as u64;

        TranslationMetadata {
            plain_md5,
            plain_sha256,
            plain_size,
            compressed_md5,
            compressed_sha256,
            compressed_size,
        }
    }
}

impl crate::domain::prelude::ReleaseTracker for SqliteStorage {
    #[tracing::instrument(
        skip(self),
        fields(
            db.system = "sqlite",
            db.statement = SQL_SELECT_GITHUB_RELEASE,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn is_release_scanned(
        &self,
        repo_owner: &str,
        repo_name: &str,
        release_id: u64,
    ) -> anyhow::Result<bool> {
        let result: Option<(i64,)> = sqlx::query_as(SQL_SELECT_GITHUB_RELEASE)
            .bind(repo_owner)
            .bind(repo_name)
            .bind(release_id as i64)
            .fetch_optional(&self.pool)
            .await?;

        Ok(result.is_some())
    }

    #[tracing::instrument(
        skip(self),
        fields(
            db.system = "sqlite",
            db.statement = SQL_INSERT_GITHUB_RELEASE,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn mark_release_scanned(
        &self,
        repo_owner: &str,
        repo_name: &str,
        release_id: u64,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();

        sqlx::query(SQL_INSERT_GITHUB_RELEASE)
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
    #[tracing::instrument(
        skip(self, package),
        fields(
            db.system = "sqlite",
            db.statement = SQL_INSERT_DEB_ASSET,
            span.type = "sql",
            otel.kind = "client",
            asset_id = package.asset.asset_id
        )
    )]
    async fn insert_package(&self, package: &Package) -> anyhow::Result<()> {
        let description_json = serde_json::to_string(&package.metadata.control.description)?;
        let others_json = serde_json::to_string(&package.metadata.control.others)?;

        sqlx::query(SQL_INSERT_DEB_ASSET)
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

    #[tracing::instrument(
        skip(self),
        fields(
            db.system = "sqlite",
            db.statement = SQL_SELECT_DEB_ASSET_BY_ID,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn find_package_by_asset_id(&self, asset_id: u64) -> Option<Package> {
        match sqlx::query_as::<_, SqliteWrapper<Package>>(SQL_SELECT_DEB_ASSET_BY_ID)
            .bind(asset_id as i64)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(wrapper)) => Some(wrapper.into_inner()),
            Ok(None) => None,
            Err(err) => {
                tracing::error!(error = ?err, asset_id, "failed to find package by asset_id");
                None
            }
        }
    }

    #[tracing::instrument(
        skip(self),
        fields(
            db.system = "sqlite",
            db.statement = SQL_SELECT_ALL_DEB_ASSETS,
            span.type = "sql",
            otel.kind = "client"
        )
    )]
    async fn list_all_packages(&self) -> anyhow::Result<Vec<Package>> {
        let rows: Vec<SqliteWrapper<Package>> = sqlx::query_as(SQL_SELECT_ALL_DEB_ASSETS)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(|w| w.into_inner()).collect())
    }
}

impl crate::domain::prelude::ReleaseStore for SqliteStorage {
    async fn insert_release(&self, entry: ReleaseMetadata) {
        // Save to database
        if let Err(err) = self.save_release_to_db(&entry).await {
            tracing::error!(error = ?err, "failed to save release metadata to database");
        }

        // Update cache
        let mut cache = self.release_cache.write().await;
        *cache = Some(entry);
    }

    async fn find_latest_release(&self) -> Option<ReleaseMetadata> {
        self.release_cache.read().await.clone()
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
    async fn test_release_metadata_persistence() {
        let temp_dir = temp_file::empty();
        let db_path = temp_dir.path().with_extension("db");

        // Create storage and insert release metadata
        {
            let storage = SqliteStorage::new(&db_path).await.unwrap();

            // Initially empty
            let release = storage.find_latest_release().await;
            assert!(release.is_none());

            // Insert release metadata with architectures
            let metadata = ReleaseMetadata {
                origin: "Test".into(),
                label: "TestLabel".into(),
                suite: "stable".into(),
                version: "1.0".into(),
                codename: "test".into(),
                date: chrono::DateTime::parse_from_rfc3339("2025-01-21T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                architectures: vec![ArchitectureMetadata {
                    name: "amd64".to_string(),
                    plain_md5: "abc123".to_string(),
                    plain_sha256: "def456".to_string(),
                    plain_size: 1000,
                    compressed_md5: "ghi789".to_string(),
                    compressed_sha256: "jkl012".to_string(),
                    compressed_size: 500,
                    packages: vec![],
                }],
                components: vec!["main".to_string()],
                description: "Test repo".into(),
                translation: Default::default(),
            };
            storage.insert_release(metadata).await;

            // Should be cached
            let found = storage.find_latest_release().await;
            assert!(found.is_some());
            assert_eq!(found.as_ref().unwrap().origin, "Test");
        }

        // Create new storage instance from same database - should load from DB
        {
            let storage = SqliteStorage::new(&db_path).await.unwrap();

            // Should have loaded from database
            let found = storage.find_latest_release().await;
            assert!(found.is_some());
            let found = found.unwrap();
            assert_eq!(found.origin, "Test");
            assert_eq!(found.label, "TestLabel");
            assert_eq!(found.suite, "stable");
            assert_eq!(found.version, "1.0");
            assert_eq!(found.codename, "test");
            assert_eq!(found.components, vec!["main".to_string()]);
            assert_eq!(found.description, "Test repo");

            // Check architecture metadata was persisted
            assert_eq!(found.architectures.len(), 1);
            let arch = &found.architectures[0];
            assert_eq!(arch.name, "amd64");
            assert_eq!(arch.plain_md5, "abc123");
            assert_eq!(arch.plain_sha256, "def456");
            assert_eq!(arch.plain_size, 1000);
            assert_eq!(arch.compressed_md5, "ghi789");
            assert_eq!(arch.compressed_sha256, "jkl012");
            assert_eq!(arch.compressed_size, 500);
        }
    }

    #[tokio::test]
    async fn test_release_metadata_history() {
        let storage = create_test_storage().await;

        // Insert first release
        let metadata1 = ReleaseMetadata {
            origin: "First".into(),
            label: "First".into(),
            suite: "stable".into(),
            version: "1.0".into(),
            codename: "first".into(),
            date: Utc::now(),
            architectures: vec![],
            components: vec!["main".to_string()],
            description: "First release".into(),
            translation: Default::default(),
        };
        storage.insert_release(metadata1).await;

        // Insert second release
        let metadata2 = ReleaseMetadata {
            origin: "Second".into(),
            label: "Second".into(),
            suite: "stable".into(),
            version: "2.0".into(),
            codename: "second".into(),
            date: Utc::now(),
            architectures: vec![],
            components: vec!["main".to_string()],
            description: "Second release".into(),
            translation: Default::default(),
        };
        storage.insert_release(metadata2).await;

        // find_latest_release should return the most recent one
        let found = storage.find_latest_release().await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().origin, "Second");
    }
}
