use std::{borrow::Cow, collections::HashMap, fmt::Write};

use md5::Digest;

/// Package
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Package {
    pub metadata: PackageMetadata,
    pub asset: DebAsset,
}

impl Package {
    pub fn serialize(&self) -> SerializedPackageMetadata<'_> {
        SerializedPackageMetadata(self)
    }
}

/// Metadata extracted from a .deb file's control section.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageMetadata {
    pub control: PackageControl,
    pub file: FileMetadata,
}

#[derive(Clone, Copy, Debug)]
pub struct SerializedPackageMetadata<'a>(&'a Package);

impl<'a> std::fmt::Display for SerializedPackageMetadata<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ctrl = &self.0.metadata.control;
        let file = &self.0.metadata.file;
        let asset = &self.0.asset;
        writeln!(f, "Package: {}", ctrl.package)?;
        writeln!(f, "Version: {}", ctrl.version)?;
        if let Some(ref section) = ctrl.section {
            writeln!(f, "Section: {}", section)?;
        }
        writeln!(f, "Priority: {}", ctrl.priority)?;
        writeln!(f, "Architecture: {}", ctrl.architecture)?;
        writeln!(f, "Maintainer: {}", ctrl.maintainer)?;
        write_multiline(f, "Description", &ctrl.description)?;
        for (name, values) in ctrl.others.iter() {
            write_multiline(f, name, values)?;
        }
        if let Some(first) = ctrl.package.chars().next() {
            writeln!(
                f,
                "Filename: pool/main/{first}/{}/{}",
                ctrl.package, asset.filename,
            )?;
        }
        writeln!(f, "Size: {}", file.size)?;
        writeln!(f, "SHA256: {}", file.sha256)?;
        Ok(())
    }
}

fn write_multiline(
    f: &mut std::fmt::Formatter<'_>,
    name: &str,
    values: &[String],
) -> std::fmt::Result {
    write!(f, "{name}:")?;
    if values.is_empty() {
        f.write_char('\n')
    } else {
        for value in values {
            writeln!(f, " {value}")?;
        }
        Ok(())
    }
}

/// Metadata extracted from a .deb file's control section.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageControl {
    /// name of the package
    pub package: String,
    /// version of the package
    pub version: String,
    /// section or category (like utilx, net, libs)
    pub section: Option<String>,
    /// important (like required, standard, optional, etc)
    pub priority: String,
    /// target architecture (amd64, arm64, all, etc)
    pub architecture: String,
    /// name and email of the maintainer
    pub maintainer: String,
    /// brief description of the package
    pub description: Vec<String>,
    pub others: HashMap<String, Vec<String>>,
}

impl PackageControl {
    /// Returns the raw description text as it appears in the Packages file.
    /// This is used to compute the Description-md5 for Translation files.
    pub fn description_text(&self) -> String {
        self.description.join("\n ")
    }

    /// Computes the MD5 hash of the description text.
    /// This is used in Translation files to match descriptions with packages.
    pub fn description_md5(&self) -> String {
        let text = self.description_text();
        // APT computes the MD5 of the description with a trailing newline
        let hash = md5::Md5::digest(format!("{}\n", text).as_bytes());
        hex::encode(hash)
    }
}

/// Metadata extracted from a .deb file's control section.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    pub sha256: String,
}

/// Metadata for the Release file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReleaseMetadata {
    pub origin: Cow<'static, str>,
    pub label: Cow<'static, str>,
    pub suite: Cow<'static, str>,
    pub version: Cow<'static, str>,
    pub codename: Cow<'static, str>,
    pub date: chrono::DateTime<chrono::Utc>,
    pub architectures: Vec<ArchitectureMetadata>,
    pub components: Vec<String>,
    pub description: Cow<'static, str>,
    /// Translation file metadata (i18n/Translation-en)
    #[serde(default)]
    pub translation: TranslationMetadata,
}

impl ReleaseMetadata {
    pub fn serialize(&self) -> SerializedReleaseMetadata<'_> {
        SerializedReleaseMetadata(self)
    }
}

pub struct SerializedReleaseMetadata<'a>(&'a ReleaseMetadata);

impl<'a> std::fmt::Display for SerializedReleaseMetadata<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Origin: {}", self.0.origin)?;
        writeln!(f, "Label: {}", self.0.label)?;
        writeln!(f, "Suite: {}", self.0.suite)?;
        writeln!(f, "Version: {}", self.0.version)?;
        writeln!(f, "Codename: {}", self.0.codename)?;
        writeln!(f, "Components: {}", self.0.components.join(" "))?;
        writeln!(f, "Date: {}", self.0.date.to_rfc2822())?;
        writeln!(f, "Acquire-By-Hash: yes")?;
        writeln!(f, "Description: {}", self.0.description)?;
        if !self.0.architectures.is_empty() {
            let translation = &self.0.translation;
            f.write_str("\n")?;
            writeln!(f, "MD5Sum:")?;
            for arch in self.0.architectures.iter() {
                writeln!(
                    f,
                    " {} {} main/binary-{}/Packages",
                    arch.plain_md5, arch.plain_size, arch.name
                )?;
                writeln!(
                    f,
                    " {} {} main/binary-{}/Packages.gz",
                    arch.compressed_md5, arch.compressed_size, arch.name
                )?;
            }
            // Include Translation-en in the Release file
            writeln!(
                f,
                " {} {} main/i18n/Translation-en",
                translation.plain_md5, translation.plain_size
            )?;
            writeln!(
                f,
                " {} {} main/i18n/Translation-en.gz",
                translation.compressed_md5, translation.compressed_size
            )?;
            f.write_str("\n")?;
            writeln!(f, "SHA256:")?;
            for arch in self.0.architectures.iter() {
                writeln!(
                    f,
                    " {} {} main/binary-{}/Packages",
                    arch.plain_sha256, arch.plain_size, arch.name
                )?;
                writeln!(
                    f,
                    " {} {} main/binary-{}/Packages.gz",
                    arch.compressed_sha256, arch.compressed_size, arch.name
                )?;
            }
            // Include Translation-en in the Release file
            writeln!(
                f,
                " {} {} main/i18n/Translation-en",
                translation.plain_sha256, translation.plain_size
            )?;
            writeln!(
                f,
                " {} {} main/i18n/Translation-en.gz",
                translation.compressed_sha256, translation.compressed_size
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArchitectureMetadata {
    pub name: String,
    pub plain_md5: String,
    pub plain_sha256: String,
    pub plain_size: u64,
    pub compressed_md5: String,
    pub compressed_sha256: String,
    pub compressed_size: u64,
    pub packages: Vec<Package>,
}

/// Represents a .deb asset (source, filename, URL, etc.).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Metadata for Translation files (i18n).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TranslationMetadata {
    pub plain_md5: String,
    pub plain_sha256: String,
    pub plain_size: u64,
    pub compressed_md5: String,
    pub compressed_sha256: String,
    pub compressed_size: u64,
}

/// Entry for a single package in a Translation file.
#[derive(Debug, Clone)]
pub struct TranslationEntry {
    pub package: String,
    pub description_md5: String,
    pub description: Vec<String>,
}

impl std::fmt::Display for TranslationEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Package: {}", self.package)?;
        writeln!(f, "Description-md5: {}", self.description_md5)?;
        write_multiline(f, "Description-en", &self.description)
    }
}

/// A GitHub release with its .deb assets for incremental processing.
#[derive(Debug, Clone)]
pub struct ReleaseWithAssets {
    pub release_id: u64,
    pub repo_owner: String,
    pub repo_name: String,
    pub assets: Vec<DebAsset>,
}

/// A GitHub release with its .apk assets for incremental processing.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "APK support entity (#63), consumed in #65")
)]
#[derive(Debug, Clone)]
pub struct ApkReleaseWithAssets {
    pub release_id: u64,
    pub repo_owner: String,
    pub repo_name: String,
    pub assets: Vec<ApkAsset>,
}

/// An Alpine package with its metadata and source asset.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApkPackage {
    pub metadata: ApkMetadata,
    pub asset: ApkAsset,
}

#[expect(
    dead_code,
    reason = "foundational type for APK support (#60), consumers in #61-#68"
)]
impl ApkPackage {
    pub fn serialize(&self) -> SerializedApkIndexEntry<'_> {
        SerializedApkIndexEntry(self)
    }
}

/// Metadata extracted from an `.apk` file's `.PKGINFO`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApkMetadata {
    /// Package name (`pkgname`).
    pub name: String,
    /// Package version (`pkgver`).
    pub version: String,
    /// Target architecture (`arch`), e.g. `x86_64`, `aarch64`.
    pub architecture: String,
    /// Installed size in bytes (`.PKGINFO` `size` field).
    /// Note: in APKINDEX this maps to `I:`, not `S:`.
    /// `S:` (package file size) comes from `ApkAsset::size`.
    pub installed_size: u64,
    /// Short description (`pkgdesc`).
    pub description: String,
    /// Project URL (`url`).
    pub url: String,
    /// License identifier (`license`).
    pub license: String,
    /// Origin package name (`origin`).
    pub origin: Option<String>,
    /// Maintainer name and email (`maintainer`).
    pub maintainer: Option<String>,
    /// Build timestamp as Unix epoch (`builddate`).
    pub build_date: Option<u64>,
    /// Runtime dependencies (`depend`), one per entry.
    pub dependencies: Vec<String>,
    /// Capabilities this package provides (`provides`), one per entry.
    pub provides: Vec<String>,
    /// SHA256 checksum of the package data (`datahash`).
    pub datahash: Option<String>,
}

/// Represents an `.apk` asset from a GitHub release.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApkAsset {
    pub repo_owner: String,
    pub repo_name: String,
    pub release_id: u64,
    pub asset_id: u64,
    pub filename: String,
    pub url: String,
    pub size: u64,
    pub sha256: Option<String>,
}

/// Serialized APKINDEX entry for a single package.
#[derive(Clone, Copy, Debug)]
pub struct SerializedApkIndexEntry<'a>(&'a ApkPackage);

impl<'a> std::fmt::Display for SerializedApkIndexEntry<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let meta = &self.0.metadata;
        let asset = &self.0.asset;
        if let Some(ref datahash) = meta.datahash {
            writeln!(f, "C:{datahash}")?;
        }
        writeln!(f, "P:{}", meta.name)?;
        writeln!(f, "V:{}", meta.version)?;
        writeln!(f, "A:{}", meta.architecture)?;
        writeln!(f, "S:{}", asset.size)?;
        writeln!(f, "I:{}", meta.installed_size)?;
        writeln!(f, "T:{}", meta.description)?;
        writeln!(f, "U:{}", meta.url)?;
        writeln!(f, "L:{}", meta.license)?;
        if let Some(ref origin) = meta.origin {
            writeln!(f, "o:{origin}")?;
        }
        if let Some(ref maintainer) = meta.maintainer {
            writeln!(f, "m:{maintainer}")?;
        }
        if let Some(build_date) = meta.build_date {
            writeln!(f, "t:{build_date}")?;
        }
        if !meta.dependencies.is_empty() {
            writeln!(f, "D:{}", meta.dependencies.join(" "))?;
        }
        if !meta.provides.is_empty() {
            writeln!(f, "p:{}", meta.provides.join(" "))?;
        }
        Ok(())
    }
}
