use std::{borrow::Cow, collections::HashMap, fmt::Write};

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
        writeln!(f, "Description: {}", self.0.description)?;
        if !self.0.architectures.is_empty() {
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
