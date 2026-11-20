use anyhow::Context;

use crate::domain::entity::ApkMetadata;

/// Extract `.PKGINFO` from an `.apk` file and parse it into [`ApkMetadata`].
pub fn from_path(path: &std::path::Path) -> anyhow::Result<ApkMetadata> {
    let bytes = std::fs::read(path).context("unable to read file")?;
    let (raw, checksum) = read_control(&bytes)?;
    parse_pkginfo(&raw, checksum)
}

/// Find the control segment of an `.apk` and return its `.PKGINFO` with the
/// APKINDEX `C:` checksum.
///
/// An `.apk` is concatenated gzip streams (optional signature, control, data).
/// The control stream is the one holding `.PKGINFO`; apk identifies a package
/// by `Q1` + base64(SHA-1 of that stream's compressed bytes).
fn read_control(bytes: &[u8]) -> anyhow::Result<(String, String)> {
    use base64::Engine;
    use sha1::Digest;
    use std::io::Read;

    let mut rest = bytes;
    while !rest.is_empty() {
        let before = rest.len();
        let mut tar_bytes = Vec::new();
        flate2::bufread::GzDecoder::new(&mut rest)
            .read_to_end(&mut tar_bytes)
            .context("invalid gzip stream in apk archive")?;
        let stream = &bytes[bytes.len() - before..bytes.len() - rest.len()];

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path()?.as_os_str() == ".PKGINFO" {
                let mut value = String::new();
                entry.read_to_string(&mut value)?;
                let digest = sha1::Sha1::digest(stream);
                let checksum = format!(
                    "Q1{}",
                    base64::engine::general_purpose::STANDARD.encode(digest)
                );
                return Ok((value, checksum));
            }
        }
    }

    anyhow::bail!(".PKGINFO not found in apk archive")
}

/// Parse `.PKGINFO` key-value content into [`ApkMetadata`].
fn parse_pkginfo(input: &str, checksum: String) -> anyhow::Result<ApkMetadata> {
    let mut builder = PkgInfoBuilder::default();

    for line in input.lines() {
        let line = line.trim();
        // skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(" = ") {
            builder.set(key.trim(), value.trim());
        }
    }

    builder.build(checksum)
}

#[derive(Debug, Default)]
struct PkgInfoBuilder {
    name: Option<String>,
    version: Option<String>,
    architecture: Option<String>,
    installed_size: Option<u64>,
    description: Option<String>,
    url: Option<String>,
    license: Option<String>,
    origin: Option<String>,
    maintainer: Option<String>,
    build_date: Option<u64>,
    dependencies: Vec<String>,
    provides: Vec<String>,
    datahash: Option<String>,
}

impl PkgInfoBuilder {
    fn set(&mut self, key: &str, value: &str) {
        match key {
            "pkgname" => self.name = Some(value.to_string()),
            "pkgver" => self.version = Some(value.to_string()),
            "arch" => self.architecture = Some(value.to_string()),
            "size" => self.installed_size = value.parse().ok(),
            "pkgdesc" => self.description = Some(value.to_string()),
            "url" => self.url = Some(value.to_string()),
            "license" => self.license = Some(value.to_string()),
            "origin" => self.origin = Some(value.to_string()),
            "maintainer" => self.maintainer = Some(value.to_string()),
            "builddate" => self.build_date = value.parse().ok(),
            "depend" => self.dependencies.push(value.to_string()),
            "provides" => self.provides.push(value.to_string()),
            "datahash" => self.datahash = Some(value.to_string()),
            // ignore unknown fields (commit, packager, replaces, triggers, etc.)
            _ => {}
        }
    }

    fn build(self, checksum: String) -> anyhow::Result<ApkMetadata> {
        Ok(ApkMetadata {
            name: self
                .name
                .ok_or_else(|| anyhow::anyhow!("missing pkgname in .PKGINFO"))?,
            version: self
                .version
                .ok_or_else(|| anyhow::anyhow!("missing pkgver in .PKGINFO"))?,
            architecture: self
                .architecture
                .ok_or_else(|| anyhow::anyhow!("missing arch in .PKGINFO"))?,
            installed_size: self
                .installed_size
                .ok_or_else(|| anyhow::anyhow!("missing size in .PKGINFO"))?,
            description: self
                .description
                .ok_or_else(|| anyhow::anyhow!("missing pkgdesc in .PKGINFO"))?,
            url: self
                .url
                .ok_or_else(|| anyhow::anyhow!("missing url in .PKGINFO"))?,
            license: self
                .license
                .ok_or_else(|| anyhow::anyhow!("missing license in .PKGINFO"))?,
            origin: self.origin,
            maintainer: self.maintainer,
            build_date: self.build_date,
            dependencies: self.dependencies,
            provides: self.provides,
            datahash: self.datahash,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_pkginfo_with_all_fields() {
        let input = r#"# Generated by abuild 3.14.1-r4
# using fakeroot version 1.37.1.1
pkgname = busybox
pkgver = 1.37.0-r14
pkgdesc = Size optimized toolbox of many common UNIX utilities
url = https://busybox.net/
builddate = 1763903404
packager = Buildozer <alpine-devel@lists.alpinelinux.org>
size = 817257
arch = x86_64
origin = busybox
commit = 284d827a2793963e6dcf88324bd1eb81adff579c
maintainer = Sören Tempel <soeren+alpine@soeren-tempel.net>
license = GPL-2.0-only
replaces = busybox-initscripts
triggers = /bin /usr/bin /sbin /usr/sbin /lib/modules/* /usr/lib/modules/*
# automatically detected:
provides = cmd:busybox=1.37.0-r14
depend = so:libc.musl-x86_64.so.1
datahash = dba362efdaf5615e7193972f24e56c73ac395830a1756afe35246f42e8f1de56
"#;
        let meta = parse_pkginfo(input, "Q1test".to_string()).unwrap();
        assert_eq!(meta.name, "busybox");
        assert_eq!(meta.version, "1.37.0-r14");
        assert_eq!(meta.architecture, "x86_64");
        assert_eq!(meta.installed_size, 817257);
        assert_eq!(
            meta.description,
            "Size optimized toolbox of many common UNIX utilities"
        );
        assert_eq!(meta.url, "https://busybox.net/");
        assert_eq!(meta.license, "GPL-2.0-only");
        assert_eq!(meta.origin.as_deref(), Some("busybox"));
        assert_eq!(
            meta.maintainer.as_deref(),
            Some("Sören Tempel <soeren+alpine@soeren-tempel.net>")
        );
        assert_eq!(meta.build_date, Some(1763903404));
        assert_eq!(meta.dependencies, vec!["so:libc.musl-x86_64.so.1"]);
        assert_eq!(meta.provides, vec!["cmd:busybox=1.37.0-r14"]);
        assert_eq!(
            meta.datahash.as_deref(),
            Some("dba362efdaf5615e7193972f24e56c73ac395830a1756afe35246f42e8f1de56")
        );
    }

    #[test]
    fn should_parse_pkginfo_with_minimal_fields() {
        let input = r#"# Generated by abuild 3.14.0-r0
pkgname = alpine-keys
pkgver = 2.5-r0
pkgdesc = Public keys for Alpine Linux packages
url = https://alpinelinux.org
builddate = 1723638620
size = 14212
arch = x86_64
origin = alpine-keys
maintainer = Natanael Copa <ncopa@alpinelinux.org>
license = MIT
datahash = c72f1654a3503e252d02681b55c7074c6620310333523d8830ec3edb199e5327
"#;
        let meta = parse_pkginfo(input, "Q1test".to_string()).unwrap();
        assert_eq!(meta.name, "alpine-keys");
        assert_eq!(meta.version, "2.5-r0");
        assert!(meta.dependencies.is_empty());
        assert!(meta.provides.is_empty());
    }

    #[test]
    fn should_fail_when_pkgname_missing() {
        let input = "pkgver = 1.0\narch = x86_64\nsize = 100\npkgdesc = test\nurl = http://test\nlicense = MIT\n";
        let err = parse_pkginfo(input, "Q1test".to_string()).unwrap_err();
        assert!(err.to_string().contains("pkgname"));
    }

    #[test]
    fn should_extract_pkginfo_from_busybox_apk_file() {
        let local = std::env::current_dir().unwrap();
        let path = local.join("resources").join("busybox-1.37.0-r14.apk");
        let meta = from_path(&path).unwrap();
        assert_eq!(meta.name, "busybox");
        assert_eq!(meta.version, "1.37.0-r14");
        assert_eq!(meta.architecture, "x86_64");
        assert_eq!(meta.installed_size, 817257);
        assert_eq!(meta.license, "GPL-2.0-only");
        assert!(!meta.dependencies.is_empty());
        assert!(!meta.provides.is_empty());
        assert!(meta.datahash.is_some());
        // Value produced by `apk index` (apk-tools 2.14.13) for this file.
        assert_eq!(meta.checksum, "Q1p/ydDCbqw8aB8uA/M5rzEgEeRD4=");
    }

    #[test]
    fn should_extract_pkginfo_from_alpine_keys_apk_file() {
        let local = std::env::current_dir().unwrap();
        let path = local.join("resources").join("alpine-keys-2.5-r0.apk");
        let meta = from_path(&path).unwrap();
        assert_eq!(meta.name, "alpine-keys");
        assert_eq!(meta.version, "2.5-r0");
        assert_eq!(meta.architecture, "x86_64");
        assert_eq!(meta.installed_size, 14212);
        assert_eq!(meta.license, "MIT");
        assert!(meta.dependencies.is_empty());
        assert!(meta.provides.is_empty());
        // Value produced by `apk index` (apk-tools 2.14.13) for this file.
        assert_eq!(meta.checksum, "Q1kQFL/boOf3tFBRWUZunxmHFgalk=");
    }
}
