mod pkginfo;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "APK adapter (#61), wired in #67")
)]
#[derive(Clone, Debug)]
pub struct ApkReader;

impl crate::domain::prelude::ApkMetadataExtractor for ApkReader {
    async fn extract_metadata(
        &self,
        path: &std::path::Path,
    ) -> anyhow::Result<crate::domain::entity::ApkMetadata> {
        pkginfo::from_path(path)
    }
}

#[cfg(test)]
mod tests {
    use crate::{adapter_apk::ApkReader, domain::prelude::ApkMetadataExtractor};

    #[tokio::test]
    async fn should_extract_metadata_from_busybox_apk() {
        let current = std::env::current_dir().unwrap();
        let path = current.join("resources").join("busybox-1.37.0-r14.apk");
        let meta = ApkReader.extract_metadata(&path).await.unwrap();
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

    #[tokio::test]
    async fn should_extract_metadata_from_alpine_keys_apk() {
        let current = std::env::current_dir().unwrap();
        let path = current.join("resources").join("alpine-keys-2.5-r0.apk");
        let meta = ApkReader.extract_metadata(&path).await.unwrap();
        assert_eq!(meta.name, "alpine-keys");
        assert_eq!(meta.version, "2.5-r0");
        assert_eq!(meta.architecture, "x86_64");
        assert_eq!(meta.license, "MIT");
        assert!(meta.dependencies.is_empty());
        assert!(meta.provides.is_empty());
    }
}
