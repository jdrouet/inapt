use crate::domain::entity::FileMetadata;

pub fn from_path(path: &std::path::Path) -> anyhow::Result<FileMetadata> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(path)?;
    let size = std::io::copy(&mut file, &mut hasher)?;
    let hash_bytes = hasher.finalize();

    Ok(FileMetadata {
        size,
        sha256: hex::encode(hash_bytes),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn should_parse_zlib_amd64_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local
            .join("resources")
            .join("zlib1g_1.3.dfsg+really1.3.1-1+b1_amd64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.size, 88892);
        assert_eq!(
            meta.sha256,
            "015be740d6236ad114582dea500c1d907f29e16d6db00566ca32fb68d71ac90d"
        );
    }

    #[test]
    fn should_parse_zlib_arm64_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local
            .join("resources")
            .join("zlib1g_1.3.dfsg+really1.3.1-1+b1_arm64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.size, 85116);
        assert_eq!(
            meta.sha256,
            "209aa5cf671e97b9eb0410844fa6df4cae2e75b0c72e7802ab6c8ece13e6ddef"
        );
    }

    #[test]
    fn should_parse_curl_amd64_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local.join("resources").join("curl_8.14.1-2_amd64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.size, 269228);
        assert_eq!(
            meta.sha256,
            "5272249012b8065cdc6ca3cbf7d01d516a3037b64a91915311ab52e2260a862d"
        );
    }

    #[test]
    fn should_parse_curl_arm64_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local.join("resources").join("curl_8.14.1-2_arm64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.size, 261988);
        assert_eq!(
            meta.sha256,
            "a55043aeec3fab6a6317bb1e23f6907ebbf3a28e658145b53be65edae9b7cbea"
        );
    }

    #[test]
    fn should_parse_htop_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local
            .join("resources")
            .join("htop_2.0.1-1ubuntu1_amd64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.size, 76358);
        assert_eq!(
            meta.sha256,
            "d29864c97dce191f33e335927b1b2ee59e30ba6d779078b73d9ecd3f7c0da19f"
        );
    }
}
