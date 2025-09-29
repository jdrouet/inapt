use std::collections::HashMap;

use anyhow::Context;

use crate::domain::entity::PackageControl;

pub fn from_path(path: &std::path::Path) -> anyhow::Result<PackageControl> {
    let file = std::fs::File::open(path).context("unable to open file")?;
    let control = metadata(file)?;
    parse_control(control.as_str())
}

/// Return (size, sha256, control_fields) for a .deb given as bytes.
fn metadata<R: std::io::Read>(reader: R) -> anyhow::Result<String> {
    let mut archive = ar::Archive::new(reader);

    while let Some(entry) = archive.next_entry() {
        let entry = entry.context("invalid entry")?;

        // ar identifiers are ASCII; trim padding
        let name = std::str::from_utf8(entry.header().identifier())
            .unwrap_or("")
            .trim()
            .to_string();

        if name.starts_with("control.tar") {
            // entry.read_to_end(&mut buf)?;
            if name.ends_with(".gz") {
                return read_control(flate2::read::GzDecoder::new(entry));
            }
            if name.ends_with(".xz") {
                return read_control(xz2::read::XzDecoder::new(entry));
            }
            if name.ends_with(".zst") {
                return read_control(zstd::stream::read::Decoder::new(entry)?);
            }
            if name == "control.tar" {
                return read_control(entry);
            }
            anyhow::bail!("unsupported control.tar compression: {name}")
        }
    }

    anyhow::bail!("control.tar.* not found in deb")
}

// control.tar.* contains files, we want the "control" file text.
fn read_control<R: std::io::Read>(reader: R) -> anyhow::Result<String> {
    use std::io::Read;

    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry
            .path()
            .ok()
            .map(|p| p.to_path_buf().to_string_lossy().to_string())
            .unwrap_or_default();
        if path.ends_with("/control") || path == "control" {
            let mut value = String::new();
            entry.read_to_string(&mut value)?;
            return Ok(value);
        }
    }
    anyhow::bail!("control file not found inside control.tar")
}

fn parse_control(input: &str) -> anyhow::Result<PackageControl> {
    let mut builder = ControlBuilder::default();
    for next in input.split("\n") {
        builder.parse(next)?;
    }
    builder.build()
}

#[derive(Debug, Default)]
struct ControlBuilder<'a> {
    inner: HashMap<&'a str, Vec<&'a str>>,
    previous: Option<&'a str>,
}

impl<'a> ControlBuilder<'a> {
    fn parse(&mut self, next: &'a str) -> anyhow::Result<()> {
        if next.trim().is_empty() {
            return Ok(());
        }
        if let Some(following) = next.strip_prefix([' ', '\t']) {
            if let Some(previous) = self.previous {
                self.inner.entry(previous).or_default().push(following);
                return Ok(());
            } else {
                anyhow::bail!("expected previous element")
            }
        }
        if let Some((name, value)) = next.split_once(": ") {
            self.inner.entry(name).or_default().push(value);
            self.previous.replace(name);
        }
        Ok(())
    }

    fn take_string(&mut self, name: &str) -> Option<String> {
        self.inner.remove(name).map(|values| values.join("\n"))
    }

    fn take_strings(&mut self, name: &str) -> Option<Vec<String>> {
        self.inner
            .remove(name)
            .map(|values| values.into_iter().map(String::from).collect())
    }

    fn build(mut self) -> anyhow::Result<PackageControl> {
        Ok(PackageControl {
            package: self
                .take_string("Package")
                .ok_or_else(|| anyhow::anyhow!("unable to find package name"))?,
            version: self
                .take_string("Version")
                .ok_or_else(|| anyhow::anyhow!("unable to find package version"))?,
            section: self.take_string("Section"),
            priority: self
                .take_string("Priority")
                .ok_or_else(|| anyhow::anyhow!("unable to find package priority"))?,
            architecture: self
                .take_string("Architecture")
                .ok_or_else(|| anyhow::anyhow!("unable to find package architecture"))?,
            maintainer: self
                .take_string("Maintainer")
                .ok_or_else(|| anyhow::anyhow!("unable to find package maintainer"))?,
            description: self
                .take_strings("Description")
                .ok_or_else(|| anyhow::anyhow!("unable to find package description"))?,
            others: self
                .inner
                .into_iter()
                .map(|(key, values)| {
                    (
                        key.to_string(),
                        values.into_iter().map(String::from).collect(),
                    )
                })
                .collect(),
        })
    }
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
        assert_eq!(meta.package, "zlib1g");
        assert_eq!(meta.version, "1:1.3.dfsg+really1.3.1-1+b1");
        assert_eq!(meta.architecture, "amd64");
    }

    #[test]
    fn should_parse_zlib_arm64_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local
            .join("resources")
            .join("zlib1g_1.3.dfsg+really1.3.1-1+b1_arm64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.package, "zlib1g");
    }

    #[test]
    fn should_parse_curl_amd64_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local.join("resources").join("curl_8.14.1-2_amd64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.package, "curl");
    }

    #[test]
    fn should_parse_curl_arm64_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local.join("resources").join("curl_8.14.1-2_arm64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.package, "curl");
    }

    #[test]
    fn should_parse_htop_deb_file() {
        let local = std::env::current_dir().unwrap();
        let deb_file = local
            .join("resources")
            .join("htop_2.0.1-1ubuntu1_amd64.deb");
        let meta = super::from_path(&deb_file).unwrap();
        assert_eq!(meta.package, "htop");
    }
}
