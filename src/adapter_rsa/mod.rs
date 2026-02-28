use std::{io::Write, path::PathBuf};

use anyhow::Context;
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};

mod signer;

#[derive(serde::Deserialize)]
pub struct Config {
    private_key_path: PathBuf,
    #[serde(default = "default_key_name")]
    key_name: String,
}

fn default_key_name() -> String {
    "inapt.rsa.pub".to_string()
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "RSA adapter (#62), wired in #67")
)]
impl Config {
    fn generate_private_key(&self) -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 4096).context("unable to generate RSA private key")?;

        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .context("unable to encode RSA private key as PEM")?;

        let mut output = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.private_key_path)
            .context("unable to create RSA private key file")?;
        output
            .write_all(pem.as_bytes())
            .context("unable to write RSA private key")?;
        output
            .flush()
            .context("unable to flush RSA private key content")?;

        Ok(())
    }

    pub fn build(self) -> anyhow::Result<RsaClient> {
        if !self.private_key_path.exists() {
            self.generate_private_key()?;
        }

        let pem = std::fs::read_to_string(&self.private_key_path)
            .context("unable to read RSA private key file")?;

        let private_key = RsaPrivateKey::from_pkcs1_pem(&pem)
            .context("unable to parse RSA private key from PEM")?;

        Ok(RsaClient {
            private_key,
            key_name: self.key_name,
        })
    }
}

#[derive(Clone)]
pub struct RsaClient {
    private_key: RsaPrivateKey,
    key_name: String,
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn should_generate_key_and_build_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test-key.pem");

        let config = Config {
            private_key_path: key_path.clone(),
            key_name: "test.rsa.pub".to_string(),
        };

        let client = config.build().unwrap();
        assert!(key_path.exists());
        assert_eq!(client.key_name, "test.rsa.pub");
    }

    #[test]
    fn should_load_existing_key_from_pem() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("existing-key.pem");

        // Generate a key first
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem =
            rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&private_key, rsa::pkcs1::LineEnding::LF)
                .unwrap();
        std::fs::write(&key_path, pem.as_bytes()).unwrap();

        let config = Config {
            private_key_path: key_path,
            key_name: "existing.rsa.pub".to_string(),
        };

        let client = config.build().unwrap();
        assert_eq!(client.key_name, "existing.rsa.pub");
    }
}
