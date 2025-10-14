use std::{io::Write, path::PathBuf};

use anyhow::Context;
use sequoia_openpgp::{
    Cert,
    crypto::{KeyPair, Password},
    parse::Parse,
    policy::StandardPolicy,
};

mod cipher;

pub struct Config {
    private_key_path: PathBuf,
    passphrase: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Ok(Self {
            private_key_path: std::path::PathBuf::from(
                crate::with_env_or("PGP_PRIVATE_KEY_PATH", "./private-key.pem").as_ref(),
            ),
            passphrase: crate::maybe_env("PGP_PASSPHRASE"),
        })
    }

    fn generate_private_key(&self) -> anyhow::Result<()> {
        use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize, types::KeyFlags};

        let (cert, _) = CertBuilder::new()
            .set_validity_period(None)
            .add_subkey(
                KeyFlags::empty().set_transport_encryption().set_group_key(),
                None,
                None,
            )
            .add_signing_subkey()
            .add_certification_subkey()
            .add_storage_encryption_subkey()
            .generate()?;

        let mut output = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.private_key_path)
            .context("unable to create file")?;
        cert.as_tsk().armored().serialize(&mut output)?;
        output
            .flush()
            .context("unable to flush private key content")?;

        Ok(())
    }

    pub fn build(self) -> anyhow::Result<PGPClient> {
        if !self.private_key_path.exists() {
            self.generate_private_key()?;
        }

        let private_key = Cert::from_file(self.private_key_path)?;

        let policy = StandardPolicy::new();
        let keypair = private_key
            .keys()
            .secret()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .context("signing key not found")?;

        let mut private_key = keypair.key().clone();
        if private_key.secret().is_encrypted()
            && let Some(password) = self.passphrase
        {
            let password = Password::from(password);
            private_key
                .secret_mut()
                .decrypt_in_place(keypair.key(), &password)
                .context("unable to decrypt private key")?;
        };
        let keypair = private_key
            .into_keypair()
            .context("unable to convert to key pair")?;

        Ok(PGPClient { keypair })
    }
}

#[derive(Clone)]
pub struct PGPClient {
    keypair: KeyPair,
}
