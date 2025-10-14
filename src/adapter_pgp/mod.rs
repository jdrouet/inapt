use std::path::PathBuf;

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

    pub fn build(self) -> anyhow::Result<PGPClient> {
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
