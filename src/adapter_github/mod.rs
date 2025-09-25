mod releases;

pub struct Config {
    token: secrecy::SecretString,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            token: secrecy::SecretString::from(crate::with_env("GITHUB_TOKEN")?),
        })
    }

    pub fn build(self) -> anyhow::Result<Client> {
        Ok(Client {
            inner: octocrab::Octocrab::builder().build()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    inner: octocrab::Octocrab,
}
