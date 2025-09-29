mod releases;

pub struct Config {
    token: Option<secrecy::SecretString>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            token: crate::maybe_env("GITHUB_TOKEN").map(secrecy::SecretString::from),
        })
    }

    pub fn build(self) -> anyhow::Result<Client> {
        let builder = octocrab::Octocrab::builder();
        if let Some(_token) = self.token {
            todo!()
        }
        Ok(Client {
            inner: builder.build()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    inner: octocrab::Octocrab,
}
