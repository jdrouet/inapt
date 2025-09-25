pub struct Config {
    #[allow(unused, reason = "preparation")]
    token: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            token: crate::with_env("GITHUB_TOKEN")?,
        })
    }

    pub fn build(self) -> anyhow::Result<Client> {
        Ok(Client)
    }
}

#[derive(Debug)]
pub struct Client;
