use anyhow::Context;

mod adapter_github;
mod adapter_http_server;
mod domain;

fn with_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("unable to find {name:?}"))
}

fn with_env_as_or<T>(name: &str, default_value: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    let Ok(value) = std::env::var(name) else {
        return Ok(default_value);
    };
    value
        .parse::<T>()
        .with_context(|| format!("unable to parse value from {name:?}"))
}

pub struct Config {
    github: adapter_github::Config,
    http_server: adapter_http_server::Config,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Ok(Self {
            github: adapter_github::Config::from_env()?,
            http_server: adapter_http_server::Config::from_env()?,
        })
    }

    pub fn build(self) -> anyhow::Result<Application> {
        Ok(Application {
            github: self.github.build()?,
            http_server: self.http_server.build()?,
        })
    }
}

pub struct Application {
    #[allow(unused, reason = "preparation")]
    github: adapter_github::Client,
    http_server: adapter_http_server::Server,
}

impl Application {
    pub async fn run(self) -> anyhow::Result<()> {
        self.http_server.run().await
    }
}
