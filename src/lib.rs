use anyhow::Context;

const DEFAULT_ADDRESS: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
const DEFAULT_PORT: u16 = 3000;

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
    address: std::net::IpAddr,
    port: u16,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Ok(Self {
            address: with_env_as_or("ADDRESS", DEFAULT_ADDRESS)?,
            port: with_env_as_or("PORT", DEFAULT_PORT)?,
        })
    }

    pub fn build(self) -> anyhow::Result<Application> {
        Ok(Application {
            address: std::net::SocketAddr::from((self.address, self.port)),
        })
    }
}

pub struct Application {
    address: std::net::SocketAddr,
}

impl Application {
    pub async fn run(self) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.address).await?;
        let app = axum::Router::new();
        axum::serve(listener, app).await.context("server crashed")
    }
}
