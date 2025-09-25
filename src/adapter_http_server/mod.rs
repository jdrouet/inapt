use anyhow::Context;

mod handler;

const DEFAULT_ADDRESS: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
const DEFAULT_PORT: u16 = 3000;

pub struct Config {
    address: std::net::IpAddr,
    port: u16,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Ok(Self {
            address: crate::with_env_as_or("ADDRESS", DEFAULT_ADDRESS)?,
            port: crate::with_env_as_or("PORT", DEFAULT_PORT)?,
        })
    }

    pub fn build(self) -> anyhow::Result<Server> {
        Ok(Server {
            address: std::net::SocketAddr::from((self.address, self.port)),
        })
    }
}

#[derive(Debug)]
pub struct Server {
    address: std::net::SocketAddr,
}

impl Server {
    pub async fn run(self) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.address).await?;
        let app = handler::build();
        tracing::info!(address = ?self.address, "starting server");
        axum::serve(listener, app).await.context("server crashed")
    }
}
