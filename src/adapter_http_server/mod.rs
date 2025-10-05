use anyhow::Context;

mod handler;
mod middleware;

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

    pub fn builder<AR>(self) -> anyhow::Result<ServerBuilder<AR>> {
        Ok(ServerBuilder {
            address: std::net::SocketAddr::from((self.address, self.port)),
            apt_repository: None,
        })
    }
}

#[derive(Debug)]
pub struct ServerBuilder<AR> {
    address: std::net::SocketAddr,
    apt_repository: Option<AR>,
}

impl<AR> ServerBuilder<AR>
where
    AR: Clone + crate::domain::prelude::AptRepositoryReader,
{
    pub fn with_apt_repository(self, value: AR) -> Self {
        Self {
            address: self.address,
            apt_repository: Some(value),
        }
    }
}

impl<AR> ServerBuilder<AR>
where
    AR: Clone + crate::domain::prelude::AptRepositoryReader,
{
    pub fn build(self) -> anyhow::Result<Server> {
        let router = handler::build()
            .layer(middleware::tracing::layer())
            .with_state(ServerState {
                apt_repository: self
                    .apt_repository
                    .ok_or_else(|| anyhow::anyhow!("apt_repository service not defined"))?,
            });
        Ok(Server {
            address: self.address,
            router,
        })
    }
}

#[derive(Debug)]
pub struct Server {
    address: std::net::SocketAddr,
    router: axum::Router,
}

impl Server {
    pub async fn run(self) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.address).await?;
        tracing::info!(address = ?self.address, "starting server");
        axum::serve(listener, self.router)
            .await
            .context("server crashed")
    }
}

#[derive(Clone)]
struct ServerState<AR>
where
    AR: Clone + crate::domain::prelude::AptRepositoryReader,
{
    #[allow(unused, reason = "early")]
    apt_repository: AR,
}
