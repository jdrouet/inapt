use std::future::Future;

use anyhow::Context;

mod handler;
mod middleware;

/// Trait for components that can report their health status.
/// Used by the HTTP server to implement the `/health` endpoint.
pub trait HealthCheck: Send + Sync + 'static {
    /// Check if the component is healthy.
    /// Returns Ok(()) if healthy, Err with details if not.
    fn health_check(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

const DEFAULT_ADDRESS: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
const DEFAULT_PORT: u16 = 3000;

#[derive(serde::Deserialize)]
pub struct Config {
    #[serde(default = "Config::default_address")]
    address: std::net::IpAddr,
    #[serde(default = "Config::default_port")]
    port: u16,
}

impl Config {
    pub const fn default_address() -> std::net::IpAddr {
        DEFAULT_ADDRESS
    }
    pub const fn default_port() -> u16 {
        DEFAULT_PORT
    }

    pub fn builder<AR, HC>(self) -> anyhow::Result<ServerBuilder<AR, HC>> {
        Ok(ServerBuilder {
            address: std::net::SocketAddr::from((self.address, self.port)),
            apt_repository: None,
            health_checker: None,
        })
    }
}

#[derive(Debug)]
pub struct ServerBuilder<AR, HC> {
    address: std::net::SocketAddr,
    apt_repository: Option<AR>,
    health_checker: Option<HC>,
}

impl<AR, HC> ServerBuilder<AR, HC>
where
    AR: Clone + crate::domain::prelude::AptRepositoryReader,
    HC: Clone + HealthCheck,
{
    pub fn with_apt_repository(self, value: AR) -> Self {
        Self {
            apt_repository: Some(value),
            ..self
        }
    }

    pub fn with_health_checker(self, value: HC) -> Self {
        Self {
            health_checker: Some(value),
            ..self
        }
    }

    pub fn build(self) -> anyhow::Result<Server> {
        let router = handler::build()
            .layer(middleware::tracing::layer())
            .with_state(ServerState {
                apt_repository: self
                    .apt_repository
                    .ok_or_else(|| anyhow::anyhow!("apt_repository service not defined"))?,
                health_checker: self
                    .health_checker
                    .ok_or_else(|| anyhow::anyhow!("health_checker not defined"))?,
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
pub(crate) struct ServerState<AR, HC>
where
    AR: Clone + crate::domain::prelude::AptRepositoryReader,
    HC: Clone + HealthCheck,
{
    pub(crate) apt_repository: AR,
    pub(crate) health_checker: HC,
}
