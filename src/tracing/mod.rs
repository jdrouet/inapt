use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub enum Config {
    Console(ConsoleConfig),
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self::Console(ConsoleConfig::from_env()?))
    }

    pub fn install(self) -> anyhow::Result<TracingProvider> {
        match self {
            Self::Console(inner) => inner.install(),
        }
    }
}

pub struct ConsoleConfig {
    color: bool,
}

impl ConsoleConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            color: crate::with_env_as_or("TRACING_CONSOLE_COLOR", true)?,
        })
    }

    fn install(self) -> anyhow::Result<TracingProvider> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_ansi(self.color))
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .with_env_var("TRACING_LEVEL")
                    .from_env_lossy(),
            )
            .try_init()?;
        Ok(TracingProvider::Console)
    }
}

pub enum TracingProvider {
    Console,
}

impl TracingProvider {
    pub async fn shutdown(self) {}
}
