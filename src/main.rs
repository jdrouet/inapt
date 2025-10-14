#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tracing_config = inapt::tracing::Config::from_env()?;
    let tracer = tracing_config.install()?;

    let config_path = std::env::var("CONFIG_PATH")
        .ok()
        .unwrap_or("./config.toml".into());
    let config = inapt::Config::from_path(config_path)?;
    let app = config.build()?;
    let res = app.run().await;

    tracer.shutdown();

    res
}
