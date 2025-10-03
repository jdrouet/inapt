#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tracing_config = inapt::tracing::Config::from_env()?;
    let tracer = tracing_config.install()?;

    let config = inapt::Config::from_env()?;
    let app = config.build()?;
    let res = app.run().await;

    tracer.shutdown();

    res
}
