#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = inapt::Config::from_env()?;
    let app = config.build()?;
    app.run().await
}
