#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = inapt::Config::from_env()?;
    let app = config.build()?;
    app.run().await
}
