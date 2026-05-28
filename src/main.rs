use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    okta_awscli_rs::cli::run().await
}
