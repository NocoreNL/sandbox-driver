//! The ACA provider served as a sandbox-driver plugin.
//!
//! Speaks the JSON-RPC plugin protocol on stdin/stdout and drives Azure
//! Container Apps sessions over the data-plane REST API. Stdout belongs
//! to the protocol; logs go to stderr.
//!
//! TODO(Task 12): `AcaProvider::connect` is currently `unimplemented!()`.

use std::io::stderr;
use std::sync::Arc;

use anyhow::Context as _;
use sandbox_driver_aca::provider::AcaProvider;
use sandbox_driver_protocol::serve_stdio;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(stderr))
        .try_init()
        .context("configuring aca plugin diagnostics")?;

    tracing::info!(provider_kind = "aca", "aca plugin starting");
    let provider = AcaProvider::connect().await.context("connecting to ACA")?;
    serve_stdio(Arc::new(provider))
        .await
        .context("serving the aca provider plugin")
}
