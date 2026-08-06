pub mod http;
mod web;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::info;

use crate::{build_info::BuildInfo, shutdown};

pub(crate) async fn serve(address: SocketAddr) -> Result<()> {
    let router = http::router().context("failed to initialize HTTP application")?;
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind {address}"))?;
    let local_address = listener
        .local_addr()
        .context("failed to read the bound listen address")?;
    let build = BuildInfo::current();
    info!(
        address = %local_address,
        version = build.version,
        commit = build.commit,
        "server listening"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown::wait())
        .await
        .context("HTTP server failed")
}
