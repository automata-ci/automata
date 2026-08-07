//! Dependency-free release-image smoke and UI-preview service.

use anyhow::{Context as _, Result};
use tokio::net::TcpListener;
use tracing::info;

use crate::{app::http, build_info::BuildInfo, cli::PreviewArgs, shutdown};

/// Serves health, readiness, embedded assets, and server-rendered UI routes.
///
/// Unlike [`crate::server::serve`], this deliberately composes no database,
/// object store, scheduler, Results API, or runner-control listener. Keeping it
/// as a distinct command prevents missing production credentials from silently
/// weakening the control plane while still allowing the fully static release
/// image to be exercised from `FROM scratch`.
///
/// # Errors
///
/// Returns an error when the listener cannot bind, the embedded renderer cannot
/// initialize, or the HTTP service fails.
pub async fn serve(args: &PreviewArgs) -> Result<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .context("failed to bind preview listener")?;
    let address = listener
        .local_addr()
        .context("failed to inspect preview listener")?;
    let router = http::router().context("failed to initialize preview application")?;
    let build = BuildInfo::current();
    info!(
        %address,
        version = build.version,
        commit = build.commit,
        "dependency-free preview listening"
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown::wait())
        .await
        .context("preview HTTP service failed")
}
