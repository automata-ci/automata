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
    serve_listener(listener).await
}

async fn serve_listener(listener: TcpListener) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use super::*;
    use crate::cli::{StatusHttpPolicy, fetch_control_plane_status};

    #[tokio::test]
    async fn preview_listener_serves_status() {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("preview listener must bind");
        let address = listener
            .local_addr()
            .expect("preview listener address must be available");
        let task = tokio::spawn(serve_listener(listener));

        let policy =
            StatusHttpPolicy::new(Duration::from_secs(5), Duration::from_mins(1), 64 * 1024)
                .expect("preview test status policy must be valid");
        let status = fetch_control_plane_status(&format!("http://{address}"), policy)
            .await
            .expect("preview status must be available");

        assert_eq!(status["health"]["status"], "ok");
        assert_eq!(status["health"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(status["readiness"]["ready"], true);

        task.abort();
        let error = task
            .await
            .expect_err("aborted preview task must not complete");
        assert!(error.is_cancelled());
    }
}
