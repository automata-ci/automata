#[cfg(unix)]
use tracing::warn;
use tracing::{error, info};

/// Waits for the platform's normal process shutdown signal.
pub async fn wait() {
    wait_for_platform_signal().await;
}

#[cfg(unix)]
async fn wait_for_platform_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            error!(%error, "failed to install SIGTERM handler");
            wait_for_ctrl_c().await;
            return;
        }
    };

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => info!("received interrupt signal; starting graceful shutdown"),
                Err(error) => error!(%error, "failed to wait for interrupt signal"),
            }
        }
        received = terminate.recv() => {
            if received.is_some() {
                info!("received SIGTERM; starting graceful shutdown");
            } else {
                warn!("SIGTERM signal stream ended; starting graceful shutdown");
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_platform_signal() {
    wait_for_ctrl_c().await;
}

async fn wait_for_ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("received interrupt signal; starting graceful shutdown"),
        Err(error) => error!(%error, "failed to wait for interrupt signal"),
    }
}
