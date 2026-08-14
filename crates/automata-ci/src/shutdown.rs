use tracing::{error, info};

#[cfg(unix)]
use tracing::warn;

/// Waits for the platform's normal process shutdown signal.
pub async fn wait() {
    wait_for_platform_signal(true).await;
}

pub(crate) async fn wait_without_logging() {
    wait_for_platform_signal(false).await;
}

#[cfg(unix)]
async fn wait_for_platform_signal(log_signal: bool) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            if log_signal {
                error!(%error, "failed to install SIGTERM handler");
            }
            wait_for_ctrl_c(log_signal).await;
            return;
        }
    };

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if log_signal {
                match result {
                    Ok(()) => info!("received interrupt signal; starting graceful shutdown"),
                    Err(error) => error!(%error, "failed to wait for interrupt signal"),
                }
            }
        }
        received = terminate.recv() => {
            if log_signal {
                if received.is_some() {
                    info!("received SIGTERM; starting graceful shutdown");
                } else {
                    warn!("SIGTERM signal stream ended; starting graceful shutdown");
                }
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_platform_signal(log_signal: bool) {
    wait_for_ctrl_c(log_signal).await;
}

async fn wait_for_ctrl_c(log_signal: bool) {
    let result = tokio::signal::ctrl_c().await;
    if log_signal {
        match result {
            Ok(()) => info!("received interrupt signal; starting graceful shutdown"),
            Err(error) => error!(%error, "failed to wait for interrupt signal"),
        }
    }
}
