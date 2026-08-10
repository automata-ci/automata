use std::sync::Arc;

use automata_ci_runner_transport::PreparedRequest;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    RetryPolicy, RunnerRuntimeControlClient, RunnerRuntimeError, RunnerRuntimeEvent,
    RunnerRuntimeObserver, RuntimeControlErrorKind, RuntimeControlReply, RuntimeControlRetry,
    RuntimeExchangeKind, RuntimeRetryCause, RuntimeSleeper,
};

pub(crate) async fn exchange_exact(
    client: &dyn RunnerRuntimeControlClient,
    sleeper: &dyn RuntimeSleeper,
    observer: &dyn RunnerRuntimeObserver,
    policy: RetryPolicy,
    prepared: &PreparedRequest,
    cancellation: CancellationToken,
) -> Result<RuntimeControlReply, RunnerRuntimeError> {
    let mut consecutive_failures = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            return Err(RunnerRuntimeError::Shutdown);
        }
        match client.exchange(prepared, cancellation.clone()).await {
            Ok(reply) => return Ok(reply),
            Err(error) if error.kind() == RuntimeControlErrorKind::Cancelled => {
                return Err(RunnerRuntimeError::Shutdown);
            }
            Err(error) if error.retry() == RuntimeControlRetry::SamePreparedRequest => {
                let Some(cause) = RuntimeRetryCause::from_control_error(error.kind()) else {
                    return Err(RunnerRuntimeError::Shutdown);
                };
                consecutive_failures = consecutive_failures.saturating_add(1);
                let ramp_step = u16::try_from(consecutive_failures)
                    .unwrap_or(u16::MAX)
                    .min(policy.maximum_attempts());
                let entropy = retry_entropy(prepared, consecutive_failures);
                let delay = policy.jittered_delay_after(ramp_step, entropy);
                observer.observe(RunnerRuntimeEvent::RetryBackoff {
                    exchange: RuntimeExchangeKind::from_prepared(prepared),
                    cause,
                    delay,
                });
                sleeper.sleep(delay, cancellation.clone()).await;
                if cancellation.is_cancelled() {
                    return Err(RunnerRuntimeError::Shutdown);
                }
                observer.observe(RunnerRuntimeEvent::RetryAttempt {
                    exchange: RuntimeExchangeKind::from_prepared(prepared),
                });
            }
            Err(error) => return Err(RunnerRuntimeError::Client(error)),
        }
    }
}

fn retry_entropy(prepared: &PreparedRequest, consecutive_failures: u64) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"automata.runner-control.retry-jitter.v1");
    digest.update([0]);
    digest.update(prepared.operation_id().as_uuid().as_bytes());
    digest.update(consecutive_failures.to_be_bytes());
    let output: [u8; 32] = digest.finalize().into();
    u64::from_be_bytes(output[..8].try_into().expect("eight-byte digest prefix"))
}

pub(crate) async fn sleep_or_shutdown(
    sleeper: &Arc<dyn RuntimeSleeper>,
    delay: std::time::Duration,
    cancellation: &CancellationToken,
) -> Result<(), RunnerRuntimeError> {
    sleeper.sleep(delay, cancellation.clone()).await;
    if cancellation.is_cancelled() {
        Err(RunnerRuntimeError::Shutdown)
    } else {
        Ok(())
    }
}
