use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::secret::{SecretString, SecureRandom};
use std::collections::BTreeMap;

use automata_ci_core::{RunnerId, SecretBinding};
use automata_ci_job_executor_actions::{
    ActionsJobExecutor, EphemeralJobSecret, EphemeralJobSecrets, SecretCustodyAcknowledger,
};
use automata_ci_protocol::ManagedSecretBindingOverlay;
use automata_ci_runner_runtime::{
    AdmissionRejection, CleanupFuture, CleanupRequest, ExecutionAdmission, ExecutionCancellation,
    ExecutionEvents, ExecutionRequest, ExecutorError, ExecutorErrorKind, ExecutorFuture,
    JobExecutor,
};
use automata_ci_runner_transport::{
    ClientError, ClientErrorKind, MANAGED_SECRET_DELIVERY_CREDENTIAL_KEY_ID,
    ManagedSecretDeliveryBinding, ManagedSecretDeliveryCoordinates, ManagedSecretDeliveryOperation,
    ManagedSecretDeliveryRequest, ManagedSecretDeliveryResponse, PreparedEphemeralRequest,
    RetryClass, RunnerEphemeralClient,
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize as _, Zeroizing};

const BEARER_BYTES: usize = 32;
const MAX_EXCHANGE_ATTEMPTS: usize = 3;

/// Execution-scoped managed-secret delivery in front of the secretless base executor.
pub(super) struct ManagedSecretJobExecutor {
    runner_id: RunnerId,
    base: Arc<ActionsJobExecutor>,
    client: Arc<dyn RunnerEphemeralClient>,
    random: Arc<dyn SecureRandom>,
}

impl ManagedSecretJobExecutor {
    pub(super) fn new(
        runner_id: RunnerId,
        base: Arc<ActionsJobExecutor>,
        client: Arc<dyn RunnerEphemeralClient>,
        random: Arc<dyn SecureRandom>,
    ) -> Self {
        Self {
            runner_id,
            base,
            client,
            random,
        }
    }

    async fn execute_inner(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> Result<automata_ci_core::JobResult, ExecutorError> {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let runtime_context = self.base.verified_runtime_context(request.job()).await?;
        if !runtime_context.secrets().is_empty() {
            return Err(invalid_job());
        }
        let Some(overlay) = request.managed_secret_bindings() else {
            return self.base.execute(request, events, cancellation).await;
        };
        overlay
            .validate_for(request.lease())
            .map_err(|_| invalid_job())?;
        if overlay.bindings().is_empty() {
            return self.base.execute(request, events, cancellation).await;
        }
        let runtime_bindings = runtime_bindings(overlay)?;
        let coordinates = delivery_coordinates(self.runner_id, &request, overlay)?;
        let bindings = sorted_bindings(overlay)?;
        let mut bearer = Zeroizing::new([0_u8; BEARER_BYTES]);
        self.random
            .fill(bearer.as_mut())
            .map_err(|_| unavailable())?;

        let fetch = prepared_request(
            ManagedSecretDeliveryOperation::Fetch,
            bearer.as_ref().to_vec(),
            coordinates,
            &bindings,
        )?;
        let response =
            exchange_same_request(self.client.as_ref(), &fetch, cancellation.token()).await?;
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let response_body = response.into_body();
        let response =
            ManagedSecretDeliveryResponse::decode(&response_body).map_err(|_| invalid_job())?;
        let custody = install_values(overlay, response)?;
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }

        let acknowledge = prepared_request(
            ManagedSecretDeliveryOperation::Acknowledge,
            bearer.as_ref().to_vec(),
            coordinates,
            &bindings,
        )?;
        let acknowledger: Arc<dyn SecretCustodyAcknowledger> = Arc::new(DeliveryAcknowledger {
            client: Arc::clone(&self.client),
            request: acknowledge,
        });
        let secrets = Arc::new(custody);
        self.base
            .with_managed_secret_custody(secrets, acknowledger, runtime_bindings)
            .execute(request, events, cancellation)
            .await
    }
}

impl JobExecutor for ManagedSecretJobExecutor {
    fn admit(
        &self,
        job: &automata_ci_core::JobIrEnvelope,
    ) -> Result<ExecutionAdmission, AdmissionRejection> {
        self.base.admit(job)
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(self.execute_inner(request, events, cancellation))
    }

    fn cleanup(
        &self,
        request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        self.base.cleanup(request, events, cancellation)
    }
}

impl fmt::Debug for ManagedSecretJobExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretJobExecutor")
            .field("runner_id", &self.runner_id)
            .field("base", &self.base)
            .field("client", &"configured")
            .field("random", &"configured")
            .finish()
    }
}

struct DeliveryAcknowledger {
    client: Arc<dyn RunnerEphemeralClient>,
    request: PreparedEphemeralRequest,
}

#[async_trait]
impl SecretCustodyAcknowledger for DeliveryAcknowledger {
    async fn acknowledge(&self, cancellation: CancellationToken) -> Result<(), ExecutorError> {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let response =
            exchange_same_request(self.client.as_ref(), &self.request, cancellation.clone())
                .await?;
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let body = response.into_body();
        match ManagedSecretDeliveryResponse::decode(&body) {
            Ok(ManagedSecretDeliveryResponse::Acknowledged) => Ok(()),
            Ok(ManagedSecretDeliveryResponse::Values(_)) | Err(_) => Err(invalid_job()),
        }
    }
}

impl fmt::Debug for DeliveryAcknowledger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeliveryAcknowledger([REDACTED])")
    }
}

fn delivery_coordinates(
    runner_id: RunnerId,
    request: &ExecutionRequest,
    overlay: &ManagedSecretBindingOverlay,
) -> Result<ManagedSecretDeliveryCoordinates, ExecutorError> {
    let lease = request.lease();
    if lease.runner_id() != runner_id {
        return Err(invalid_job());
    }
    Ok(ManagedSecretDeliveryCoordinates {
        runner_id: *runner_id.as_uuid().as_bytes(),
        session_id: *request.session_id().as_uuid().as_bytes(),
        slot: request.slot().get(),
        run_id: *request.job().job().run_id().as_uuid().as_bytes(),
        job_id: *request.job().job().job_id().as_uuid().as_bytes(),
        attempt_id: *lease.attempt_id().as_uuid().as_bytes(),
        lease_id: *lease.lease_id().as_uuid().as_bytes(),
        lease_issued_at_ms: lease.issued_at().get(),
        lease_expires_at_ms: lease.expires_at().get(),
        fencing_token: lease.fencing_token().get(),
        runtime_context_digest: request
            .job()
            .execution()
            .runtime_context()
            .digest()
            .into_bytes(),
        binding_overlay_digest: overlay.digest().into_bytes(),
    })
}

fn sorted_bindings(
    overlay: &ManagedSecretBindingOverlay,
) -> Result<Vec<ManagedSecretDeliveryBinding>, ExecutorError> {
    let mut bindings = overlay.bindings().iter().collect::<Vec<_>>();
    bindings.sort_unstable_by(|left, right| {
        left.binding()
            .binding_id()
            .cmp(right.binding().binding_id())
    });
    bindings
        .into_iter()
        .map(|entry| {
            let binding = entry.binding();
            let version = binding.version_id().ok_or_else(invalid_job)?;
            ManagedSecretDeliveryBinding::new(entry.canonical_name(), binding.binding_id(), version)
                .map_err(|_| invalid_job())
        })
        .collect()
}

fn runtime_bindings(
    overlay: &ManagedSecretBindingOverlay,
) -> Result<BTreeMap<String, SecretBinding>, ExecutorError> {
    let bindings = overlay
        .bindings()
        .iter()
        .map(|entry| (entry.canonical_name().to_owned(), entry.binding().clone()))
        .collect::<BTreeMap<_, _>>();
    (bindings.len() == overlay.bindings().len())
        .then_some(bindings)
        .ok_or_else(invalid_job)
}

fn prepared_request(
    operation: ManagedSecretDeliveryOperation,
    bearer: Vec<u8>,
    coordinates: ManagedSecretDeliveryCoordinates,
    bindings: &[ManagedSecretDeliveryBinding],
) -> Result<PreparedEphemeralRequest, ExecutorError> {
    let request = ManagedSecretDeliveryRequest::new(
        operation,
        MANAGED_SECRET_DELIVERY_CREDENTIAL_KEY_ID,
        bearer,
        coordinates,
        bindings.to_vec(),
    )
    .map_err(|_| invalid_job())?;
    PreparedEphemeralRequest::new(request.encode().map_err(|_| invalid_job())?)
        .map_err(|_| invalid_job())
}

fn install_values(
    overlay: &ManagedSecretBindingOverlay,
    response: ManagedSecretDeliveryResponse,
) -> Result<EphemeralJobSecrets, ExecutorError> {
    let ManagedSecretDeliveryResponse::Values(values) = response else {
        return Err(invalid_job());
    };
    let mut bindings = overlay
        .bindings()
        .iter()
        .map(automata_ci_protocol::ManagedSecretBindingOverlayEntry::binding)
        .collect::<Vec<_>>();
    bindings.sort_unstable_by(|left, right| left.binding_id().cmp(right.binding_id()));
    if bindings.len() != values.len() {
        return Err(invalid_job());
    }
    let entries = bindings
        .into_iter()
        .zip(values)
        .map(|(binding, value)| install_value(binding, value))
        .collect::<Result<Vec<_>, _>>()?;
    EphemeralJobSecrets::new(entries).map_err(|_| invalid_job())
}

fn install_value(
    binding: &SecretBinding,
    value: automata_ci_runner_transport::ManagedSecretDeliveryValue,
) -> Result<EphemeralJobSecret, ExecutorError> {
    if binding.binding_id() != value.binding_id()
        || binding.version_id() != Some(value.version_id())
    {
        return Err(invalid_job());
    }
    let mut bytes = value.into_value();
    let owned = std::mem::take(&mut *bytes);
    let text = String::from_utf8(owned).map_err(|error| {
        let mut rejected = error.into_bytes();
        rejected.zeroize();
        invalid_job()
    })?;
    let secret = SecretString::new(text).map_err(|_| invalid_job())?;
    EphemeralJobSecret::new(binding, secret).map_err(|_| invalid_job())
}

async fn exchange_same_request(
    client: &dyn RunnerEphemeralClient,
    request: &PreparedEphemeralRequest,
    cancellation: CancellationToken,
) -> Result<automata_ci_runner_transport::RunnerEphemeralResponse, ExecutorError> {
    for attempt in 0..MAX_EXCHANGE_ATTEMPTS {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        match client.exchange(request, cancellation.clone()).await {
            Ok(response) => return Ok(response),
            Err(error)
                if error.retry_class() == RetryClass::RetrySameRequest
                    && attempt + 1 < MAX_EXCHANGE_ATTEMPTS => {}
            Err(error) => return Err(map_client_error(error)),
        }
    }
    Err(unavailable())
}

const fn map_client_error(error: ClientError) -> ExecutorError {
    match error.kind() {
        ClientErrorKind::Cancelled => cancelled(),
        ClientErrorKind::Timeout => ExecutorError::new(ExecutorErrorKind::TimedOut),
        ClientErrorKind::Transport
        | ClientErrorKind::HttpStatus(_)
        | ClientErrorKind::InvalidResponse
        | ClientErrorKind::ResponseTooLarge
        | ClientErrorKind::InvalidProtobuf => unavailable(),
    }
}

const fn invalid_job() -> ExecutorError {
    ExecutorError::new(ExecutorErrorKind::InvalidJob)
}

const fn unavailable() -> ExecutorError {
    ExecutorError::new(ExecutorErrorKind::Unavailable)
}

const fn cancelled() -> ExecutorError {
    ExecutorError::new(ExecutorErrorKind::Cancelled)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use automata_ci_core::{
        AttemptId, FencingToken, Lease, LeaseId, RunnerId, SecretBinding, UnixMillis,
    };
    use automata_ci_job_executor_actions::SecretPort as _;
    use automata_ci_runner_transport::{
        EphemeralClientFuture, ManagedSecretDeliveryValue, RunnerEphemeralResponse,
    };

    use super::*;

    fn binding(id: &str, version: &str) -> SecretBinding {
        SecretBinding::new(id)
            .and_then(|binding| binding.with_version_id(version))
            .expect("exact secret binding")
    }

    fn lease() -> Lease {
        Lease::new(
            LeaseId::from_uuid(uuid::uuid!("00000000-0000-4000-8000-000000000006")),
            AttemptId::from_uuid(uuid::uuid!("00000000-0000-4000-8000-000000000005")),
            RunnerId::from_uuid(uuid::uuid!("00000000-0000-4000-8000-000000000001")),
            FencingToken::new(1).expect("fence"),
            UnixMillis::new(10),
            UnixMillis::new(20),
        )
        .expect("lease")
    }

    fn overlay() -> ManagedSecretBindingOverlay {
        ManagedSecretBindingOverlay::new(
            &lease(),
            [
                (
                    "ALPHA".to_owned(),
                    binding(
                        "00000000-0000-4000-8000-00000000000a",
                        "00000000-0000-4000-8000-00000000001a",
                    ),
                ),
                (
                    "BETA".to_owned(),
                    binding(
                        "00000000-0000-4000-8000-00000000000b",
                        "00000000-0000-4000-8000-00000000001b",
                    ),
                ),
            ],
        )
        .expect("overlay")
    }

    #[test]
    fn complete_exact_response_enters_shared_zeroizing_custody() {
        let response = ManagedSecretDeliveryResponse::Values(vec![
            ManagedSecretDeliveryValue::new(
                "00000000-0000-4000-8000-00000000000a",
                "00000000-0000-4000-8000-00000000001a",
                b"alpha-value".to_vec(),
            )
            .expect("first value"),
            ManagedSecretDeliveryValue::new(
                "00000000-0000-4000-8000-00000000000b",
                "00000000-0000-4000-8000-00000000001b",
                b"beta-value".to_vec(),
            )
            .expect("second value"),
        ]);
        let custody = install_values(&overlay(), response).expect("complete custody");
        assert_eq!(custody.len(), 2);
        assert_eq!(
            custody
                .resolve("00000000-0000-4000-8000-00000000000a")
                .expect("first binding")
                .expose_secret(),
            "alpha-value"
        );
        let diagnostic = format!("{custody:?}");
        assert!(!diagnostic.contains("alpha-value"));
        assert!(!diagnostic.contains("beta-value"));
    }

    #[test]
    fn partial_response_never_enters_custody() {
        let partial = ManagedSecretDeliveryResponse::Values(vec![
            ManagedSecretDeliveryValue::new(
                "00000000-0000-4000-8000-00000000000a",
                "00000000-0000-4000-8000-00000000001a",
                b"value".to_vec(),
            )
            .expect("partial value"),
        ]);
        assert_eq!(
            install_values(&overlay(), partial).unwrap_err().kind(),
            ExecutorErrorKind::InvalidJob
        );
    }

    #[test]
    fn changed_version_never_enters_custody() {
        let changed = ManagedSecretDeliveryResponse::Values(vec![
            ManagedSecretDeliveryValue::new(
                "00000000-0000-4000-8000-00000000000a",
                "00000000-0000-4000-8000-00000000002a",
                b"value".to_vec(),
            )
            .expect("changed version"),
            ManagedSecretDeliveryValue::new(
                "00000000-0000-4000-8000-00000000000b",
                "00000000-0000-4000-8000-00000000001b",
                b"value".to_vec(),
            )
            .expect("unchanged version"),
        ]);
        assert_eq!(
            install_values(&overlay(), changed).unwrap_err().kind(),
            ExecutorErrorKind::InvalidJob
        );
    }

    #[test]
    fn non_utf8_value_never_enters_custody() {
        let non_utf8 = ManagedSecretDeliveryResponse::Values(vec![
            ManagedSecretDeliveryValue::new(
                "00000000-0000-4000-8000-00000000000a",
                "00000000-0000-4000-8000-00000000001a",
                vec![0xff],
            )
            .expect("non-UTF8 value"),
            ManagedSecretDeliveryValue::new(
                "00000000-0000-4000-8000-00000000000b",
                "00000000-0000-4000-8000-00000000001b",
                b"value".to_vec(),
            )
            .expect("valid value"),
        ]);
        assert_eq!(
            install_values(&overlay(), non_utf8).unwrap_err().kind(),
            ExecutorErrorKind::InvalidJob
        );
    }

    #[derive(Debug)]
    struct AckClient {
        calls: AtomicUsize,
        body: Vec<u8>,
    }

    impl RunnerEphemeralClient for AckClient {
        fn exchange<'a>(
            &'a self,
            _request: &'a PreparedEphemeralRequest,
            _cancellation: CancellationToken,
        ) -> EphemeralClientFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                RunnerEphemeralResponse::from_body(self.body.clone())
                    .map_err(|_| unreachable!("test response is bounded"))
            })
        }
    }

    fn acknowledgement(client: Arc<dyn RunnerEphemeralClient>) -> DeliveryAcknowledger {
        let overlay = ManagedSecretBindingOverlay::new(
            &lease(),
            [(
                "TOKEN".to_owned(),
                binding(
                    "00000000-0000-4000-8000-00000000000a",
                    "00000000-0000-4000-8000-00000000001a",
                ),
            )],
        )
        .expect("overlay");
        let coordinates = ManagedSecretDeliveryCoordinates {
            runner_id: *lease().runner_id().as_uuid().as_bytes(),
            session_id: [2; 16],
            slot: 1,
            run_id: [3; 16],
            job_id: [4; 16],
            attempt_id: *lease().attempt_id().as_uuid().as_bytes(),
            lease_id: *lease().lease_id().as_uuid().as_bytes(),
            lease_issued_at_ms: 10,
            lease_expires_at_ms: 20,
            fencing_token: 1,
            runtime_context_digest: [7; 32],
            binding_overlay_digest: overlay.digest().into_bytes(),
        };
        let binding = ManagedSecretDeliveryBinding::new(
            "TOKEN",
            "00000000-0000-4000-8000-00000000000a",
            "00000000-0000-4000-8000-00000000001a",
        )
        .expect("binding");
        DeliveryAcknowledger {
            client,
            request: prepared_request(
                ManagedSecretDeliveryOperation::Acknowledge,
                vec![8; BEARER_BYTES],
                coordinates,
                &[binding],
            )
            .expect("acknowledgement request"),
        }
    }

    #[tokio::test]
    async fn acknowledgement_is_not_sent_after_cancellation() {
        let body = ManagedSecretDeliveryResponse::Acknowledged
            .encode()
            .expect("ack response");
        let client = Arc::new(AckClient {
            calls: AtomicUsize::new(0),
            body,
        });
        let acknowledger = acknowledgement(client.clone());
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            acknowledger
                .acknowledge(cancellation)
                .await
                .unwrap_err()
                .kind(),
            ExecutorErrorKind::Cancelled
        );
        assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exact_acknowledgement_response_completes_once() {
        let body = ManagedSecretDeliveryResponse::Acknowledged
            .encode()
            .expect("ack response");
        let client = Arc::new(AckClient {
            calls: AtomicUsize::new(0),
            body,
        });
        acknowledgement(client.clone())
            .acknowledge(CancellationToken::new())
            .await
            .expect("acknowledged");
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }
}
