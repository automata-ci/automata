//! Bounded CLI client for authenticated, idempotent workflow reruns.

use std::{fmt, time::Duration};

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::session_credential::SessionCredential;
use bytes::Bytes;
use reqwest::{Client, Method, Request, Response, StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use uuid::Uuid;

use super::{
    OutputFormat, RerunArgs, RerunSelection,
    auth::{
        CliServerOrigin, auth_client, bearer_header, decode_json_response,
        discard_bounded_response, retry_after_seconds,
    },
    credential_store::{CliAuthProcessLock, CliCredentialStore, SecretServiceCredentialStore},
};

const MAX_REQUEST_ATTEMPTS: usize = 3;
const MAX_RETRY_DELAY_SECONDS: u64 = 5;
const SERVER_RETRY_DELAY: Duration = Duration::from_secs(1);
const TRANSPORT_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
struct RetryPolicy {
    attempts: usize,
    server_delay: Duration,
    transport_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: MAX_REQUEST_ATTEMPTS,
            server_delay: SERVER_RETRY_DELAY,
            transport_delay: TRANSPORT_RETRY_DELAY,
        }
    }
}

pub(crate) async fn execute_rerun_command(
    server_url: &str,
    output: OutputFormat,
    args: &RerunArgs,
) -> Result<()> {
    validate_arguments(args)?;
    let origin = CliServerOrigin::new(server_url)
        .context("rerun endpoint policy rejected the server URL")?;
    let _process_lock = CliAuthProcessLock::acquire(origin.as_str())
        .context("CLI rerun operation could not be serialized")?;
    let store =
        SecretServiceCredentialStore::discover().context("CLI session custody is unavailable")?;
    let completed =
        execute_rerun_command_with(origin, args, &store, RetryPolicy::default()).await?;
    print_rerun(output, &completed)
}

async fn execute_rerun_command_with(
    origin: CliServerOrigin,
    args: &RerunArgs,
    store: &dyn CliCredentialStore,
    retry_policy: RetryPolicy,
) -> Result<CompletedRerun> {
    let selection = validate_arguments(args)?;
    let client = auth_client().context("failed to configure the workflow rerun client")?;
    let credential = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
        .ok_or_else(|| anyhow::anyhow!("no CLI session exists; run `automata auth login`"))?;
    let operation_id = args.operation_id.unwrap_or_else(Uuid::new_v4);
    submit_rerun(
        &client,
        &origin,
        &credential,
        args,
        selection,
        operation_id,
        retry_policy,
    )
    .await
}

fn validate_arguments(args: &RerunArgs) -> Result<SelectionDocument> {
    if args.source_run_id.is_nil() {
        bail!("source run ID must be a non-nil canonical UUID");
    }
    if args
        .operation_id
        .is_some_and(|operation_id| operation_id.is_nil())
    {
        bail!("operation ID must be a non-nil canonical UUID");
    }
    match (args.selection, args.job_id) {
        (RerunSelection::EntireWorkflow, None) => Ok(SelectionDocument {
            mode: "entire_workflow",
            logical_job_id: None,
        }),
        (RerunSelection::FailedJobsAndDependents, None) => Ok(SelectionDocument {
            mode: "failed_jobs_and_dependents",
            logical_job_id: None,
        }),
        (RerunSelection::JobAndDependents, Some(logical_job_id)) if !logical_job_id.is_nil() => {
            Ok(SelectionDocument {
                mode: "job_and_dependents",
                logical_job_id: Some(logical_job_id),
            })
        }
        (RerunSelection::JobAndDependents, _) => {
            bail!("--job-id is required for --selection job-and-dependents")
        }
        (RerunSelection::EntireWorkflow | RerunSelection::FailedJobsAndDependents, Some(_)) => {
            bail!("--job-id is valid only for --selection job-and-dependents")
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the reviewed request keeps client, credential, exact target, identity, and retry policy explicit"
)]
async fn submit_rerun(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    args: &RerunArgs,
    selection: SelectionDocument,
    operation_id: Uuid,
    retry_policy: RetryPolicy,
) -> Result<CompletedRerun> {
    let endpoint = rerun_endpoint(origin, args)?;
    let body = serde_json::to_vec(&RerunRequestDocument {
        operation_id,
        selection,
    })
    .context("workflow rerun request could not be encoded")?;
    let request = client
        .request(Method::POST, endpoint)
        .header(header::AUTHORIZATION, bearer_header(credential)?)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body))
        .build()
        .map_err(reqwest::Error::without_url)
        .context("workflow rerun request could not be constructed")?;
    let response = send_with_retries(client, &request, retry_policy)
        .await
        .map_err(|error| match error {
            RerunRequestError::Transport | RerunRequestError::InvalidRetryResponse => {
                anyhow::anyhow!(recovery_hint(operation_id))
            }
            RerunRequestError::InvalidPolicy | RerunRequestError::NonReplayableRequest => {
                anyhow::Error::new(error)
            }
        })?;
    let status = response.status();
    match status {
        StatusCode::CREATED | StatusCode::OK => {
            let document: RerunResponseDocument = decode_json_response(response)
                .await
                .with_context(|| recovery_hint(operation_id))?;
            validate_response(&document, status, args.source_run_id, operation_id)
                .with_context(|| recovery_hint(operation_id))
        }
        status if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() => {
            discard_bounded_response(response)
                .await
                .with_context(|| recovery_hint(operation_id))?;
            Err(anyhow::anyhow!(recovery_hint(operation_id)))
        }
        _ => response_error(response, status).await,
    }
}

fn rerun_endpoint(origin: &CliServerOrigin, args: &RerunArgs) -> Result<Url> {
    let mut endpoint = origin.endpoint("/api/v1/repositories");
    let source_run_id = args.source_run_id.hyphenated().to_string();
    endpoint
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("workflow rerun endpoint could not be constructed"))?
        .extend([
            args.repository.owner(),
            args.repository.name(),
            "runs",
            &source_run_id,
            "reruns",
        ]);
    Ok(endpoint)
}

async fn send_with_retries(
    client: &Client,
    request: &Request,
    policy: RetryPolicy,
) -> std::result::Result<Response, RerunRequestError> {
    if policy.attempts == 0 {
        return Err(RerunRequestError::InvalidPolicy);
    }
    for attempt in 0..policy.attempts {
        let request = request
            .try_clone()
            .ok_or(RerunRequestError::NonReplayableRequest)?;
        match client.execute(request).await {
            Ok(response)
                if attempt + 1 < policy.attempts
                    && matches!(
                        response.status(),
                        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                    ) =>
            {
                let delay = match retry_after_seconds(&response) {
                    Some(seconds) if seconds <= MAX_RETRY_DELAY_SECONDS => {
                        Duration::from_secs(seconds)
                    }
                    Some(_) => return Err(RerunRequestError::InvalidRetryResponse),
                    None => policy.server_delay,
                };
                discard_bounded_response(response)
                    .await
                    .map_err(|_| RerunRequestError::InvalidRetryResponse)?;
                sleep(delay).await;
            }
            Ok(response) => return Ok(response),
            Err(_) if attempt + 1 < policy.attempts => sleep(policy.transport_delay).await,
            Err(_) => return Err(RerunRequestError::Transport),
        }
    }
    Err(RerunRequestError::Transport)
}

fn validate_response(
    document: &RerunResponseDocument,
    status: StatusCode,
    requested_source_run_id: Uuid,
    operation_id: Uuid,
) -> Result<CompletedRerun> {
    let source_run_id = canonical_response_uuid(&document.source_run_id)?;
    let run_id = canonical_response_uuid(&document.run_id)?;
    let expected_replay = status == StatusCode::OK;
    if source_run_id != requested_source_run_id
        || run_id == source_run_id
        || document.public_run_id == 0
        || document.run_number == 0
        || document.run_attempt < 2
        || document.replay != expected_replay
    {
        bail!("control plane returned inconsistent workflow rerun metadata");
    }
    Ok(CompletedRerun {
        operation_id,
        source_run_id,
        run_id,
        public_run_id: document.public_run_id,
        run_number: document.run_number,
        run_attempt: document.run_attempt,
        replay: document.replay,
    })
}

fn canonical_response_uuid(value: &str) -> Result<Uuid> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| anyhow::anyhow!("control plane returned invalid workflow rerun metadata"))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        bail!("control plane returned invalid workflow rerun metadata");
    }
    Ok(parsed)
}

async fn response_error<T>(response: Response, status: StatusCode) -> Result<T> {
    discard_bounded_response(response).await?;
    match status {
        StatusCode::UNAUTHORIZED => bail!("CLI session is no longer authorized"),
        StatusCode::FORBIDDEN => bail!("workflow rerun requires runs:rerun authority"),
        StatusCode::NOT_FOUND => bail!("workflow rerun source is unavailable"),
        StatusCode::BAD_REQUEST
        | StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            bail!("control plane rejected the workflow rerun request")
        }
        StatusCode::CONFLICT => bail!("workflow rerun conflicts with current source state"),
        _ => bail!("workflow rerun request returned HTTP {status}"),
    }
}

fn recovery_hint(operation_id: Uuid) -> String {
    format!(
        "workflow rerun outcome is indeterminate; retry the same request with --operation-id {}",
        operation_id.hyphenated()
    )
}

fn print_rerun(output: OutputFormat, completed: &CompletedRerun) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("operation_id\t{}", completed.operation_id.hyphenated());
            println!("source_run_id\t{}", completed.source_run_id.hyphenated());
            println!("run_id\t{}", completed.run_id.hyphenated());
            println!("public_run_id\t{}", completed.public_run_id);
            println!("run_number\t{}", completed.run_number);
            println!("run_attempt\t{}", completed.run_attempt);
            println!("replay\t{}", completed.replay);
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(completed)?);
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct RerunRequestDocument {
    operation_id: Uuid,
    selection: SelectionDocument,
}

#[derive(Debug, Serialize)]
struct SelectionDocument {
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_job_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RerunResponseDocument {
    source_run_id: String,
    run_id: String,
    public_run_id: u64,
    run_number: u64,
    run_attempt: u32,
    replay: bool,
}

#[derive(Debug, Serialize)]
struct CompletedRerun {
    operation_id: Uuid,
    source_run_id: Uuid,
    run_id: Uuid,
    public_run_id: u64,
    run_number: u64,
    run_attempt: u32,
    replay: bool,
}

#[derive(Clone, Copy, Debug)]
enum RerunRequestError {
    InvalidPolicy,
    NonReplayableRequest,
    InvalidRetryResponse,
    Transport,
}

impl fmt::Display for RerunRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "workflow rerun retry policy is invalid",
            Self::NonReplayableRequest => "workflow rerun request cannot be replayed safely",
            Self::InvalidRetryResponse => "control plane returned an invalid retry response",
            Self::Transport => "workflow rerun request transport failed",
        })
    }
}

impl std::error::Error for RerunRequestError {}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use axum::{
        Router,
        body::Bytes as AxumBytes,
        extract::{Path, State},
        http::HeaderMap,
        response::Response as AxumResponse,
        routing::post,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::cli::{OperatorArgs, RepositoryRef, credential_store::CredentialStoreError};

    const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const REPOSITORY_OWNER: &str = "automata-ci";
    const REPOSITORY_NAME: &str = "automata";
    const SOURCE_RUN_ID: &str = "20000000-0000-4000-8000-000000000002";
    const LOGICAL_JOB_ID: &str = "30000000-0000-4000-8000-000000000003";
    const OPERATION_ID: &str = "40000000-0000-4000-8000-000000000004";
    const RERUN_RUN_ID: &str = "50000000-0000-4000-8000-000000000005";

    #[derive(Debug)]
    struct FixedCredentialStore;

    #[async_trait]
    impl CliCredentialStore for FixedCredentialStore {
        async fn load(
            &self,
            _server_origin: &str,
        ) -> std::result::Result<Option<SessionCredential>, CredentialStoreError> {
            Ok(Some(
                SessionCredential::from_raw(SESSION).expect("test CLI credential"),
            ))
        }

        async fn store(
            &self,
            _server_origin: &str,
            _credential: &SessionCredential,
        ) -> std::result::Result<(), CredentialStoreError> {
            Err(CredentialStoreError::Unavailable)
        }

        async fn remove(
            &self,
            _server_origin: &str,
        ) -> std::result::Result<(), CredentialStoreError> {
            Err(CredentialStoreError::Unavailable)
        }
    }

    #[derive(Debug, Default)]
    struct ExactRequestEvidence {
        attempts: AtomicUsize,
        authorized: AtomicBool,
        json_content_type: AtomicBool,
        paths: Mutex<Vec<(String, String, String)>>,
        bodies: Mutex<Vec<Value>>,
    }

    async fn retry_then_create(
        State(evidence): State<Arc<ExactRequestEvidence>>,
        Path((owner, repository, source_run_id)): Path<(String, String, String)>,
        headers: HeaderMap,
        body: AxumBytes,
    ) -> AxumResponse {
        evidence.authorized.store(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                == Some("Bearer v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Ordering::Relaxed,
        );
        evidence.json_content_type.store(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                == Some("application/json"),
            Ordering::Relaxed,
        );
        evidence
            .paths
            .lock()
            .expect("paths")
            .push((owner, repository, source_run_id));
        evidence
            .bodies
            .lock()
            .expect("bodies")
            .push(serde_json::from_slice(&body).expect("request JSON"));
        if evidence.attempts.fetch_add(1, Ordering::Relaxed) == 0 {
            return AxumResponse::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(axum::body::Body::empty())
                .expect("retry response");
        }
        AxumResponse::builder()
            .status(StatusCode::CREATED)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                json!({
                    "source_run_id": SOURCE_RUN_ID,
                    "run_id": RERUN_RUN_ID,
                    "public_run_id": 41,
                    "run_number": 17,
                    "run_attempt": 2,
                    "replay": false
                })
                .to_string(),
            ))
            .expect("created response")
    }

    #[tokio::test]
    async fn credentialed_retry_preserves_exact_path_body_and_operation_identity() {
        let evidence = Arc::new(ExactRequestEvidence::default());
        let app = Router::new()
            .route(
                "/api/v1/repositories/{owner}/{repository}/runs/{source_run_id}/reruns",
                post(retry_then_create),
            )
            .with_state(Arc::clone(&evidence));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let origin = CliServerOrigin::new(&format!("http://{address}/")).expect("origin");
        let completed = execute_rerun_command_with(
            origin,
            &args(Some(OPERATION_ID), RerunSelection::JobAndDependents),
            &FixedCredentialStore,
            immediate_retry_policy(),
        )
        .await
        .expect("rerun receipt");
        server.abort();
        let join_error = server.await.expect_err("aborted test server");
        assert!(join_error.is_cancelled());

        assert!(evidence.authorized.load(Ordering::Relaxed));
        assert!(evidence.json_content_type.load(Ordering::Relaxed));
        assert_eq!(evidence.attempts.load(Ordering::Relaxed), 2);
        assert_eq!(completed.operation_id.to_string(), OPERATION_ID);
        assert_eq!(completed.run_id.to_string(), RERUN_RUN_ID);
        assert!(!completed.replay);
        assert_eq!(
            evidence.paths.lock().expect("paths").as_slice(),
            [
                (
                    REPOSITORY_OWNER.to_owned(),
                    REPOSITORY_NAME.to_owned(),
                    SOURCE_RUN_ID.to_owned()
                ),
                (
                    REPOSITORY_OWNER.to_owned(),
                    REPOSITORY_NAME.to_owned(),
                    SOURCE_RUN_ID.to_owned()
                ),
            ]
        );
        let bodies = evidence.bodies.lock().expect("bodies");
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(
            bodies[0],
            json!({
                "operation_id": OPERATION_ID,
                "selection": {
                    "mode": "job_and_dependents",
                    "logical_job_id": LOGICAL_JOB_ID
                }
            })
        );
    }

    #[derive(Debug, Default)]
    struct UnavailableEvidence {
        bodies: Mutex<Vec<Value>>,
    }

    async fn always_unavailable(
        State(evidence): State<Arc<UnavailableEvidence>>,
        body: AxumBytes,
    ) -> AxumResponse {
        evidence
            .bodies
            .lock()
            .expect("bodies")
            .push(serde_json::from_slice(&body).expect("request JSON"));
        AxumResponse::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(axum::body::Body::empty())
            .expect("unavailable response")
    }

    #[tokio::test]
    async fn generated_identity_is_stable_and_recoverable_after_ambiguous_failure() {
        let evidence = Arc::new(UnavailableEvidence::default());
        let app = Router::new()
            .route(
                "/api/v1/repositories/{owner}/{repository}/runs/{source_run_id}/reruns",
                post(always_unavailable),
            )
            .with_state(Arc::clone(&evidence));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let origin_text = format!("http://{address}/");
        let origin = CliServerOrigin::new(&origin_text).expect("origin");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let error = execute_rerun_command_with(
            origin,
            &args(None, RerunSelection::EntireWorkflow),
            &FixedCredentialStore,
            immediate_retry_policy(),
        )
        .await
        .expect_err("bounded attempts remain unavailable");
        server.abort();
        let join_error = server.await.expect_err("aborted test server");
        assert!(join_error.is_cancelled());

        let bodies = evidence.bodies.lock().expect("bodies");
        assert_eq!(bodies.len(), MAX_REQUEST_ATTEMPTS);
        assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
        let generated = bodies[0]["operation_id"]
            .as_str()
            .expect("generated operation ID");
        canonical_response_uuid(generated).expect("canonical generated operation ID");
        let message = error.to_string();
        assert!(message.contains(&format!("--operation-id {generated}")));
        assert!(!message.contains(SESSION));
        assert!(!message.contains(&origin_text));
        assert!(!message.contains("entire_workflow"));
    }

    #[test]
    fn response_contract_accepts_exact_replay_and_rejects_inconsistent_metadata() {
        let source_run_id = Uuid::parse_str(SOURCE_RUN_ID).expect("source run ID");
        let operation_id = Uuid::parse_str(OPERATION_ID).expect("operation ID");
        let completed = validate_response(
            &response_document(RERUN_RUN_ID, 41, 17, 2, true),
            StatusCode::OK,
            source_run_id,
            operation_id,
        )
        .expect("exact replay response");
        assert!(completed.replay);
        assert_eq!(completed.operation_id, operation_id);

        for (document, status) in [
            (
                response_document(RERUN_RUN_ID, 41, 17, 2, false),
                StatusCode::OK,
            ),
            (
                response_document(RERUN_RUN_ID, 41, 17, 2, true),
                StatusCode::CREATED,
            ),
            (
                response_document("50000000000040008000000000000005", 41, 17, 2, true),
                StatusCode::OK,
            ),
            (
                response_document("00000000-0000-0000-0000-000000000000", 41, 17, 2, true),
                StatusCode::OK,
            ),
            (
                response_document(SOURCE_RUN_ID, 41, 17, 2, true),
                StatusCode::OK,
            ),
            (
                response_document(RERUN_RUN_ID, 0, 17, 2, true),
                StatusCode::OK,
            ),
            (
                response_document(RERUN_RUN_ID, 41, 0, 2, true),
                StatusCode::OK,
            ),
            (
                response_document(RERUN_RUN_ID, 41, 17, 1, true),
                StatusCode::OK,
            ),
        ] {
            assert!(
                validate_response(&document, status, source_run_id, operation_id).is_err(),
                "inconsistent response must be rejected"
            );
        }
    }

    #[test]
    fn repository_coordinate_is_encoded_as_two_exact_path_segments() {
        let mut args = args(Some(OPERATION_ID), RerunSelection::EntireWorkflow);
        args.repository = "owner#team/repo?name"
            .parse::<RepositoryRef>()
            .expect("bounded repository coordinate");
        let origin = CliServerOrigin::new("https://ci.example.test/").expect("origin");

        let endpoint = rerun_endpoint(&origin, &args).expect("rerun endpoint");

        assert_eq!(
            endpoint.as_str(),
            concat!(
                "https://ci.example.test/api/v1/repositories/owner%23team/",
                "repo%3Fname/runs/20000000-0000-4000-8000-000000000002/reruns"
            )
        );
        assert!(endpoint.query().is_none());
        assert!(endpoint.fragment().is_none());
    }

    fn response_document(
        run_id: &str,
        public_run_id: u64,
        run_number: u64,
        run_attempt: u32,
        replay: bool,
    ) -> RerunResponseDocument {
        RerunResponseDocument {
            source_run_id: SOURCE_RUN_ID.to_owned(),
            run_id: run_id.to_owned(),
            public_run_id,
            run_number,
            run_attempt,
            replay,
        }
    }

    fn args(operation_id: Option<&str>, selection: RerunSelection) -> RerunArgs {
        RerunArgs {
            operator: OperatorArgs {
                server_url: "http://127.0.0.1:8080".to_owned(),
                output: OutputFormat::Json,
            },
            repository: format!("{REPOSITORY_OWNER}/{REPOSITORY_NAME}")
                .parse::<RepositoryRef>()
                .expect("repository"),
            source_run_id: Uuid::parse_str(SOURCE_RUN_ID).expect("source run ID"),
            selection,
            job_id: (selection == RerunSelection::JobAndDependents)
                .then(|| Uuid::parse_str(LOGICAL_JOB_ID).expect("logical job ID")),
            operation_id: operation_id.map(|value| Uuid::parse_str(value).expect("operation ID")),
        }
    }

    const fn immediate_retry_policy() -> RetryPolicy {
        RetryPolicy {
            attempts: MAX_REQUEST_ATTEMPTS,
            server_delay: Duration::ZERO,
            transport_delay: Duration::ZERO,
        }
    }
}
