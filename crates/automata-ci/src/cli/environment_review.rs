//! Authenticated CLI client for one protected-environment review decision.

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::session_credential::SessionCredential;
use bytes::Bytes;
use reqwest::{Client, Response, StatusCode, Url, header};
use serde::{Deserialize, Serialize};

use super::{
    EnvironmentReviewArgs, EnvironmentReviewDecision, OutputFormat,
    auth::{
        CliServerOrigin, auth_client, bearer_header, decode_json_response, discard_bounded_response,
    },
    credential_store::{CliAuthProcessLock, CliCredentialStore, SecretServiceCredentialStore},
};

const ENVIRONMENT_REVIEW_BASE: &str = "/api/v1/repositories";

pub(crate) async fn execute_environment_review_command(
    server_url: &str,
    output: OutputFormat,
    args: &EnvironmentReviewArgs,
) -> Result<()> {
    validate_arguments(args)?;
    let origin = CliServerOrigin::new(server_url)
        .context("environment-review endpoint policy rejected the server URL")?;
    let _process_lock = CliAuthProcessLock::acquire(origin.as_str())
        .context("CLI environment-review operation could not be serialized")?;
    let store =
        SecretServiceCredentialStore::discover().context("CLI session custody is unavailable")?;
    let completed = execute_environment_review_command_with(origin, args, &store).await?;
    print_environment_review(output, &completed)
}

async fn execute_environment_review_command_with(
    origin: CliServerOrigin,
    args: &EnvironmentReviewArgs,
    store: &dyn CliCredentialStore,
) -> Result<CompletedEnvironmentReview> {
    validate_arguments(args)?;
    let client = auth_client().context("failed to configure the environment-review client")?;
    let credential = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
        .ok_or_else(|| anyhow::anyhow!("no CLI session exists; run `automata auth login`"))?;
    submit_environment_review(&client, &origin, &credential, args).await
}

fn validate_arguments(args: &EnvironmentReviewArgs) -> Result<()> {
    if args.repository_id.is_nil() || args.attempt_id.is_nil() {
        bail!("environment review requires non-nil canonical repository and attempt UUIDs");
    }
    Ok(())
}

async fn submit_environment_review(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    args: &EnvironmentReviewArgs,
) -> Result<CompletedEnvironmentReview> {
    let endpoint = environment_review_endpoint(origin, args)?;
    let body = serde_json::to_vec(&ReviewRequestDocument {
        decision: args.decision,
    })
    .context("environment-review request could not be encoded")?;
    let request = client
        .post(endpoint)
        .header(header::AUTHORIZATION, bearer_header(credential)?)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body))
        .build()
        .map_err(reqwest::Error::without_url)
        .context("environment-review request could not be constructed")?;
    let response = client
        .execute(request)
        .await
        .map_err(reqwest::Error::without_url)
        .context(indeterminate_review_message())?;
    let status = response.status();
    if status != StatusCode::OK {
        return response_error(response, status).await;
    }
    let document: ReviewResponseDocument = decode_json_response(response)
        .await
        .context(indeterminate_review_message())?;
    Ok(CompletedEnvironmentReview {
        repository_id: args.repository_id,
        attempt_id: args.attempt_id,
        decision: args.decision,
        state: document.state,
    })
}

fn environment_review_endpoint(
    origin: &CliServerOrigin,
    args: &EnvironmentReviewArgs,
) -> Result<Url> {
    let mut endpoint = origin.endpoint(ENVIRONMENT_REVIEW_BASE);
    let repository_id = args.repository_id.hyphenated().to_string();
    let attempt_id = args.attempt_id.hyphenated().to_string();
    endpoint
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("environment-review endpoint could not be constructed"))?
        .extend([
            repository_id.as_str(),
            "attempts",
            attempt_id.as_str(),
            "environment",
            "reviews",
        ]);
    Ok(endpoint)
}

async fn response_error<T>(response: Response, status: StatusCode) -> Result<T> {
    if status.is_server_error() {
        discard_bounded_response(response)
            .await
            .context(indeterminate_review_message())?;
        bail!(indeterminate_review_message());
    }
    discard_bounded_response(response).await?;
    match status {
        StatusCode::UNAUTHORIZED => bail!("CLI session is no longer authorized"),
        StatusCode::FORBIDDEN => {
            bail!("environment review requires environments:approve authority")
        }
        StatusCode::NOT_FOUND => bail!("protected-environment review target is unavailable"),
        StatusCode::BAD_REQUEST
        | StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            bail!("control plane rejected the environment-review request")
        }
        StatusCode::CONFLICT => bail!("protected-environment review conflicts with current state"),
        _ => bail!("environment-review request returned HTTP {status}"),
    }
}

const fn indeterminate_review_message() -> &'static str {
    "environment-review outcome is indeterminate; retry only the exact same repository, attempt, and decision"
}

fn print_environment_review(
    output: OutputFormat,
    completed: &CompletedEnvironmentReview,
) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("repository_id\t{}", completed.repository_id.hyphenated());
            println!("attempt_id\t{}", completed.attempt_id.hyphenated());
            println!("decision\t{}", completed.decision.as_str());
            println!("state\t{}", completed.state.as_str());
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(completed)?);
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ReviewRequestDocument {
    decision: EnvironmentReviewDecision,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewResponseDocument {
    state: EnvironmentGateState,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum EnvironmentGateState {
    Waiting,
    Resolving,
    Ready,
    Rejected,
    Expired,
    Cancelled,
}

impl EnvironmentGateState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Resolving => "resolving",
            Self::Ready => "ready",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Serialize)]
struct CompletedEnvironmentReview {
    repository_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    decision: EnvironmentReviewDecision,
    state: EnvironmentGateState,
}

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
    use crate::cli::{OperatorArgs, credential_store::CredentialStoreError};

    const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const REPOSITORY_ID: &str = "aaaaaaaa-1111-4111-8111-111111111111";
    const ATTEMPT_ID: &str = "22222222-2222-4222-8222-222222222222";

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
        path: Mutex<Option<(String, String)>>,
        body: Mutex<Option<Value>>,
    }

    async fn record_review(
        State(evidence): State<Arc<ExactRequestEvidence>>,
        Path((repository_id, attempt_id)): Path<(String, String)>,
        headers: HeaderMap,
        body: AxumBytes,
    ) -> AxumResponse {
        evidence.attempts.fetch_add(1, Ordering::Relaxed);
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
        *evidence.path.lock().expect("path") = Some((repository_id, attempt_id));
        *evidence.body.lock().expect("body") =
            Some(serde_json::from_slice(&body).expect("request JSON"));
        AxumResponse::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(r#"{"state":"ready"}"#))
            .expect("review response")
    }

    async fn unavailable_review(State(attempts): State<Arc<AtomicUsize>>) -> AxumResponse {
        attempts.fetch_add(1, Ordering::Relaxed);
        AxumResponse::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(axum::body::Body::from(format!(
                "must stay redacted: {SESSION}"
            )))
            .expect("unavailable response")
    }

    #[tokio::test]
    async fn credentialed_review_preserves_exact_target_decision_and_authentication() {
        let evidence = Arc::new(ExactRequestEvidence::default());
        let app = Router::new()
            .route(
                "/api/v1/repositories/{repository_id}/attempts/{attempt_id}/environment/reviews",
                post(record_review),
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

        let completed = execute_environment_review_command_with(
            origin,
            &args(EnvironmentReviewDecision::Approve),
            &FixedCredentialStore,
        )
        .await
        .expect("environment review");
        server.abort();
        let join_error = server.await.expect_err("aborted test server");
        assert!(join_error.is_cancelled());

        assert!(evidence.authorized.load(Ordering::Relaxed));
        assert!(evidence.json_content_type.load(Ordering::Relaxed));
        assert_eq!(evidence.attempts.load(Ordering::Relaxed), 1);
        assert_eq!(
            evidence.path.lock().expect("path").as_ref(),
            Some(&(REPOSITORY_ID.to_owned(), ATTEMPT_ID.to_owned()))
        );
        assert_eq!(
            evidence.body.lock().expect("body").as_ref(),
            Some(&json!({"decision": "approve"}))
        );
        assert_eq!(completed.repository_id.to_string(), REPOSITORY_ID);
        assert_eq!(completed.attempt_id.to_string(), ATTEMPT_ID);
        assert!(matches!(
            completed.decision,
            EnvironmentReviewDecision::Approve
        ));
        assert!(matches!(completed.state, EnvironmentGateState::Ready));
    }

    #[tokio::test]
    async fn mutation_is_not_retried_and_indeterminate_error_is_redacted() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/api/v1/repositories/{repository_id}/attempts/{attempt_id}/environment/reviews",
                post(unavailable_review),
            )
            .with_state(Arc::clone(&attempts));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let origin_text = format!("http://{address}/");
        let origin = CliServerOrigin::new(&origin_text).expect("origin");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });

        let error = execute_environment_review_command_with(
            origin,
            &args(EnvironmentReviewDecision::Reject),
            &FixedCredentialStore,
        )
        .await
        .expect_err("unavailable review remains indeterminate");
        server.abort();
        let join_error = server.await.expect_err("aborted test server");
        assert!(join_error.is_cancelled());

        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        let message = error.to_string();
        assert!(message.contains("outcome is indeterminate"));
        assert!(!message.contains(SESSION));
        assert!(!message.contains(&origin_text));
        assert!(!message.contains("reject"));
    }

    #[test]
    fn response_contract_accepts_only_one_closed_gate_state() {
        for state in [
            "waiting",
            "resolving",
            "ready",
            "rejected",
            "expired",
            "cancelled",
        ] {
            let body = format!(r#"{{"state":"{state}"}}"#);
            assert!(serde_json::from_str::<ReviewResponseDocument>(&body).is_ok());
        }
        for body in [
            r#"{"state":"unknown"}"#,
            r#"{"state":"ready","extra":true}"#,
            r#"{"state":"ready","state":"ready"}"#,
            r"{}",
        ] {
            assert!(serde_json::from_str::<ReviewResponseDocument>(body).is_err());
        }
    }

    fn args(decision: EnvironmentReviewDecision) -> EnvironmentReviewArgs {
        EnvironmentReviewArgs {
            operator: OperatorArgs {
                server_url: "http://127.0.0.1:8080".to_owned(),
                output: OutputFormat::Json,
            },
            repository_id: uuid::Uuid::parse_str(REPOSITORY_ID).expect("repository ID"),
            attempt_id: uuid::Uuid::parse_str(ATTEMPT_ID).expect("attempt ID"),
            decision,
        }
    }
}
