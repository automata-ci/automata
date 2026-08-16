//! One-time runner enrollment over the human HTTPS listener.

use std::{fmt, sync::Arc, time::Duration};

use automata_ci_auth::{
    management::{
        ManagementActor, ManagementMutationOutcome, ManagementRepositoryError, ManagementRevision,
    },
    request_auth::AuthenticatedRequestSnapshot,
    secret::{RunnerEnrollmentToken, SecretString},
    session::SessionKind,
    time::Clock,
};
use automata_ci_auth_postgres::management::{
    ConsumeRunnerEnrollment, CreateRunnerEnrollmentToken, MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
    MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS, PostgresHumanRbacManagementRepository,
    PrepareRunnerEnrollment, PreparedRunnerEnrollment, RunnerEnrollmentConsumeOutcome,
    RunnerEnrollmentPrepareOutcome,
};
use automata_ci_control::runner_control::capability_admission::RunnerCapabilityReadiness;
use automata_ci_core::{RunnerCapabilities, RunnerFeature, RunnerGroup};
use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use futures::StreamExt as _;
use rcgen::{
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::{
    client::{WebPkiServerVerifier, danger::ServerCertVerifier as _},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject as _},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

pub(crate) const RUNNER_ENROLLMENTS_PATH: &str = "/api/v1/runner-enrollments";
pub(crate) const RUNNER_ENROLLMENT_REDEEM_PATH: &str = "/api/v1/runner-enrollments/redeem";

const REDEEM_REQUEST_DOMAIN: &[u8] = b"automata.runner-enrollment-request.v1\0";
const MAX_REQUEST_BYTES: usize = 384 * 1_024;
const INITIAL_REQUEST_CAPACITY_BYTES: usize = 8 * 1_024;
const MAX_CSR_BYTES: usize = 32 * 1_024;
const MAX_REDEEM_RESPONSE_BYTES: usize = 512 * 1_024;
const MIN_DYNAMIC_RESPONSE_HEADROOM_BYTES: usize = 64 * 1_024;
const MIN_TOKEN_LIFETIME_SECONDS: u64 = 60;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 60 * 60;
const MAX_CONCURRENT_REDEMPTIONS: usize = 32;

/// In-memory CA signer for runner client certificates.
pub(crate) struct RunnerCertificateIssuer {
    issuer: Issuer<'static, KeyPair>,
    client_ca_pem: String,
    server_ca_pem: String,
    server_certificate_chain: Vec<CertificateDer<'static>>,
    server_name: ServerName<'static>,
    server_verifier: Arc<WebPkiServerVerifier>,
    control_endpoint: String,
    issuer_not_before_seconds: i64,
    issuer_not_after_seconds: i64,
    server_roots_not_before_seconds: i64,
    server_roots_not_after_seconds: i64,
}

impl fmt::Debug for RunnerCertificateIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerCertificateIssuer")
            .field("control_endpoint", &self.control_endpoint)
            .finish_non_exhaustive()
    }
}

impl RunnerCertificateIssuer {
    pub(crate) fn from_pem(
        client_ca_pem: &[u8],
        client_ca_private_key_pem: &[u8],
        server_ca_pem: &[u8],
        server_certificate_pem: &[u8],
        control_endpoint: String,
    ) -> Result<Self, RunnerCertificateIssuerError> {
        let client_ca_pem = std::str::from_utf8(client_ca_pem)
            .map_err(|_| RunnerCertificateIssuerError)?
            .to_owned();
        let server_ca_pem = std::str::from_utf8(server_ca_pem)
            .map_err(|_| RunnerCertificateIssuerError)?
            .to_owned();
        let private_key_pem = std::str::from_utf8(client_ca_private_key_pem)
            .map_err(|_| RunnerCertificateIssuerError)?;
        let endpoint = Url::parse(&control_endpoint).map_err(|_| RunnerCertificateIssuerError)?;
        if endpoint.scheme() != "https"
            || endpoint.as_str() != control_endpoint
            || endpoint.cannot_be_a_base()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.host().is_none()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || client_ca_pem
                .len()
                .checked_add(server_ca_pem.len())
                .and_then(|size| size.checked_add(control_endpoint.len()))
                .is_none_or(|fixed| {
                    fixed
                        > MAX_REDEEM_RESPONSE_BYTES
                            .saturating_sub(MIN_DYNAMIC_RESPONSE_HEADROOM_BYTES)
                })
        {
            return Err(RunnerCertificateIssuerError);
        }
        let key = KeyPair::from_pem(private_key_pem).map_err(|_| RunnerCertificateIssuerError)?;
        let client_ca_der =
            rustls::pki_types::CertificateDer::pem_slice_iter(client_ca_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| RunnerCertificateIssuerError)?;
        let [client_ca_der] = client_ca_der.as_slice() else {
            return Err(RunnerCertificateIssuerError);
        };
        let (remainder, client_ca) = parse_x509_certificate(client_ca_der.as_ref())
            .map_err(|_| RunnerCertificateIssuerError)?;
        let basic_constraints = client_ca
            .basic_constraints()
            .map_err(|_| RunnerCertificateIssuerError)?
            .ok_or(RunnerCertificateIssuerError)?;
        let key_usage = client_ca
            .key_usage()
            .map_err(|_| RunnerCertificateIssuerError)?
            .ok_or(RunnerCertificateIssuerError)?;
        if !remainder.is_empty()
            || !basic_constraints.value.ca
            || !key_usage.value.key_cert_sign()
            || client_ca.validity().not_before >= client_ca.validity().not_after
            || client_ca.public_key().subject_public_key.data.as_ref() != key.public_key_raw()
        {
            return Err(RunnerCertificateIssuerError);
        }
        let issuer_not_before_seconds = client_ca.validity().not_before.timestamp();
        let issuer_not_after_seconds = client_ca.validity().not_after.timestamp();
        let (server_roots, server_roots_not_before_seconds, server_roots_not_after_seconds) =
            server_root_authority(&server_ca_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&client_ca_pem, key)
            .map_err(|_| RunnerCertificateIssuerError)?;
        let server_certificate_chain = CertificateDer::pem_slice_iter(server_certificate_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RunnerCertificateIssuerError)?;
        let server_name = ServerName::try_from(
            endpoint
                .host_str()
                .ok_or(RunnerCertificateIssuerError)?
                .to_owned(),
        )
        .map_err(|_| RunnerCertificateIssuerError)?;
        if server_certificate_chain.is_empty() {
            return Err(RunnerCertificateIssuerError);
        }
        let server_verifier = WebPkiServerVerifier::builder(Arc::new(server_roots))
            .build()
            .map_err(|_| RunnerCertificateIssuerError)?;
        Ok(Self {
            issuer,
            client_ca_pem,
            server_ca_pem,
            server_certificate_chain,
            server_name,
            server_verifier,
            control_endpoint,
            issuer_not_before_seconds,
            issuer_not_after_seconds,
            server_roots_not_before_seconds,
            server_roots_not_after_seconds,
        })
    }

    fn issue(
        &self,
        runner_id: Uuid,
        csr_pem: &str,
        database_time_ms: i64,
    ) -> Result<IssuedRunnerCertificate, RunnerCertificateIssuerError> {
        if runner_id.is_nil()
            || csr_pem.is_empty()
            || csr_pem.len() > MAX_CSR_BYTES
            || database_time_ms < 0
        {
            return Err(RunnerCertificateIssuerError);
        }
        let mut request = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|_| RunnerCertificateIssuerError)?;
        if request.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(RunnerCertificateIssuerError);
        }
        let issued_at_seconds = database_time_ms.div_euclid(1_000);
        if issued_at_seconds < self.issuer_not_before_seconds
            || issued_at_seconds >= self.issuer_not_after_seconds
            || issued_at_seconds < self.server_roots_not_before_seconds
            || issued_at_seconds >= self.server_roots_not_after_seconds
        {
            return Err(RunnerCertificateIssuerError);
        }
        let [server_leaf, server_intermediates @ ..] = self.server_certificate_chain.as_slice()
        else {
            return Err(RunnerCertificateIssuerError);
        };
        let issued_at =
            u64::try_from(issued_at_seconds).map_err(|_| RunnerCertificateIssuerError)?;
        self.server_verifier
            .verify_server_cert(
                server_leaf,
                server_intermediates,
                &self.server_name,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(issued_at)),
            )
            .map_err(|_| RunnerCertificateIssuerError)?;
        let not_before_seconds = issued_at_seconds
            .saturating_sub(60)
            .max(self.issuer_not_before_seconds);
        let not_before = OffsetDateTime::from_unix_timestamp(not_before_seconds)
            .map_err(|_| RunnerCertificateIssuerError)?;
        let requested_not_after = not_before
            .checked_add(time::Duration::seconds(
                MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
            ))
            .ok_or(RunnerCertificateIssuerError)?;
        let expires_at_seconds = requested_not_after
            .unix_timestamp()
            .min(self.issuer_not_after_seconds)
            .min(self.server_roots_not_after_seconds);
        if expires_at_seconds
            .checked_sub(issued_at_seconds)
            .is_none_or(|remaining| remaining < MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS)
        {
            return Err(RunnerCertificateIssuerError);
        }
        let not_after = OffsetDateTime::from_unix_timestamp(expires_at_seconds)
            .map_err(|_| RunnerCertificateIssuerError)?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, runner_id.hyphenated().to_string());
        request.params.not_before = not_before;
        request.params.not_after = not_after;
        request.params.distinguished_name = distinguished_name;
        request.params.subject_alt_names.clear();
        request.params.is_ca = IsCa::NoCa;
        request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        request.params.name_constraints = None;
        request.params.crl_distribution_points.clear();
        request.params.custom_extensions.clear();
        request.params.use_authority_key_identifier_extension = false;
        let certificate = request
            .signed_by(&self.issuer)
            .map_err(|_| RunnerCertificateIssuerError)?;
        let leaf_der = certificate.der();
        let leaf_sha256: [u8; 32] = Sha256::digest(leaf_der.as_ref()).into();
        let mut certificate_chain_pem = certificate.pem();
        if !certificate_chain_pem.ends_with('\n') {
            certificate_chain_pem.push('\n');
        }
        certificate_chain_pem.push_str(&self.client_ca_pem);
        Ok(IssuedRunnerCertificate {
            certificate_chain_pem,
            server_ca_pem: self.server_ca_pem.clone(),
            control_endpoint: self.control_endpoint.clone(),
            leaf_sha256,
            issued_at_seconds,
            expires_at_seconds,
        })
    }
}

fn server_root_authority(
    server_ca_pem: &str,
) -> Result<(rustls::RootCertStore, i64, i64), RunnerCertificateIssuerError> {
    let mut roots = rustls::RootCertStore::empty();
    let mut root_count = 0_usize;
    let mut not_before_seconds = i64::MIN;
    let mut not_after_seconds = i64::MAX;
    for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(server_ca_pem.as_bytes()) {
        let certificate = certificate.map_err(|_| RunnerCertificateIssuerError)?;
        let (remainder, root) = parse_x509_certificate(certificate.as_ref())
            .map_err(|_| RunnerCertificateIssuerError)?;
        if !remainder.is_empty()
            || root.validity().not_before >= root.validity().not_after
            || !root
                .basic_constraints()
                .map_err(|_| RunnerCertificateIssuerError)?
                .is_some_and(|constraints| constraints.value.ca)
        {
            return Err(RunnerCertificateIssuerError);
        }
        not_before_seconds = not_before_seconds.max(root.validity().not_before.timestamp());
        not_after_seconds = not_after_seconds.min(root.validity().not_after.timestamp());
        roots
            .add(certificate)
            .map_err(|_| RunnerCertificateIssuerError)?;
        root_count += 1;
    }
    if root_count == 0 || not_before_seconds >= not_after_seconds {
        return Err(RunnerCertificateIssuerError);
    }
    Ok((roots, not_before_seconds, not_after_seconds))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RunnerCertificateIssuerError;

#[derive(Clone)]
struct RunnerEnrollmentApiState {
    repository: Arc<PostgresHumanRbacManagementRepository>,
    issuer: Arc<RunnerCertificateIssuer>,
    clock: Arc<dyn Clock>,
    capability_readiness: RunnerCapabilityReadiness,
    redemptions: Arc<tokio::sync::Semaphore>,
}

pub(crate) fn runner_enrollment_api_router(
    repository: Arc<PostgresHumanRbacManagementRepository>,
    issuer: Arc<RunnerCertificateIssuer>,
    clock: Arc<dyn Clock>,
    capability_readiness: RunnerCapabilityReadiness,
) -> Router {
    Router::new()
        .route(RUNNER_ENROLLMENTS_PATH, post(create_enrollment))
        .route(RUNNER_ENROLLMENT_REDEEM_PATH, post(redeem_enrollment))
        .with_state(RunnerEnrollmentApiState {
            repository,
            issuer,
            clock,
            capability_readiness,
            redemptions: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REDEMPTIONS)),
        })
        .layer(axum::middleware::from_fn(super::api_security::no_store))
}

async fn create_enrollment(
    State(state): State<RunnerEnrollmentApiState>,
    request: Request,
) -> Response {
    let actor = match actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let document: CreateEnrollmentDocument = match json_document(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    if document.operation_id.is_nil() {
        return ApiError::InvalidRequest.into_response();
    }
    if !(MIN_TOKEN_LIFETIME_SECONDS..=MAX_TOKEN_LIFETIME_SECONDS)
        .contains(&document.expires_in_seconds)
    {
        return ApiError::InvalidRequest.into_response();
    }
    let Ok(runner_group) = RunnerGroup::new(&document.runner_group) else {
        return ApiError::InvalidRequest.into_response();
    };
    let Ok(token) = RunnerEnrollmentToken::from_secret(document.token) else {
        return ApiError::EnrollmentRejected.into_response();
    };
    let request = CreateRunnerEnrollmentToken {
        actor,
        enrollment_id: document.operation_id,
        token_sha256: token.digest(),
        runner_group: runner_group.as_str().to_owned(),
        lifetime_ms: i64::try_from(document.expires_in_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .unwrap_or(0),
    };
    match state
        .repository
        .create_runner_enrollment_token(request)
        .await
    {
        Ok(ManagementMutationOutcome::Applied(record)) => {
            let response = CreateEnrollmentResponse {
                enrollment_id: record.enrollment_id,
                runner_group: record.runner_group,
                expires_at_ms: record.expires_at_ms,
                redeem_url: RUNNER_ENROLLMENT_REDEEM_PATH,
            };
            json_response(StatusCode::CREATED, &response)
        }
        Ok(ManagementMutationOutcome::Forbidden) => ApiError::Forbidden.into_response(),
        Ok(ManagementMutationOutcome::SessionStale) => ApiError::SessionStale.into_response(),
        Ok(_) => ApiError::Conflict.into_response(),
        Err(error) => repository_error(error).into_response(),
    }
}

async fn redeem_enrollment(
    State(state): State<RunnerEnrollmentApiState>,
    request: Request,
) -> Response {
    let Ok(_permit) = state.redemptions.try_acquire() else {
        return ApiError::RateLimited.into_response();
    };
    let document: RedeemEnrollmentDocument = match json_document(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    if !valid_redeem_document(&document) {
        return ApiError::InvalidRequest.into_response();
    }
    let request_sha256 = match redeem_request_digest(&document) {
        Ok(digest) => digest,
        Err(error) => return error.into_response(),
    };
    let Ok(token) = RunnerEnrollmentToken::from_secret(document.token) else {
        return ApiError::EnrollmentRejected.into_response();
    };
    let outcome = match state
        .repository
        .prepare_runner_enrollment(PrepareRunnerEnrollment {
            token_sha256: token.digest(),
            operation_id: document.operation_id,
            request_sha256,
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => return repository_error(error).into_response(),
    };
    let prepared = match decide_enrollment_preparation(
        outcome,
        &document.capabilities,
        state.capability_readiness,
    ) {
        EnrollmentPreparation::Prepared(prepared) => prepared,
        EnrollmentPreparation::Replayed(response) => {
            return exact_json_response(StatusCode::CREATED, response);
        }
        EnrollmentPreparation::Rejected => return ApiError::EnrollmentRejected.into_response(),
        EnrollmentPreparation::NotReady => return ApiError::InvalidRequest.into_response(),
    };
    let runner_id = document.capabilities.runner_id().as_uuid();
    let Ok(expected_group) = RunnerGroup::new(&prepared.runner_group) else {
        return ApiError::Internal.into_response();
    };
    if document.capabilities.groups() != &std::collections::BTreeSet::from([expected_group]) {
        return ApiError::EnrollmentRejected.into_response();
    }
    let Ok(issued) = state
        .issuer
        .issue(runner_id, &document.csr_pem, prepared.database_time_ms)
    else {
        return ApiError::InvalidRequest.into_response();
    };
    let response = RedeemEnrollmentResponse {
        runner_id,
        runner_group: prepared.runner_group.clone(),
        control_endpoint: issued.control_endpoint,
        certificate_chain_pem: issued.certificate_chain_pem,
        server_ca_pem: issued.server_ca_pem,
        certificate_expires_at_seconds: issued.expires_at_seconds,
    };
    let Ok(response) = serde_json::to_vec(&response) else {
        return ApiError::Internal.into_response();
    };
    if response.is_empty() || response.len() > MAX_REDEEM_RESPONSE_BYTES {
        return ApiError::Internal.into_response();
    }
    let consume = ConsumeRunnerEnrollment {
        token_sha256: token.digest(),
        operation_id: document.operation_id,
        request_sha256,
        runner_id,
        runner_name: document.runner_name,
        capabilities: document.capabilities,
        certificate_leaf_sha256: issued.leaf_sha256,
        certificate_issued_at_seconds: issued.issued_at_seconds,
        certificate_expires_at_seconds: issued.expires_at_seconds,
        response,
    };
    match state.repository.consume_runner_enrollment(consume).await {
        Ok(
            RunnerEnrollmentConsumeOutcome::Applied(response)
            | RunnerEnrollmentConsumeOutcome::Replayed(response),
        ) => exact_json_response(StatusCode::CREATED, response),
        Ok(RunnerEnrollmentConsumeOutcome::Rejected) => {
            ApiError::EnrollmentRejected.into_response()
        }
        Ok(
            RunnerEnrollmentConsumeOutcome::AlreadyExists
            | RunnerEnrollmentConsumeOutcome::CapacityExhausted,
        ) => ApiError::Conflict.into_response(),
        Err(error) => repository_error(error).into_response(),
    }
}

fn valid_redeem_document(document: &RedeemEnrollmentDocument) -> bool {
    !document.operation_id.is_nil()
        && !document.runner_name.is_empty()
        && document.runner_name.len() <= 255
        && document.runner_name.trim() == document.runner_name
        && !document.runner_name.chars().any(char::is_control)
        && document.capabilities.validate().is_ok()
}

enum EnrollmentPreparation {
    Prepared(PreparedRunnerEnrollment),
    Replayed(Vec<u8>),
    Rejected,
    NotReady,
}

fn decide_enrollment_preparation(
    outcome: RunnerEnrollmentPrepareOutcome,
    capabilities: &RunnerCapabilities,
    readiness: RunnerCapabilityReadiness,
) -> EnrollmentPreparation {
    match outcome {
        RunnerEnrollmentPrepareOutcome::Replayed(response) => {
            EnrollmentPreparation::Replayed(response)
        }
        RunnerEnrollmentPrepareOutcome::Rejected => EnrollmentPreparation::Rejected,
        RunnerEnrollmentPrepareOutcome::Prepared(_)
            if capabilities
                .features()
                .contains(&RunnerFeature::OIDC_TOKENS)
                && !readiness.github_oidc() =>
        {
            EnrollmentPreparation::NotReady
        }
        RunnerEnrollmentPrepareOutcome::Prepared(prepared) => {
            EnrollmentPreparation::Prepared(prepared)
        }
    }
}

fn actor_from_request(
    state: &RunnerEnrollmentApiState,
    request: &Request,
) -> Result<ManagementActor, ApiError> {
    let snapshot = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .ok_or(ApiError::Unauthorized)?;
    let identity = snapshot.session().identity();
    if identity.kind() != SessionKind::Cli {
        return Err(ApiError::Unauthorized);
    }
    let revision = ManagementRevision::new(snapshot.session().authorization_revision())
        .map_err(|_| ApiError::Unauthorized)?;
    Ok(ManagementActor::new(
        identity.tenant_id().clone(),
        identity.principal_id().clone(),
        identity.session_id().clone(),
        revision,
        None,
        state.clock.now(),
    ))
}

async fn json_document<T: for<'de> Deserialize<'de>>(request: Request) -> Result<T, ApiError> {
    if request.uri().query().is_some()
        || request.headers().contains_key(header::CONTENT_ENCODING)
        || !is_json_content_type(request.headers())
    {
        return Err(ApiError::UnsupportedMediaType);
    }
    let mut stream = request.into_body().into_data_stream();
    let mut body = Zeroizing::new(Vec::with_capacity(
        MAX_REQUEST_BYTES.min(INITIAL_REQUEST_CAPACITY_BYTES),
    ));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::InvalidRequest)?;
        let within_limit = body
            .len()
            .checked_add(chunk.len())
            .is_some_and(|length| length <= MAX_REQUEST_BYTES);
        if within_limit {
            body.extend_from_slice(&chunk);
        }
        wipe_body_chunk(chunk);
        if !within_limit {
            return Err(ApiError::TooLarge);
        }
    }
    serde_json::from_slice(&body).map_err(|_| ApiError::InvalidRequest)
}

fn wipe_body_chunk(chunk: Bytes) {
    if let Ok(mut chunk) = chunk.try_into_mut() {
        chunk.as_mut().fill(0);
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none()
        && value.to_str().is_ok_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.eq_ignore_ascii_case("application/json; charset=utf-8")
        })
}

fn redeem_request_digest(document: &RedeemEnrollmentDocument) -> Result<[u8; 32], ApiError> {
    let receipt = RedeemRequestReceipt {
        operation_id: document.operation_id,
        runner_name: &document.runner_name,
        capabilities: &document.capabilities,
        csr_pem: &document.csr_pem,
    };
    let encoded = serde_json::to_vec(&receipt).map_err(|_| ApiError::InvalidRequest)?;
    let mut digest = Sha256::new();
    digest.update(REDEEM_REQUEST_DOMAIN);
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn json_response<T: Serialize>(status: StatusCode, document: &T) -> Response {
    let Ok(body) = serde_json::to_vec(document) else {
        return ApiError::Internal.into_response();
    };
    exact_json_response(status, body)
}

fn exact_json_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = Response::new(axum::body::Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEnrollmentDocument {
    operation_id: Uuid,
    token: SecretString,
    runner_group: String,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct CreateEnrollmentResponse<'a> {
    enrollment_id: Uuid,
    runner_group: String,
    expires_at_ms: i64,
    redeem_url: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemEnrollmentDocument {
    operation_id: Uuid,
    token: SecretString,
    runner_name: String,
    capabilities: RunnerCapabilities,
    csr_pem: String,
}

#[derive(Serialize)]
struct RedeemRequestReceipt<'a> {
    operation_id: Uuid,
    runner_name: &'a str,
    capabilities: &'a RunnerCapabilities,
    csr_pem: &'a str,
}

#[derive(Serialize)]
struct RedeemEnrollmentResponse {
    runner_id: Uuid,
    runner_group: String,
    control_endpoint: String,
    certificate_chain_pem: String,
    server_ca_pem: String,
    certificate_expires_at_seconds: i64,
}

struct IssuedRunnerCertificate {
    certificate_chain_pem: String,
    server_ca_pem: String,
    control_endpoint: String,
    leaf_sha256: [u8; 32],
    issued_at_seconds: i64,
    expires_at_seconds: i64,
}

fn repository_error(error: ManagementRepositoryError) -> ApiError {
    match error {
        ManagementRepositoryError::InvalidRequest => ApiError::InvalidRequest,
        ManagementRepositoryError::Unavailable => ApiError::Unavailable,
        ManagementRepositoryError::CorruptData => ApiError::Internal,
    }
}

#[derive(Clone, Copy, Debug)]
enum ApiError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    SessionStale,
    Conflict,
    EnrollmentRejected,
    UnsupportedMediaType,
    TooLarge,
    RateLimited,
    Unavailable,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::SessionStale => (StatusCode::CONFLICT, "session_stale"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::EnrollmentRejected => (StatusCode::UNAUTHORIZED, "enrollment_rejected"),
            Self::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let mut response =
            Response::new(axum::body::Body::from(format!("{{\"error\":\"{code}\"}}")));
        *response.status_mut() = status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        if matches!(self, Self::RateLimited) {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automata_ci_core::{Architecture, OperatingSystem, RunnerId, RunnerPlatform};
    use axum::body::Body;
    use rcgen::{BasicConstraints, CertificateParams};

    fn server_certificate_chain_pem(ca_pem: &str, ca_key_pem: &str, hostname: &str) -> String {
        let issuer_key = KeyPair::from_pem(ca_key_pem).expect("server issuer key");
        let issuer = Issuer::from_ca_cert_pem(ca_pem, issuer_key).expect("server issuer");
        let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("server key");
        let mut server_params =
            CertificateParams::new(vec![hostname.to_owned()]).expect("server params");
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = server_params
            .signed_by(&server_key, &issuer)
            .expect("server certificate")
            .pem();
        format!("{leaf}{ca_pem}")
    }

    #[tokio::test]
    async fn json_collector_accepts_fragmented_documents_and_rejects_oversize_bodies() {
        let fragments = futures::stream::iter([
            Ok::<_, std::convert::Infallible>(Bytes::from_static(b"{\"runner\":\"")),
            Ok(Bytes::from_static(b"fragmented\"}")),
        ]);
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(fragments))
            .expect("fragmented request");
        let document: serde_json::Value = json_document(request)
            .await
            .expect("valid fragmented document");
        assert_eq!(document, serde_json::json!({"runner": "fragmented"}));

        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(vec![b'x'; MAX_REQUEST_BYTES + 1]))
            .expect("oversize request");
        assert!(matches!(
            json_document::<serde_json::Value>(request).await,
            Err(ApiError::TooLarge)
        ));
    }

    #[test]
    fn token_create_response_never_echoes_the_client_generated_secret() {
        let response = CreateEnrollmentResponse {
            enrollment_id: Uuid::new_v4(),
            runner_group: "default".to_owned(),
            expires_at_ms: 1_800_000_000_000,
            redeem_url: RUNNER_ENROLLMENT_REDEEM_PATH,
        };
        let document = serde_json::to_value(response).expect("create response");
        assert!(
            !document
                .as_object()
                .expect("response object")
                .contains_key("token")
        );
    }

    #[test]
    fn redeem_receipt_binds_semantics_without_persisting_the_token() {
        let operation_id = Uuid::new_v4();
        let capabilities = RunnerCapabilities::new(
            RunnerId::new(),
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        );
        let mut document = RedeemEnrollmentDocument {
            operation_id,
            token: SecretString::new("first-secret").expect("bounded secret"),
            runner_name: "runner-one".to_owned(),
            capabilities,
            csr_pem: "csr".to_owned(),
        };
        let first = redeem_request_digest(&document).expect("request digest");
        document.token = SecretString::new("different-secret").expect("bounded secret");
        assert_eq!(
            redeem_request_digest(&document).expect("request digest"),
            first
        );
        document.operation_id = Uuid::new_v4();
        assert_ne!(
            redeem_request_digest(&document).expect("request digest"),
            first
        );
    }

    #[test]
    fn committed_replay_wins_when_mutation_readiness_is_false() {
        let capabilities = RunnerCapabilities::new(
            RunnerId::new(),
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_features([RunnerFeature::OIDC_TOKENS]);
        let response = br#"{"runner":"committed"}"#.to_vec();
        assert!(matches!(
            decide_enrollment_preparation(
                RunnerEnrollmentPrepareOutcome::Replayed(response.clone()),
                &capabilities,
                RunnerCapabilityReadiness::unavailable(),
            ),
            EnrollmentPreparation::Replayed(replayed) if replayed == response
        ));
    }

    #[test]
    fn issuer_requires_matching_ca_key_and_overrides_csr_profile() {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
        let ca_key_pem = ca_key.serialize_pem();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let ca_pem = ca.pem();
        let server_pem = server_certificate_chain_pem(&ca_pem, &ca_key_pem, "runner.example.test");
        let issuer = RunnerCertificateIssuer::from_pem(
            ca_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            ca_pem.as_bytes(),
            server_pem.as_bytes(),
            "https://runner.example.test/".to_owned(),
        )
        .expect("matching CA material");

        let runner_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("runner key");
        let mut requested = CertificateParams::default();
        requested.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        requested.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let csr = requested
            .serialize_request(&runner_key)
            .expect("CSR")
            .pem()
            .expect("CSR PEM");
        let runner_id = Uuid::new_v4();
        let certificate = issuer
            .issue(runner_id, &csr, 1_800_000_000_123)
            .expect("issued leaf");
        let leaf = rustls::pki_types::CertificateDer::pem_slice_iter(
            certificate.certificate_chain_pem.as_bytes(),
        )
        .next()
        .expect("leaf")
        .expect("valid leaf PEM");
        let (_, leaf) = parse_x509_certificate(leaf.as_ref()).expect("valid leaf DER");
        assert_eq!(certificate.issued_at_seconds, 1_800_000_000);
        assert_eq!(
            leaf.validity()
                .not_after
                .timestamp()
                .checked_sub(leaf.validity().not_before.timestamp()),
            Some(MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS)
        );
        assert_eq!(
            certificate.expires_at_seconds,
            certificate.issued_at_seconds - 60 + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS
        );
        assert!(
            leaf.basic_constraints()
                .expect("basic constraints")
                .is_none_or(|constraints| !constraints.value.ca)
        );
        let eku = leaf
            .extended_key_usage()
            .expect("EKU")
            .expect("EKU extension");
        assert!(eku.value.client_auth);
        assert!(!eku.value.server_auth);

        let wrong_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .expect("different CA key")
            .serialize_pem();
        assert!(
            RunnerCertificateIssuer::from_pem(
                ca_pem.as_bytes(),
                wrong_key.as_bytes(),
                ca_pem.as_bytes(),
                server_pem.as_bytes(),
                "https://runner.example.test/".to_owned(),
            )
            .is_err()
        );
    }

    #[test]
    fn issuer_caps_the_leaf_at_the_earliest_trust_expiry() {
        let issued_at_seconds = 1_800_000_000;
        let ca_expires_at_seconds = issued_at_seconds + 3_600;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
        let ca_key_pem = ca_key.serialize_pem();
        let mut ca_params = CertificateParams::default();
        ca_params.not_before =
            OffsetDateTime::from_unix_timestamp(issued_at_seconds - 60).expect("CA not-before");
        ca_params.not_after =
            OffsetDateTime::from_unix_timestamp(ca_expires_at_seconds).expect("CA not-after");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let ca_pem = ca.pem();
        let server_pem = server_certificate_chain_pem(&ca_pem, &ca_key_pem, "runner.example.test");
        let issuer = RunnerCertificateIssuer::from_pem(
            ca_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            ca_pem.as_bytes(),
            server_pem.as_bytes(),
            "https://runner.example.test/".to_owned(),
        )
        .expect("short-lived CA material");
        let runner_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("runner key");
        let csr = CertificateParams::default()
            .serialize_request(&runner_key)
            .expect("CSR")
            .pem()
            .expect("CSR PEM");
        let certificate = issuer
            .issue(Uuid::new_v4(), &csr, issued_at_seconds * 1_000)
            .expect("clamped leaf");
        assert_eq!(certificate.expires_at_seconds, ca_expires_at_seconds);
        assert!(
            certificate.expires_at_seconds - certificate.issued_at_seconds
                < MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the trust-boundary regression keeps all generated certificate relationships visible"
    )]
    fn issuer_rejects_insufficient_lifetime_and_unusable_server_identity() {
        let issued_at_seconds = 1_800_000_000;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
        let ca_key_pem = ca_key.serialize_pem();
        let mut ca_params = CertificateParams::default();
        ca_params.not_before =
            OffsetDateTime::from_unix_timestamp(issued_at_seconds - 60).expect("CA not-before");
        ca_params.not_after = OffsetDateTime::from_unix_timestamp(
            issued_at_seconds + MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS - 1,
        )
        .expect("CA not-after");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let ca_pem = ca.pem();
        let server_pem = server_certificate_chain_pem(&ca_pem, &ca_key_pem, "runner.example.test");
        let issuer = RunnerCertificateIssuer::from_pem(
            ca_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            ca_pem.as_bytes(),
            server_pem.as_bytes(),
            "https://runner.example.test/".to_owned(),
        )
        .expect("short-lived issuer material");
        let runner_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("runner key");
        let csr = CertificateParams::default()
            .serialize_request(&runner_key)
            .expect("CSR")
            .pem()
            .expect("CSR PEM");
        assert!(
            issuer
                .issue(Uuid::new_v4(), &csr, issued_at_seconds * 1_000)
                .is_err(),
            "one-use enrollment must not consume an almost-expired issuer"
        );

        let long_lived_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("long-lived CA key");
        let long_lived_key_pem = long_lived_key.serialize_pem();
        let mut long_lived_params = CertificateParams::default();
        long_lived_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        long_lived_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let long_lived_ca = long_lived_params
            .self_signed(&long_lived_key)
            .expect("long-lived CA");
        let long_lived_ca_pem = long_lived_ca.pem();
        let wrong_hostname = server_certificate_chain_pem(
            &long_lived_ca_pem,
            &long_lived_key_pem,
            "other.example.test",
        );
        let issuer = RunnerCertificateIssuer::from_pem(
            long_lived_ca_pem.as_bytes(),
            long_lived_key_pem.as_bytes(),
            long_lived_ca_pem.as_bytes(),
            wrong_hostname.as_bytes(),
            "https://runner.example.test/".to_owned(),
        )
        .expect("structurally valid server material");
        assert!(
            issuer
                .issue(Uuid::new_v4(), &csr, issued_at_seconds * 1_000)
                .is_err(),
            "published roots must authenticate the configured authority hostname"
        );

        let expired_root_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("expired root key");
        let expired_root_key_pem = expired_root_key.serialize_pem();
        let mut expired_root_params = CertificateParams::default();
        expired_root_params.not_before =
            OffsetDateTime::from_unix_timestamp(issued_at_seconds - 120)
                .expect("expired root not-before");
        expired_root_params.not_after =
            OffsetDateTime::from_unix_timestamp(issued_at_seconds).expect("expired root not-after");
        expired_root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        expired_root_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let expired_root = expired_root_params
            .self_signed(&expired_root_key)
            .expect("expired root");
        let expired_root_pem = expired_root.pem();
        let expired_server_pem = server_certificate_chain_pem(
            &expired_root_pem,
            &expired_root_key_pem,
            "runner.example.test",
        );
        let issuer = RunnerCertificateIssuer::from_pem(
            long_lived_ca_pem.as_bytes(),
            long_lived_key_pem.as_bytes(),
            expired_root_pem.as_bytes(),
            expired_server_pem.as_bytes(),
            "https://runner.example.test/".to_owned(),
        )
        .expect("structurally valid expired server trust material");
        assert!(
            issuer
                .issue(Uuid::new_v4(), &csr, issued_at_seconds * 1_000)
                .is_err(),
            "published server trust roots must be current at issuance"
        );

        let future_root_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("future root key");
        let future_root_key_pem = future_root_key.serialize_pem();
        let mut future_root_params = CertificateParams::default();
        future_root_params.not_before = OffsetDateTime::from_unix_timestamp(issued_at_seconds + 60)
            .expect("future root not-before");
        future_root_params.not_after =
            OffsetDateTime::from_unix_timestamp(issued_at_seconds + 3_600)
                .expect("future root not-after");
        future_root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        future_root_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let future_root = future_root_params
            .self_signed(&future_root_key)
            .expect("future root");
        let future_root_pem = future_root.pem();
        let future_server_pem = server_certificate_chain_pem(
            &future_root_pem,
            &future_root_key_pem,
            "runner.example.test",
        );
        let issuer = RunnerCertificateIssuer::from_pem(
            long_lived_ca_pem.as_bytes(),
            long_lived_key_pem.as_bytes(),
            future_root_pem.as_bytes(),
            future_server_pem.as_bytes(),
            "https://runner.example.test/".to_owned(),
        )
        .expect("structurally valid future server trust material");
        assert!(
            issuer
                .issue(Uuid::new_v4(), &csr, issued_at_seconds * 1_000)
                .is_err(),
            "published server trust roots must already be valid at issuance"
        );
    }

    #[test]
    fn issuer_accepts_near_limit_fixed_material_and_rejects_the_next_root() {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
        let ca_key_pem = ca_key.serialize_pem();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let ca_pem = ca.pem();
        let server_pem = server_certificate_chain_pem(&ca_pem, &ca_key_pem, "runner.example.test");
        let endpoint = "https://runner.example.test/";
        let fixed_material_limit = MAX_REDEEM_RESPONSE_BYTES - MIN_DYNAMIC_RESPONSE_HEADROOM_BYTES;
        let root_copies = (fixed_material_limit - ca_pem.len() - endpoint.len()) / ca_pem.len();
        assert!(root_copies > 0);
        let near_limit_roots = ca_pem.repeat(root_copies);
        RunnerCertificateIssuer::from_pem(
            ca_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            near_limit_roots.as_bytes(),
            server_pem.as_bytes(),
            endpoint.to_owned(),
        )
        .expect("fixed response material within the limit");

        let over_limit_roots = ca_pem.repeat(root_copies + 1);
        assert!(
            RunnerCertificateIssuer::from_pem(
                ca_pem.as_bytes(),
                ca_key_pem.as_bytes(),
                over_limit_roots.as_bytes(),
                server_pem.as_bytes(),
                endpoint.to_owned(),
            )
            .is_err()
        );
    }
}
