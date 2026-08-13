//! One-time runner enrollment over the human HTTPS listener.

use std::{fmt, sync::Arc};

use automata_ci_auth::{
    management::{ManagementActor, ManagementMutationOutcome, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
    time::Clock,
};
use automata_ci_auth_postgres::management::{
    ConsumeRunnerEnrollment, CreateRunnerEnrollmentToken, PostgresHumanRbacManagementRepository,
    RunnerEnrollmentConsumeOutcome, RunnerEnrollmentPrepareOutcome,
};
use automata_ci_core::{RunnerCapabilities, RunnerGroup};
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::{
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::pem::PemObject as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

pub(crate) const RUNNER_ENROLLMENTS_PATH: &str = "/api/v1/runner-enrollments";
pub(crate) const RUNNER_ENROLLMENT_REDEEM_PATH: &str = "/api/v1/runner-enrollments/redeem";

const TOKEN_PREFIX: &str = "atm_re_";
const TOKEN_BYTES: usize = 32;
const TOKEN_DOMAIN: &[u8] = b"automata.runner-enrollment-token.v1\0";
const MAX_REQUEST_BYTES: usize = 384 * 1_024;
const MAX_CSR_BYTES: usize = 32 * 1_024;
const MIN_TOKEN_LIFETIME_SECONDS: u64 = 60;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 60 * 60;
const CERTIFICATE_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

/// In-memory CA signer for runner client certificates.
pub(crate) struct RunnerCertificateIssuer {
    issuer: Issuer<'static, KeyPair>,
    client_ca_pem: String,
    server_ca_pem: String,
    control_endpoint: String,
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
            || client_ca.public_key().subject_public_key.data.as_ref() != key.public_key_raw()
        {
            return Err(RunnerCertificateIssuerError);
        }
        let mut server_roots = rustls::RootCertStore::empty();
        let mut server_root_count = 0_usize;
        for certificate in
            rustls::pki_types::CertificateDer::pem_slice_iter(server_ca_pem.as_bytes())
        {
            let certificate = certificate.map_err(|_| RunnerCertificateIssuerError)?;
            server_roots
                .add(certificate)
                .map_err(|_| RunnerCertificateIssuerError)?;
            server_root_count += 1;
        }
        let issuer = Issuer::from_ca_cert_pem(&client_ca_pem, key)
            .map_err(|_| RunnerCertificateIssuerError)?;
        if !control_endpoint.starts_with("https://")
            || !control_endpoint.ends_with('/')
            || server_root_count == 0
        {
            return Err(RunnerCertificateIssuerError);
        }
        Ok(Self {
            issuer,
            client_ca_pem,
            server_ca_pem,
            control_endpoint,
        })
    }

    fn issue(
        &self,
        runner_id: Uuid,
        csr_pem: &str,
    ) -> Result<IssuedRunnerCertificate, RunnerCertificateIssuerError> {
        if runner_id.is_nil() || csr_pem.is_empty() || csr_pem.len() > MAX_CSR_BYTES {
            return Err(RunnerCertificateIssuerError);
        }
        let mut request = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|_| RunnerCertificateIssuerError)?;
        if request.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(RunnerCertificateIssuerError);
        }
        let now = OffsetDateTime::now_utc();
        let not_after = now
            .checked_add(time::Duration::seconds(CERTIFICATE_LIFETIME_SECONDS))
            .ok_or(RunnerCertificateIssuerError)?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, runner_id.hyphenated().to_string());
        request.params.not_before = now - time::Duration::minutes(1);
        request.params.not_after = not_after;
        request.params.distinguished_name = distinguished_name;
        request.params.subject_alt_names.clear();
        request.params.is_ca = IsCa::NoCa;
        request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        request.params.name_constraints = None;
        request.params.custom_extensions.clear();
        let certificate = request
            .signed_by(&self.issuer)
            .map_err(|_| RunnerCertificateIssuerError)?;
        let leaf_der = certificate.der();
        let leaf_sha256: [u8; 32] = Sha256::digest(leaf_der.as_ref()).into();
        let expires_at_seconds = not_after.unix_timestamp();
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
            expires_at_seconds,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RunnerCertificateIssuerError;

#[derive(Clone)]
struct RunnerEnrollmentApiState {
    repository: Arc<PostgresHumanRbacManagementRepository>,
    issuer: Arc<RunnerCertificateIssuer>,
    clock: Arc<dyn Clock>,
}

pub(crate) fn runner_enrollment_api_router(
    repository: Arc<PostgresHumanRbacManagementRepository>,
    issuer: Arc<RunnerCertificateIssuer>,
    clock: Arc<dyn Clock>,
) -> Router {
    Router::new()
        .route(RUNNER_ENROLLMENTS_PATH, post(create_enrollment))
        .route(RUNNER_ENROLLMENT_REDEEM_PATH, post(redeem_enrollment))
        .with_state(RunnerEnrollmentApiState {
            repository,
            issuer,
            clock,
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
    if !(MIN_TOKEN_LIFETIME_SECONDS..=MAX_TOKEN_LIFETIME_SECONDS)
        .contains(&document.expires_in_seconds)
    {
        return ApiError::InvalidRequest.into_response();
    }
    let Ok(runner_group) = RunnerGroup::new(&document.runner_group) else {
        return ApiError::InvalidRequest.into_response();
    };
    let token_sha256 = match token_digest(document.token.as_bytes()) {
        Ok(digest) => digest,
        Err(error) => return error.into_response(),
    };
    let request = CreateRunnerEnrollmentToken {
        actor,
        enrollment_id: document.operation_id,
        token_sha256,
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
                token: document.token,
                runner_group: record.runner_group,
                expires_at_ms: record.expires_at_ms,
                redeem_url: RUNNER_ENROLLMENT_REDEEM_PATH,
            };
            json_response(StatusCode::CREATED, &response)
        }
        Ok(ManagementMutationOutcome::Forbidden) => ApiError::Forbidden.into_response(),
        Ok(ManagementMutationOutcome::SessionStale) => ApiError::SessionStale.into_response(),
        Ok(_) => ApiError::Conflict.into_response(),
        Err(_) => ApiError::Unavailable.into_response(),
    }
}

async fn redeem_enrollment(
    State(state): State<RunnerEnrollmentApiState>,
    request: Request,
) -> Response {
    let document: RedeemEnrollmentDocument = match json_document(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    if document.runner_name.is_empty()
        || document.runner_name.len() > 255
        || document.runner_name.trim() != document.runner_name
        || document.runner_name.chars().any(char::is_control)
        || document.capabilities.validate().is_err()
    {
        return ApiError::InvalidRequest.into_response();
    }
    let token_sha256 = match token_digest(document.token.as_bytes()) {
        Ok(digest) => digest,
        Err(error) => return error.into_response(),
    };
    let prepared = match state
        .repository
        .prepare_runner_enrollment(token_sha256)
        .await
    {
        Ok(RunnerEnrollmentPrepareOutcome::Prepared(prepared)) => prepared,
        Ok(RunnerEnrollmentPrepareOutcome::Rejected) => {
            return ApiError::EnrollmentRejected.into_response();
        }
        Err(_) => return ApiError::Unavailable.into_response(),
    };
    let runner_id = document.capabilities.runner_id().as_uuid();
    if !document
        .capabilities
        .groups()
        .iter()
        .any(|group| group.as_str() == prepared.runner_group)
    {
        return ApiError::EnrollmentRejected.into_response();
    }
    let Ok(issued) = state.issuer.issue(runner_id, &document.csr_pem) else {
        return ApiError::InvalidRequest.into_response();
    };
    let Ok(capabilities) = serde_json::to_value(&document.capabilities) else {
        return ApiError::InvalidRequest.into_response();
    };
    let labels = document
        .capabilities
        .labels()
        .iter()
        .map(|label| label.as_str().to_owned())
        .collect();
    let consume = ConsumeRunnerEnrollment {
        token_sha256,
        runner_id,
        runner_name: document.runner_name,
        capabilities,
        labels,
        slots: document.capabilities.max_parallel_jobs(),
        certificate_leaf_sha256: issued.leaf_sha256,
        certificate_expires_at_seconds: issued.expires_at_seconds,
    };
    match state.repository.consume_runner_enrollment(consume).await {
        Ok(RunnerEnrollmentConsumeOutcome::Applied(scope)) => json_response(
            StatusCode::CREATED,
            &RedeemEnrollmentResponse {
                runner_id,
                runner_group: scope.runner_group,
                control_endpoint: issued.control_endpoint,
                certificate_chain_pem: issued.certificate_chain_pem,
                server_ca_pem: issued.server_ca_pem,
                certificate_expires_at_seconds: issued.expires_at_seconds,
            },
        ),
        Ok(RunnerEnrollmentConsumeOutcome::Rejected) => {
            ApiError::EnrollmentRejected.into_response()
        }
        Ok(
            RunnerEnrollmentConsumeOutcome::AlreadyExists
            | RunnerEnrollmentConsumeOutcome::CapacityExhausted,
        ) => ApiError::Conflict.into_response(),
        Err(_) => ApiError::Unavailable.into_response(),
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
    let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::TooLarge)?;
    serde_json::from_slice(&body).map_err(|_| ApiError::InvalidRequest)
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

fn token_digest(token: &[u8]) -> Result<[u8; 32], ApiError> {
    let encoded = token
        .strip_prefix(TOKEN_PREFIX.as_bytes())
        .ok_or(ApiError::EnrollmentRejected)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::EnrollmentRejected)?;
    if decoded.len() != TOKEN_BYTES {
        return Err(ApiError::EnrollmentRejected);
    }
    let mut digest = Sha256::new();
    digest.update(TOKEN_DOMAIN);
    digest.update(token);
    Ok(digest.finalize().into())
}

fn json_response<T: Serialize>(status: StatusCode, document: &T) -> Response {
    let Ok(body) = serde_json::to_vec(document) else {
        return ApiError::Internal.into_response();
    };
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
    #[serde(deserialize_with = "deserialize_zeroizing")]
    token: Zeroizing<String>,
    runner_group: String,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct CreateEnrollmentResponse<'a> {
    enrollment_id: Uuid,
    #[serde(serialize_with = "serialize_zeroizing")]
    token: Zeroizing<String>,
    runner_group: String,
    expires_at_ms: i64,
    redeem_url: &'a str,
}

fn serialize_zeroizing<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemEnrollmentDocument {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    token: Zeroizing<String>,
    runner_name: String,
    capabilities: RunnerCapabilities,
    csr_pem: String,
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
    expires_at_seconds: i64,
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
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams};

    #[test]
    fn token_hash_is_domain_separated_and_exact() {
        let token = format!(
            "{TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode([7_u8; TOKEN_BYTES])
        );
        let digest = token_digest(token.as_bytes()).expect("valid enrollment token");
        assert_ne!(digest, Sha256::digest(token.as_bytes()).as_slice());
        assert!(token_digest(b"plain-secret").is_err());
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
        let issuer = RunnerCertificateIssuer::from_pem(
            ca_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            ca_pem.as_bytes(),
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
        let issued = issuer.issue(runner_id, &csr).expect("issued leaf");
        let leaf = rustls::pki_types::CertificateDer::pem_slice_iter(
            issued.certificate_chain_pem.as_bytes(),
        )
        .next()
        .expect("leaf")
        .expect("valid leaf PEM");
        let (_, leaf) = parse_x509_certificate(leaf.as_ref()).expect("valid leaf DER");
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
                "https://runner.example.test/".to_owned(),
            )
            .is_err()
        );
    }
}
