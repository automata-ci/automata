use std::fmt;

use automata_ci_auth::management::{
    ManagementActor, ManagementMutationOutcome, ManagementRepositoryError,
};
use automata_ci_auth::{installation::InstallationRepositoryError, machine::AuthenticatedMachine};
use automata_ci_core::{
    IsolationLevel, MAX_REGISTERED_RUNNERS, OperatingSystem, RunnerCapabilities, RunnerFeature,
    RunnerGroup, SandboxFeature, Sha256Digest,
};
use automata_ci_protocol::VerifiedWindowsRunnerAdmission;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::installation::{
    ConfiguredDeploymentInstallationProof, revalidate_configured_deployment_installation,
};

use super::{
    AuditDescriptor, AuthorizedActor, MutationAuthorization, authorize_mutation,
    closed_authorization, commit, database_time_milliseconds, finish_applied, map_database_error,
};

const ACTION_TOKEN_CREATE: &str = "runner.enrollment_token.create";
const ACTION_TOKEN_BOOTSTRAP: &str = "runner.enrollment_token.installation_bootstrap";
const ACTION_ENROLL: &str = "runner.enroll";
const ACTION_CERTIFICATE_RENEW: &str = "runner.certificate.renew";
const RESOURCE_ENROLLMENT: &str = "runner_enrollment";
const ISSUER_HUMAN: &str = "human";
const ISSUER_INSTALLATION_BOOTSTRAP: &str = "installation_bootstrap";
const RESOURCE_RUNNER_CERTIFICATE: &str = "runner_certificate";
const MIN_TOKEN_LIFETIME_MS: i64 = 60 * 1_000;
const MAX_TOKEN_LIFETIME_MS: i64 = 60 * 60 * 1_000;
const RUNNER_ENROLLMENT_CAPACITY_LOCK: i64 = 0x4155_544f_4d41_5441;
const RUNNER_ENROLLMENT_CREATE_LOCK_SALT: i64 = 0x454e_524f_4c4c_4d54;
const RUNNER_CERTIFICATE_RENEWAL_OPERATION_LOCK_SALT: i64 = 0x4345_5254_5245_4e57;
const MAX_NAME_BYTES: usize = 255;
const MAX_GROUP_CHARACTERS: usize = 256;
const MAX_REDEEM_RESPONSE_BYTES: usize = 512 * 1_024;
const MAX_WINDOWS_ADMISSION_PAYLOAD_BYTES: usize = 64 * 1_024;
const MAX_WINDOWS_ADMISSION_ID_BYTES: usize = 128;
const MAX_WINDOWS_ADMISSION_ORIGIN_BYTES: usize = 2_048;
const MAX_WINDOWS_IMAGE_REFERENCE_BYTES: usize = 2_048;
const WINDOWS_ADMISSION_SCHEMA_VERSION: u16 = 1;
const WINDOWS_ADMISSION_SANDBOX_PROVIDER_ID: &str = "windows-hyperv";

/// A runner may request renewal only inside this fixed interval before its
/// currently presented certificate expires.
const RUNNER_CERTIFICATE_RENEWAL_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

const MAX_RUNNER_CERTIFICATE_RENEWAL_RESPONSE_BYTES: usize = 512 * 1_024;

/// `PostgreSQL` adapter for runner enrollment and certificate renewal.
///
/// Human token creation reauthorizes its session and RBAC grant inside the
/// transaction. Redemption is authorized solely by possession of the opaque
/// one-time token.
#[derive(Clone)]
pub struct PostgresRunnerEnrollmentRepository {
    pool: PgPool,
}

impl PostgresRunnerEnrollmentRepository {
    /// Binds runner enrollment to one `PostgreSQL` pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresRunnerEnrollmentRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresRunnerEnrollmentRepository")
            .finish_non_exhaustive()
    }
}

/// Fixed one-hour lifetime of an installation-bootstrap enrollment token.
pub const INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS: i64 = MAX_TOKEN_LIFETIME_MS;

/// Exact digest-only request for replica-safe installation runner bootstrap.
#[derive(Clone)]
pub struct EnsureInstallationBootstrapRunnerEnrollmentToken {
    installation: ConfiguredDeploymentInstallationProof,
    enrollment_id: Uuid,
    token_sha256: [u8; 32],
    runner_group: RunnerGroup,
    lifetime_ms: i64,
}

impl EnsureInstallationBootstrapRunnerEnrollmentToken {
    /// Constructs one exact, idempotent installation-bootstrap issuance request.
    ///
    /// Plaintext token material never crosses this repository boundary. The
    /// request accepts only the fixed one-hour deployment-bootstrap lifetime.
    ///
    /// # Errors
    ///
    /// Rejects nil operation identity, an all-zero digest, or a lifetime other
    /// than the fixed installation-bootstrap enrollment-token lifetime.
    pub fn new(
        installation: ConfiguredDeploymentInstallationProof,
        enrollment_id: Uuid,
        token_sha256: [u8; 32],
        runner_group: RunnerGroup,
        lifetime_ms: i64,
    ) -> Result<Self, InstallationBootstrapRequestError> {
        if enrollment_id.is_nil()
            || token_sha256 == [0; 32]
            || lifetime_ms != INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS
        {
            return Err(InstallationBootstrapRequestError);
        }
        Ok(Self {
            installation,
            enrollment_id,
            token_sha256,
            runner_group,
            lifetime_ms,
        })
    }
}

impl fmt::Debug for EnsureInstallationBootstrapRunnerEnrollmentToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnsureInstallationBootstrapRunnerEnrollmentToken")
            .field("enrollment_id", &self.enrollment_id)
            .field("runner_group", &self.runner_group)
            .field("lifetime_ms", &self.lifetime_ms)
            .finish_non_exhaustive()
    }
}

/// Sanitized invalid installation-bootstrap enrollment request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallationBootstrapRequestError;

impl fmt::Display for InstallationBootstrapRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("installation bootstrap request is invalid")
    }
}

impl std::error::Error for InstallationBootstrapRequestError {}

/// Durable outcome of one installation-bootstrap runner token ensure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallationBootstrapRunnerEnrollmentTokenOutcome {
    /// A new token row and its success audit event committed together.
    Applied(RunnerEnrollmentTokenRecord),
    /// The exact unconsumed token remains live; no durable row changed.
    Replayed(RunnerEnrollmentTokenRecord),
    /// The exact expired token received a new one-hour window and audit event.
    Refreshed(RunnerEnrollmentTokenRecord),
    /// The exact token was already consumed and can never be refreshed.
    Consumed(RunnerEnrollmentTokenRecord),
    /// The operation identity or token digest was already bound differently.
    Conflict,
}

/// Maximum lifetime used by the control-plane certificate profile. A leaf is
/// shorter when its issuing CA expires first.
pub const MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Minimum certificate lifetime remaining when enrollment commits. This
/// covers the bounded HTTP exchange and durable credential publication so a
/// one-use token cannot be consumed for a certificate that expires in transit.
pub const MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS: i64 = 5 * 60;

/// Authenticated, idempotent request to replace one runner certificate.
pub struct RenewRunnerCertificate {
    machine: AuthenticatedMachine,
    operation_id: Uuid,
    request_sha256: [u8; 32],
}

impl RenewRunnerCertificate {
    /// Binds a renewal operation to the exact mTLS leaf used for this request.
    ///
    /// # Errors
    ///
    /// Rejects a nil operation identifier or an all-zero request digest.
    pub fn new(
        machine: AuthenticatedMachine,
        operation_id: Uuid,
        request_sha256: [u8; 32],
    ) -> Result<Self, RunnerCertificateRenewalRequestError> {
        if operation_id.is_nil() || request_sha256 == [0; 32] {
            return Err(RunnerCertificateRenewalRequestError);
        }
        Ok(Self {
            machine,
            operation_id,
            request_sha256,
        })
    }
}

impl fmt::Debug for RenewRunnerCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenewRunnerCertificate")
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

/// One certificate and exact response produced by the configured issuer.
pub struct IssuedRunnerCertificateRenewal {
    leaf_sha256: [u8; 32],
    issued_at_seconds: i64,
    expires_at_seconds: i64,
    response: Vec<u8>,
}

impl IssuedRunnerCertificateRenewal {
    /// Creates the material returned by a synchronous renewal signer.
    ///
    /// The repository validates the material again against its transaction's
    /// database time and the presented certificate before committing it.
    #[must_use]
    pub fn new(
        leaf_sha256: [u8; 32],
        issued_at_seconds: i64,
        expires_at_seconds: i64,
        response: Vec<u8>,
    ) -> Self {
        Self {
            leaf_sha256,
            issued_at_seconds,
            expires_at_seconds,
            response,
        }
    }
}

impl fmt::Debug for IssuedRunnerCertificateRenewal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedRunnerCertificateRenewal")
            .field("issued_at_seconds", &self.issued_at_seconds)
            .field("expires_at_seconds", &self.expires_at_seconds)
            .field("response_bytes", &self.response.len())
            .finish_non_exhaustive()
    }
}

/// Sanitized failure produced when the configured certificate signer rejects
/// a CSR or cannot create the fixed runner certificate profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerCertificateRenewalSigningError;

/// Invalid public fields at the renewal repository boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerCertificateRenewalRequestError;

impl fmt::Display for RunnerCertificateRenewalRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runner certificate renewal request is invalid")
    }
}

impl std::error::Error for RunnerCertificateRenewalRequestError {}

/// Durable result of one authenticated certificate-renewal request.
#[derive(Clone, Eq, PartialEq)]
pub enum RunnerCertificateRenewalOutcome {
    /// A new certificate, immutable receipt, and one audit event committed.
    Applied(Vec<u8>),
    /// The exact operation and request already committed for this old leaf.
    Replayed(Vec<u8>),
    /// The presented machine no longer names one exact current runner record.
    Rejected,
    /// The current certificate is outside the fixed renewal window.
    NotDue,
    /// An operation or old-leaf receipt is already bound to different bytes.
    Conflict,
}

impl fmt::Debug for RunnerCertificateRenewalOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied(response) => formatter
                .debug_tuple("Applied")
                .field(&format_args!("[REDACTED; {} bytes]", response.len()))
                .finish(),
            Self::Replayed(response) => formatter
                .debug_tuple("Replayed")
                .field(&format_args!("[REDACTED; {} bytes]", response.len()))
                .finish(),
            Self::Rejected => formatter.write_str("Rejected"),
            Self::NotDue => formatter.write_str("NotDue"),
            Self::Conflict => formatter.write_str("Conflict"),
        }
    }
}

/// Authorized request to create a short-lived runner enrollment token record.
pub struct CreateRunnerEnrollmentToken {
    /// Current human actor evidence, reauthorized transactionally.
    pub actor: ManagementActor,
    /// Public, non-secret identity of this token record.
    pub enrollment_id: Uuid,
    /// SHA-256 of the opaque token; plaintext is never persisted.
    pub token_sha256: [u8; 32],
    /// Canonical runner-group name to which redemption is scoped.
    pub runner_group: String,
    /// Requested lifetime in whole milliseconds.
    pub lifetime_ms: i64,
}

impl std::fmt::Debug for CreateRunnerEnrollmentToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateRunnerEnrollmentToken")
            .field("enrollment_id", &self.enrollment_id)
            .field("runner_group", &self.runner_group)
            .field("lifetime_ms", &self.lifetime_ms)
            .finish_non_exhaustive()
    }
}

/// Metadata returned after an enrollment token is durably issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerEnrollmentTokenRecord {
    /// Public token-record identifier.
    pub enrollment_id: Uuid,
    /// Durable runner-group identifier.
    pub runner_group_id: Uuid,
    /// Canonical runner-group name.
    pub runner_group: String,
    /// Database-clock expiration timestamp in Unix milliseconds.
    pub expires_at_ms: i64,
}

/// Non-secret enrollment state loaded before certificate signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRunnerEnrollment {
    /// Public token-record identifier.
    pub enrollment_id: Uuid,
    /// Tenant selected by the issuing human authority.
    pub tenant_id: String,
    /// Durable group selected by the issuing human authority.
    pub runner_group_id: Uuid,
    /// Canonical group name selected by the issuing human authority.
    pub runner_group: String,
    /// Token expiration timestamp in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Database time sampled after this token row was read.
    pub database_time_ms: i64,
}

/// Stable identity of one runner redemption attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareRunnerEnrollment {
    /// SHA-256 of the presented opaque token.
    pub token_sha256: [u8; 32],
    /// Client-generated identity reused across ambiguous HTTP outcomes.
    pub operation_id: Uuid,
    /// Domain-separated digest of the non-secret semantic request.
    pub request_sha256: [u8; 32],
}

/// Result of looking up a one-time token without consuming it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerEnrollmentPrepareOutcome {
    /// The token exists, is unconsumed, and has not expired.
    Prepared(PreparedRunnerEnrollment),
    /// The exact response from a previously committed matching operation.
    Replayed(Vec<u8>),
    /// The token is absent, consumed, or expired; these states are intentionally indistinguishable.
    Rejected,
}

/// Exact runner and certificate state committed while consuming a token.
pub struct ConsumeRunnerEnrollment {
    /// SHA-256 of the presented opaque token.
    pub token_sha256: [u8; 32],
    /// Client-generated identity reused across ambiguous HTTP outcomes.
    pub operation_id: Uuid,
    /// Domain-separated digest of the non-secret semantic request.
    pub request_sha256: [u8; 32],
    /// Durable identity contained in the canonical capability document.
    pub runner_id: Uuid,
    /// Human-readable runner name selected on the execution host.
    pub runner_name: String,
    /// Complete validated capability document; routing projections are derived
    /// from this typed value inside the transaction.
    pub capabilities: RunnerCapabilities,
    /// SHA-256 of the newly signed leaf certificate DER.
    pub certificate_leaf_sha256: [u8; 32],
    /// Database-clock second used as the certificate profile's issuance time.
    pub certificate_issued_at_seconds: i64,
    /// Leaf-certificate expiration timestamp in Unix seconds.
    pub certificate_expires_at_seconds: i64,
    /// Exact bounded JSON response committed with runner registration.
    pub response: Vec<u8>,
    /// Server-verified broker authority required for every Windows runner and
    /// forbidden for every other platform.
    pub windows_admission: Option<WindowsRunnerAdmissionRecord>,
}

impl std::fmt::Debug for ConsumeRunnerEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsumeRunnerEnrollment")
            .field("runner_id", &self.runner_id)
            .field("runner_name", &self.runner_name)
            .field("slots", &self.capabilities.max_parallel_jobs())
            .field("operation_id", &self.operation_id)
            .field(
                "certificate_expires_at_seconds",
                &self.certificate_expires_at_seconds,
            )
            .finish_non_exhaustive()
    }
}

/// Flattened, non-secret evidence from one server-verified Windows admission
/// envelope. The management adapter consumes the nonce and advances promotion
/// rollback floors in the same transaction that registers the runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsRunnerAdmissionRecord {
    /// Opaque proof that the protocol verifier authenticated every flattened
    /// field below. Keeping the witness owned prevents callers from minting a
    /// persistence record from structurally plausible bytes.
    verified: VerifiedWindowsRunnerAdmission,
    /// Exact canonical schema authenticated by the broker.
    schema_version: u16,
    /// Runner identity authenticated by the admission receipt.
    runner_id: Uuid,
    /// Enrollment operation authenticated by the admission receipt.
    operation_id: Uuid,
    /// Server-configured broker admission signing-key identity.
    issuer_key_id: String,
    /// Globally one-use broker receipt nonce.
    nonce: Sha256Digest,
    /// Domain-separated digest of the complete signed envelope.
    envelope_sha256: Sha256Digest,
    /// Exact canonical claims bytes covered by the signature.
    signed_payload: Vec<u8>,
    /// Exact Ed25519 signature bytes.
    authenticator: Vec<u8>,
    /// Broker-owned host identity scoped by server trust.
    broker_host_id: String,
    /// Fixed sandbox provider identity authenticated by the broker.
    sandbox_provider_id: String,
    /// Exact control origin bound by the receipt.
    control_origin: String,
    /// Exact public enrollment origin bound by the receipt.
    enrollment_origin: String,
    /// Digest of the human-readable runner name.
    runner_name_sha256: Sha256Digest,
    /// Digest of the broker-custodied one-time enrollment token.
    enrollment_token_sha256: Sha256Digest,
    /// Digest of the broker-custodied key's certificate request.
    csr_sha256: Sha256Digest,
    /// Digest of the complete broker admission request.
    request_binding_sha256: Sha256Digest,
    /// Stable environment profile identity.
    environment_profile_id: String,
    /// Exact environment profile digest.
    environment_profile_sha256: Sha256Digest,
    /// Immutable digest-qualified Windows image reference.
    image_reference: String,
    /// Exact Windows image digest.
    image_sha256: Sha256Digest,
    /// Shared live-probe contract digest.
    probe_contract_sha256: Sha256Digest,
    /// Whether the broker attested sealed immutable action trees.
    sealed_action_trees: bool,
    /// Whether the admitted profile is strictly network-disabled.
    network_disabled: bool,
    /// Broker/control-owned promotion trust-bundle identity.
    promotion_trust_bundle_id: String,
    /// Exact promotion signing-key identity.
    promotion_key_id: String,
    /// Canonical promotion payload digest.
    promotion_payload_sha256: Sha256Digest,
    /// Complete promotion envelope digest.
    promotion_envelope_sha256: Sha256Digest,
    /// Monotonic promotion serial.
    promotion_serial: u64,
    /// Monotonic revocation generation.
    revocation_generation: u64,
    /// Signed promotion issue time.
    promotion_issued_at_ms: u64,
    /// Signed promotion expiry time.
    promotion_expires_at_ms: u64,
    /// Short-lived admission receipt issue time.
    receipt_issued_at_ms: u64,
    /// Short-lived admission receipt expiry time.
    receipt_expires_at_ms: u64,
    /// Digest of the exact capabilities serialized in the receipt.
    capabilities_sha256: Sha256Digest,
    /// Commitment to the opaque broker custody handle.
    custody_handle_sha256: Sha256Digest,
    /// Commitment to the idempotent broker completion nonce.
    completion_nonce_sha256: Sha256Digest,
    /// Ordered authenticated broker/authority evidence digests.
    evidence_sha256: [Sha256Digest; 9],
}

impl WindowsRunnerAdmissionRecord {
    /// Flattens one protocol-verified authority for transactional persistence.
    ///
    /// This is the only constructor. Every stored field is derived from the
    /// opaque verifier result, never from a caller-supplied persistence DTO.
    #[must_use]
    pub fn from_verified(verified: VerifiedWindowsRunnerAdmission) -> Self {
        let envelope = verified.envelope();
        let claims = verified.claims();
        let binding = claims.binding();
        let transaction = binding.transaction();
        let broker = binding.broker_profile();
        let promotion = binding.promotion();
        let promotion_validity = promotion.validity();
        let validity = claims.validity();
        let evidence = claims.evidence();
        let broker_evidence = evidence.broker();
        let authority_evidence = evidence.authority();
        Self {
            schema_version: claims.schema_version(),
            runner_id: transaction.runner_id().as_uuid(),
            operation_id: transaction.operation_id().as_uuid(),
            issuer_key_id: claims.issuer_key_id().to_owned(),
            nonce: claims.nonce(),
            envelope_sha256: verified.envelope_sha256(),
            signed_payload: envelope.signed_payload().to_vec(),
            authenticator: envelope.authenticator().to_vec(),
            broker_host_id: broker.broker_host_id().to_owned(),
            sandbox_provider_id: broker.sandbox_provider_id().to_owned(),
            control_origin: transaction.control_origin().to_owned(),
            enrollment_origin: transaction.enrollment_origin().to_owned(),
            runner_name_sha256: transaction.runner_name_sha256(),
            enrollment_token_sha256: transaction.enrollment_token_sha256(),
            csr_sha256: transaction.csr_sha256(),
            request_binding_sha256: broker.request_binding_sha256(),
            environment_profile_id: broker.profile().id().as_str().to_owned(),
            environment_profile_sha256: broker.profile().digest(),
            image_reference: broker.image().reference().to_owned(),
            image_sha256: broker.image().digest(),
            probe_contract_sha256: broker.probe_contract_sha256(),
            sealed_action_trees: broker.sealed_action_trees(),
            network_disabled: broker.network_disabled(),
            promotion_trust_bundle_id: promotion.trust_bundle_id().to_owned(),
            promotion_key_id: promotion.key_id().to_owned(),
            promotion_payload_sha256: promotion.payload_sha256(),
            promotion_envelope_sha256: promotion.envelope_sha256(),
            promotion_serial: promotion.promotion_serial(),
            revocation_generation: promotion.revocation_generation(),
            promotion_issued_at_ms: promotion_validity.issued_at_unix_millis(),
            promotion_expires_at_ms: promotion_validity.expires_at_unix_millis(),
            receipt_issued_at_ms: validity.issued_at_unix_millis(),
            receipt_expires_at_ms: validity.expires_at_unix_millis(),
            capabilities_sha256: binding.capabilities_sha256(),
            custody_handle_sha256: claims.custody_handle_sha256(),
            completion_nonce_sha256: claims.completion_nonce_sha256(),
            evidence_sha256: [
                broker_evidence.broker_attestation_sha256(),
                broker_evidence.host_input_attestation_sha256(),
                broker_evidence.image_attestation_sha256(),
                broker_evidence.network_attestation_sha256(),
                broker_evidence.profile_contract_sha256(),
                authority_evidence.authority_attestation_sha256(),
                authority_evidence.promotion_trust_bundle_sha256(),
                authority_evidence.promotion_public_key_sha256(),
                authority_evidence.cleanup_receipt_sha256(),
            ],
            verified,
        }
    }

    fn valid_for(&self, request: &ConsumeRunnerEnrollment) -> bool {
        let Some(profile) = request.capabilities.environment_profiles().iter().next() else {
            return false;
        };
        let features = request.capabilities.features();
        let node_action = [
            &RunnerFeature::NODE12_ACTIONS,
            &RunnerFeature::NODE16_ACTIONS,
            &RunnerFeature::NODE20_ACTIONS,
            &RunnerFeature::NODE24_ACTIONS,
        ]
        .into_iter()
        .any(|feature| features.contains(feature));
        let action_feature = node_action
            || features.contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
            || features.contains(&RunnerFeature::COMPOSITE_ACTIONS)
            || features.contains(&RunnerFeature::REPOSITORY_ACTIONS);
        let Ok(capabilities) = serde_json::to_vec(&request.capabilities) else {
            return false;
        };
        let runner_name_sha256 =
            Sha256Digest::from_bytes(Sha256::digest(request.runner_name.as_bytes()).into());
        let capabilities_sha256 = Sha256Digest::from_bytes(Sha256::digest(capabilities).into());
        let image_suffix = format!("@sha256:{}", self.image_sha256);
        self.envelope_sha256 == self.verified.envelope_sha256()
            && self.signed_payload.as_slice() == self.verified.envelope().signed_payload()
            && self.authenticator.as_slice() == self.verified.envelope().authenticator()
            && self.schema_version == WINDOWS_ADMISSION_SCHEMA_VERSION
            && self.runner_id == request.runner_id
            && self.operation_id == request.operation_id
            && request.capabilities.environment_profiles().len() == 1
            && request.capabilities.sandbox().maximum_isolation() == IsolationLevel::VirtualMachine
            && request
                .capabilities
                .sandbox()
                .features()
                .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
            && !features.contains(&RunnerFeature::LOCAL_ACTIONS)
            && node_action == features.contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
            && (!action_feature || features.contains(&RunnerFeature::REPOSITORY_ACTIONS))
            && (!action_feature || self.sealed_action_trees)
            && valid_admission_id(&self.issuer_key_id)
            && self.nonce != Sha256Digest::from_bytes([0; 32])
            && self.envelope_sha256 != Sha256Digest::from_bytes([0; 32])
            && !self.signed_payload.is_empty()
            && self.signed_payload.len() <= MAX_WINDOWS_ADMISSION_PAYLOAD_BYTES
            && self.authenticator.len() == 64
            && is_lower_hex_64(&self.broker_host_id)
            && self.sandbox_provider_id == WINDOWS_ADMISSION_SANDBOX_PROVIDER_ID
            && valid_origin_text(&self.control_origin)
            && valid_origin_text(&self.enrollment_origin)
            && self.runner_name_sha256 == runner_name_sha256
            && self.enrollment_token_sha256 == Sha256Digest::from_bytes(request.token_sha256)
            && self.request_binding_sha256 != Sha256Digest::from_bytes([0; 32])
            && self.csr_sha256 != Sha256Digest::from_bytes([0; 32])
            && self.environment_profile_id == profile.id().as_str()
            && self.environment_profile_sha256 == profile.digest()
            && !self.image_reference.is_empty()
            && self.image_reference.len() <= MAX_WINDOWS_IMAGE_REFERENCE_BYTES
            && self.image_reference.ends_with(&image_suffix)
            && self.image_sha256 != Sha256Digest::from_bytes([0; 32])
            && self.probe_contract_sha256 != Sha256Digest::from_bytes([0; 32])
            && self.network_disabled
            && valid_admission_id(&self.promotion_trust_bundle_id)
            && valid_admission_id(&self.promotion_key_id)
            && self.promotion_serial > 0
            && self.revocation_generation > 0
            && i64::try_from(self.promotion_serial).is_ok()
            && i64::try_from(self.revocation_generation).is_ok()
            && valid_unsigned_window(
                self.promotion_issued_at_ms,
                self.promotion_expires_at_ms,
                7 * 24 * 60 * 60 * 1_000,
            )
            && valid_unsigned_window(
                self.receipt_issued_at_ms,
                self.receipt_expires_at_ms,
                15 * 60 * 1_000,
            )
            && self.capabilities_sha256 == capabilities_sha256
            && [
                self.promotion_payload_sha256,
                self.promotion_envelope_sha256,
                self.custody_handle_sha256,
                self.completion_nonce_sha256,
            ]
            .into_iter()
            .chain(self.evidence_sha256)
            .all(|digest| digest != Sha256Digest::from_bytes([0; 32]))
    }
}

fn valid_unsigned_window(issued_at_ms: u64, expires_at_ms: u64, maximum_ms: u64) -> bool {
    issued_at_ms > 0
        && expires_at_ms
            .checked_sub(issued_at_ms)
            .is_some_and(|lifetime| (1..=maximum_ms).contains(&lifetime))
        && i64::try_from(expires_at_ms).is_ok()
}

fn valid_admission_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && (3..=MAX_WINDOWS_ADMISSION_ID_BYTES).contains(&value.len())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_origin_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WINDOWS_ADMISSION_ORIGIN_BYTES
        && value.is_ascii()
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

async fn enrollment_database_time_milliseconds(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
        .fetch_one(&mut **transaction)
        .await
}

/// Result of atomically consuming a token and registering its runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerEnrollmentConsumeOutcome {
    /// Enrollment, certificate registration, and audit append committed.
    Applied(Vec<u8>),
    /// An earlier matching operation committed; return its exact response.
    Replayed(Vec<u8>),
    /// The token was absent, consumed, or expired.
    Rejected,
    /// The runner ID or normalized name is already registered.
    AlreadyExists,
    /// The control plane's reviewed registered-runner capacity is full.
    CapacityExhausted,
}

#[derive(FromRow)]
struct EnrollmentRow {
    id: Uuid,
    tenant_id: String,
    runner_group_id: Uuid,
    runner_group: String,
    issued_at_ms: i64,
    last_refreshed_at_ms: Option<i64>,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
    consumed_runner_id: Option<Uuid>,
    redeem_operation_id: Option<Uuid>,
    redeem_request_sha256: Option<Vec<u8>>,
    redeem_response: Option<Vec<u8>>,
    redeem_certificate_expires_at_seconds: Option<i64>,
}

#[derive(FromRow)]
struct CreatedEnrollmentRow {
    id: Uuid,
    tenant_id: String,
    runner_group_id: Uuid,
    runner_group: String,
    token_sha256: Vec<u8>,
    issuer_kind: String,
    issued_by_principal_id: Option<Uuid>,
    issued_by_session_id: Option<Uuid>,
    issued_authorization_revision: Option<i64>,
    installation_authority_sha256: Option<Vec<u8>>,
    issued_at_ms: i64,
    last_refreshed_at_ms: Option<i64>,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
}

#[derive(Clone, Copy)]
enum EnrollmentIssuer<'a> {
    Human(&'a AuthorizedActor),
    Installation(&'a ConfiguredDeploymentInstallationProof),
}

impl EnrollmentIssuer<'_> {
    fn tenant_id(&self) -> &str {
        match self {
            Self::Human(actor) => &actor.tenant_id,
            Self::Installation(installation) => installation.tenant_id.as_str(),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Human(_) => ISSUER_HUMAN,
            Self::Installation(_) => ISSUER_INSTALLATION_BOOTSTRAP,
        }
    }

    const fn human_principal_id(&self) -> Option<Uuid> {
        match self {
            Self::Human(actor) => Some(actor.principal_id),
            Self::Installation(_) => None,
        }
    }

    const fn human_session_id(&self) -> Option<Uuid> {
        match self {
            Self::Human(actor) => Some(actor.session_id),
            Self::Installation(_) => None,
        }
    }

    const fn human_authorization_revision(&self) -> Option<i64> {
        match self {
            Self::Human(actor) => Some(actor.authorization_revision),
            Self::Installation(_) => None,
        }
    }

    fn installation_authority_sha256(&self) -> Option<&[u8]> {
        match self {
            Self::Human(_) => None,
            Self::Installation(installation) => {
                Some(installation.installation_authority_sha256.as_slice())
            }
        }
    }
}

struct EnrollmentTokenSpec<'a> {
    enrollment_id: Uuid,
    token_sha256: &'a [u8; 32],
    runner_group: &'a str,
    lifetime_ms: i64,
}

impl<'a> From<&'a CreateRunnerEnrollmentToken> for EnrollmentTokenSpec<'a> {
    fn from(request: &'a CreateRunnerEnrollmentToken) -> Self {
        Self {
            enrollment_id: request.enrollment_id,
            token_sha256: &request.token_sha256,
            runner_group: &request.runner_group,
            lifetime_ms: request.lifetime_ms,
        }
    }
}

impl<'a> From<&'a EnsureInstallationBootstrapRunnerEnrollmentToken> for EnrollmentTokenSpec<'a> {
    fn from(request: &'a EnsureInstallationBootstrapRunnerEnrollmentToken) -> Self {
        Self {
            enrollment_id: request.enrollment_id,
            token_sha256: &request.token_sha256,
            runner_group: request.runner_group.as_str(),
            lifetime_ms: request.lifetime_ms,
        }
    }
}

enum EnrollmentTokenCreateDecision {
    Applied(RunnerEnrollmentTokenRecord),
    Replayed(RunnerEnrollmentTokenRecord),
    Refreshed(RunnerEnrollmentTokenRecord),
    Consumed(RunnerEnrollmentTokenRecord),
    Conflict,
}

#[derive(FromRow)]
struct RenewalAuthorityRow {
    runner_id: Uuid,
    tenant_id: String,
    external_identity: Option<String>,
    desired_state: String,
    leaf_sha256: Vec<u8>,
    expires_at_seconds: i64,
    revoked_at_seconds: Option<i64>,
}

#[derive(FromRow)]
struct RenewalReceiptRow {
    operation_id: Uuid,
    runner_id: Uuid,
    presented_leaf_sha256: Vec<u8>,
    request_sha256: Vec<u8>,
    renewed_leaf_sha256: Vec<u8>,
    response: Vec<u8>,
    renewed_expires_at_seconds: i64,
    stored_certificate_expires_at_seconds: Option<i64>,
}
impl EnrollmentRow {
    fn active_from_ms(&self) -> i64 {
        self.last_refreshed_at_ms.unwrap_or(self.issued_at_ms)
    }

    fn validate(&self) -> Result<(), ManagementRepositoryError> {
        let active_from_ms = self.active_from_ms();
        if self.id.is_nil()
            || self.runner_group_id.is_nil()
            || self.tenant_id.is_empty()
            || !valid_group(&self.runner_group)
            || self.issued_at_ms < 0
            || self
                .expires_at_ms
                .checked_sub(active_from_ms)
                .is_none_or(|lifetime| {
                    !(MIN_TOKEN_LIFETIME_MS..=MAX_TOKEN_LIFETIME_MS).contains(&lifetime)
                })
            || self
                .last_refreshed_at_ms
                .is_some_and(|refreshed| refreshed <= self.issued_at_ms)
        {
            return Err(ManagementRepositoryError::CorruptData);
        }
        match (
            self.consumed_at_ms,
            self.consumed_runner_id,
            self.redeem_operation_id,
            self.redeem_request_sha256.as_deref(),
            self.redeem_response.as_deref(),
            self.redeem_certificate_expires_at_seconds,
        ) {
            (None, None, None, None, None, None) => Ok(()),
            (
                Some(consumed_at_ms),
                Some(runner_id),
                Some(operation_id),
                Some(request),
                Some(response),
                Some(certificate_expires_at_seconds),
            ) if consumed_at_ms >= active_from_ms
                && consumed_at_ms < self.expires_at_ms
                && !runner_id.is_nil()
                && !operation_id.is_nil()
                && request.len() == 32
                && !response.is_empty()
                && response.len() <= MAX_REDEEM_RESPONSE_BYTES
                && certificate_expires_at_seconds
                    .checked_sub(consumed_at_ms.div_euclid(1_000))
                    .is_some_and(|remaining| {
                        remaining >= MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS
                    }) =>
            {
                Ok(())
            }
            _ => Err(ManagementRepositoryError::CorruptData),
        }
    }

    fn prepared(
        &self,
        database_time_ms: i64,
    ) -> Result<PreparedRunnerEnrollment, ManagementRepositoryError> {
        self.validate()?;
        if self.consumed_at_ms.is_some() || self.expires_at_ms <= database_time_ms {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        Ok(PreparedRunnerEnrollment {
            enrollment_id: self.id,
            tenant_id: self.tenant_id.clone(),
            runner_group_id: self.runner_group_id,
            runner_group: self.runner_group.clone(),
            expires_at_ms: self.expires_at_ms,
            database_time_ms,
        })
    }

    fn replay(
        &self,
        operation_id: Uuid,
        request_sha256: &[u8; 32],
        database_time_ms: i64,
    ) -> Result<Option<Vec<u8>>, ManagementRepositoryError> {
        self.validate()?;
        if self.consumed_at_ms.is_none() {
            return Ok(None);
        }
        if self.redeem_operation_id == Some(operation_id)
            && self.redeem_request_sha256.as_deref() == Some(request_sha256.as_slice())
            && self
                .redeem_certificate_expires_at_seconds
                .is_some_and(|expiry| expiry > database_time_ms.div_euclid(1_000))
        {
            Ok(self.redeem_response.clone())
        } else {
            Ok(None)
        }
    }
}

impl PostgresRunnerEnrollmentRepository {
    /// Creates an audited one-time token record after checking `runners:enroll`.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error for invalid bounded input, unavailable
    /// storage, or durable state that violates an enrollment invariant.
    pub async fn create_runner_enrollment_token(
        &self,
        request: CreateRunnerEnrollmentToken,
    ) -> Result<ManagementMutationOutcome<RunnerEnrollmentTokenRecord>, ManagementRepositoryError>
    {
        if request.enrollment_id.is_nil()
            || request.token_sha256 == [0; 32]
            || !valid_group(&request.runner_group)
            || !(MIN_TOKEN_LIFETIME_MS..=MAX_TOKEN_LIFETIME_MS).contains(&request.lifetime_ms)
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let resource_id = request.enrollment_id.hyphenated().to_string();
        let descriptor = AuditDescriptor::new(
            ACTION_TOKEN_CREATE,
            RESOURCE_ENROLLMENT,
            &resource_id,
            &request.actor,
        );
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let authorization = authorize_mutation(
            &mut transaction,
            &request.actor,
            &["runners:enroll"],
            descriptor,
            map_database_error,
        )
        .await?;
        let MutationAuthorization::Authorized(actor) = authorization else {
            commit(transaction).await?;
            return Ok(closed_authorization(&authorization));
        };
        create_authorized_runner_enrollment(transaction, actor, descriptor, &request).await
    }

    /// Ensures the installation-issued runner enrollment token exists exactly.
    ///
    /// An exact live retry is read-only. An exact expired and unconsumed token
    /// receives a new one-hour window on the same row and digest. A consumed
    /// token is terminal and is never refreshed or rotated.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error when the deployment-installation
    /// proof is no longer durably exact, storage is unavailable, or enrollment
    /// state violates its closed issuer and replay contract.
    pub async fn ensure_installation_bootstrap_runner_enrollment_token(
        &self,
        request: EnsureInstallationBootstrapRunnerEnrollmentToken,
    ) -> Result<InstallationBootstrapRunnerEnrollmentTokenOutcome, ManagementRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        revalidate_configured_deployment_installation(&mut transaction, &request.installation)
            .await
            .map_err(map_installation_error)?;
        let issuer = EnrollmentIssuer::Installation(&request.installation);
        let spec = EnrollmentTokenSpec::from(&request);
        match create_runner_enrollment_token(&mut transaction, issuer, &spec).await? {
            EnrollmentTokenCreateDecision::Applied(record) => {
                append_installation_bootstrap_audit_event(
                    &mut transaction,
                    &request.installation,
                    request.enrollment_id,
                    "succeeded",
                )
                .await?;
                commit(transaction).await?;
                Ok(InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(
                    record,
                ))
            }
            EnrollmentTokenCreateDecision::Replayed(record) => {
                commit(transaction).await?;
                Ok(InstallationBootstrapRunnerEnrollmentTokenOutcome::Replayed(
                    record,
                ))
            }
            EnrollmentTokenCreateDecision::Refreshed(record) => {
                append_installation_bootstrap_audit_event(
                    &mut transaction,
                    &request.installation,
                    request.enrollment_id,
                    "succeeded",
                )
                .await?;
                commit(transaction).await?;
                Ok(InstallationBootstrapRunnerEnrollmentTokenOutcome::Refreshed(record))
            }
            EnrollmentTokenCreateDecision::Consumed(record) => {
                commit(transaction).await?;
                Ok(InstallationBootstrapRunnerEnrollmentTokenOutcome::Consumed(
                    record,
                ))
            }
            EnrollmentTokenCreateDecision::Conflict => {
                append_installation_bootstrap_audit_event(
                    &mut transaction,
                    &request.installation,
                    request.enrollment_id,
                    "failed",
                )
                .await?;
                commit(transaction).await?;
                Ok(InstallationBootstrapRunnerEnrollmentTokenOutcome::Conflict)
            }
        }
    }

    /// Loads non-secret token scope before certificate signing.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error for an invalid digest, unavailable
    /// storage, or corrupt durable enrollment state.
    pub async fn prepare_runner_enrollment(
        &self,
        request: PrepareRunnerEnrollment,
    ) -> Result<RunnerEnrollmentPrepareOutcome, ManagementRepositoryError> {
        if request.token_sha256 == [0; 32]
            || request.operation_id.is_nil()
            || request.request_sha256 == [0; 32]
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let row = load_enrollment(&mut transaction, &request.token_sha256, true).await?;
        let now_ms = enrollment_database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        commit(transaction).await?;
        let Some(row) = row else {
            return Ok(RunnerEnrollmentPrepareOutcome::Rejected);
        };
        if let Some(response) = row.replay(request.operation_id, &request.request_sha256, now_ms)? {
            return Ok(RunnerEnrollmentPrepareOutcome::Replayed(response));
        }
        if row.consumed_at_ms.is_some() || row.expires_at_ms <= now_ms {
            return Ok(RunnerEnrollmentPrepareOutcome::Rejected);
        }
        Ok(RunnerEnrollmentPrepareOutcome::Prepared(
            row.prepared(now_ms)?,
        ))
    }

    /// Atomically consumes an enrollment token and registers the runner certificate.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error for invalid runner/certificate input,
    /// unavailable storage, or durable state that violates an enrollment invariant.
    #[allow(
        clippy::too_many_lines,
        reason = "the transaction keeps token lock, runner, certificate, consumption, and audit visibly contiguous"
    )]
    pub async fn consume_runner_enrollment(
        &self,
        request: ConsumeRunnerEnrollment,
    ) -> Result<RunnerEnrollmentConsumeOutcome, ManagementRepositoryError> {
        let windows_platform =
            request.capabilities.platform().operating_system() == &OperatingSystem::Windows;
        let windows_admission_valid = match &request.windows_admission {
            Some(admission) => windows_platform && admission.valid_for(&request),
            None => !windows_platform,
        };
        if request.token_sha256 == [0; 32]
            || request.operation_id.is_nil()
            || request.request_sha256 == [0; 32]
            || request.runner_id.is_nil()
            || !valid_runner_name(&request.runner_name)
            || request.capabilities.runner_id().as_uuid() != request.runner_id
            || request.capabilities.validate().is_err()
            || request.certificate_leaf_sha256 == [0; 32]
            || request.certificate_issued_at_seconds < 0
            || request.certificate_expires_at_seconds <= request.certificate_issued_at_seconds
            || request.response.is_empty()
            || request.response.len() > MAX_REDEEM_RESPONSE_BYTES
            || !windows_admission_valid
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let Some(row) = load_enrollment(&mut transaction, &request.token_sha256, true).await?
        else {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        };
        let replay_time_ms = enrollment_database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        if let Some(response) = row.replay(
            request.operation_id,
            &request.request_sha256,
            replay_time_ms,
        )? {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Replayed(response));
        }
        if row.consumed_at_ms.is_some() {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        }
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(RUNNER_ENROLLMENT_CAPACITY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        let now_ms = enrollment_database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        if row.expires_at_ms <= now_ms {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        }
        let now_seconds = now_ms.div_euclid(1_000);
        if request.certificate_issued_at_seconds < row.active_from_ms().div_euclid(1_000)
            || request.certificate_issued_at_seconds > now_seconds
            || request
                .certificate_expires_at_seconds
                .checked_sub(now_seconds)
                .is_none_or(|remaining| {
                    remaining < MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS
                })
            || request
                .certificate_expires_at_seconds
                .checked_sub(request.certificate_issued_at_seconds)
                .is_none_or(|lifetime| {
                    !(1..=MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS).contains(&lifetime)
                })
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let prepared = row.prepared(now_ms)?;
        let expected_group =
            std::collections::BTreeSet::from([RunnerGroup::new(&prepared.runner_group)
                .map_err(|_| ManagementRepositoryError::CorruptData)?]);
        if request.capabilities.groups() != &expected_group {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        }
        let runner_count: i64 = sqlx::query_scalar("SELECT count(*) FROM runners")
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        let runner_count =
            usize::try_from(runner_count).map_err(|_| ManagementRepositoryError::CorruptData)?;
        if runner_count >= MAX_REGISTERED_RUNNERS {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::CapacityExhausted);
        }
        let normalized_name = request.runner_name.to_lowercase();
        let collision: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM runners WHERE id=$1 OR (tenant_id=$2 AND normalized_name=$3))",
        )
        .bind(request.runner_id)
        .bind(&prepared.tenant_id)
        .bind(&normalized_name)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if collision {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::AlreadyExists);
        }
        let mut admitted_at_ms = now_ms;
        if let Some(admission) = &request.windows_admission {
            if !reserve_windows_admission_nonce(
                &mut transaction,
                prepared.enrollment_id,
                admission,
                now_ms,
            )
            .await?
            {
                commit(transaction).await?;
                return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
            }
            if !advance_windows_promotion_high_water(&mut transaction, admission, now_ms).await? {
                transaction.rollback().await.map_err(map_database_error)?;
                return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
            }
            admitted_at_ms = enrollment_database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            if !windows_admission_is_current(admission, admitted_at_ms) {
                transaction.rollback().await.map_err(map_database_error)?;
                return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
            }
        }
        let labels = request
            .capabilities
            .labels()
            .iter()
            .map(|label| label.as_str().to_owned())
            .collect::<Vec<_>>();
        let capabilities = serde_json::to_value(&request.capabilities)
            .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
        let external_identity = enrolled_runner_external_identity(request.runner_id);
        sqlx::query(
            r"
            INSERT INTO runners (
                id,tenant_id,group_id,name,normalized_name,labels,capabilities,
                slots,status,generation,created_at_ms,updated_at_ms,session_epoch,
                external_identity,desired_state
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'offline',1,$9,$9,0,$10,'active')
            ",
        )
        .bind(request.runner_id)
        .bind(&prepared.tenant_id)
        .bind(prepared.runner_group_id)
        .bind(&request.runner_name)
        .bind(&normalized_name)
        .bind(labels)
        .bind(capabilities)
        .bind(i32::from(request.capabilities.max_parallel_jobs()))
        .bind(now_ms)
        .bind(external_identity)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        sqlx::query(
            "INSERT INTO runner_machine_certificates (leaf_sha256,runner_id,expires_at_seconds) VALUES ($1,$2,$3)",
        )
        .bind(request.certificate_leaf_sha256.as_slice())
        .bind(request.runner_id)
        .bind(request.certificate_expires_at_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        let consumed = sqlx::query(
            "UPDATE runner_enrollment_tokens SET consumed_at_ms=$2,consumed_runner_id=$3,redeem_operation_id=$4,redeem_request_sha256=$5,redeem_response=$6,redeem_certificate_expires_at_seconds=$7 WHERE id=$1 AND consumed_at_ms IS NULL",
        )
        .bind(prepared.enrollment_id)
        .bind(now_ms)
        .bind(request.runner_id)
        .bind(request.operation_id)
        .bind(request.request_sha256.as_slice())
        .bind(&request.response)
        .bind(request.certificate_expires_at_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if consumed.rows_affected() != 1 {
            return Err(ManagementRepositoryError::CorruptData);
        }
        if let Some(admission) = &request.windows_admission {
            persist_windows_runner_admission(
                &mut transaction,
                prepared.enrollment_id,
                &prepared.tenant_id,
                &request,
                admission,
                admitted_at_ms,
            )
            .await?;
        }
        sqlx::query(
            r"
            INSERT INTO security_audit_events (
                event_id,tenant_id,occurred_at_ms,actor_kind,action,outcome,
                resource_kind,resource_id
            ) VALUES ($1,$2,$3,'system',$4,'succeeded',$5,$6)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&prepared.tenant_id)
        .bind(now_ms)
        .bind(ACTION_ENROLL)
        .bind(RESOURCE_ENROLLMENT)
        .bind(request.runner_id.hyphenated().to_string())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        commit(transaction).await?;
        Ok(RunnerEnrollmentConsumeOutcome::Applied(request.response))
    }

    /// Renews one currently authenticated runner certificate inside a single
    /// database transaction.
    ///
    /// The presented certificate and runner row remain locked from
    /// revalidation through signing, certificate insertion, immutable receipt,
    /// audit append, and commit. The signer is invoked synchronously with the
    /// exact database time while those locks are held.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error when storage is unavailable or
    /// durable authority state violates the closed renewal schema.
    #[allow(
        clippy::too_many_lines,
        reason = "the transaction deliberately keeps renewal authority, signing, receipt, and audit visibly contiguous"
    )]
    pub async fn renew_runner_certificate<Sign>(
        &self,
        request: RenewRunnerCertificate,
        sign: Sign,
    ) -> Result<RunnerCertificateRenewalOutcome, ManagementRepositoryError>
    where
        Sign:
            FnOnce(
                Uuid,
                i64,
            )
                -> Result<IssuedRunnerCertificateRenewal, RunnerCertificateRenewalSigningError>,
    {
        let presented_leaf_sha256 = *request.machine.certificate_sha256();
        if presented_leaf_sha256 == [0; 32] {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,$2))")
            .bind(request.operation_id.hyphenated().to_string())
            .bind(RUNNER_CERTIFICATE_RENEWAL_OPERATION_LOCK_SALT)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        let authority = sqlx::query_as::<_, RenewalAuthorityRow>(
            r"
            SELECT runner.id AS runner_id,
                   runner.tenant_id,
                   runner.external_identity,
                   runner.desired_state,
                   certificate.leaf_sha256,
                   certificate.expires_at_seconds,
                   certificate.revoked_at_seconds
            FROM runner_machine_certificates AS certificate
            JOIN runners AS runner ON runner.id = certificate.runner_id
            WHERE certificate.leaf_sha256 = $1
            FOR UPDATE OF certificate, runner
            ",
        )
        .bind(presented_leaf_sha256.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        let Some(authority) = authority else {
            commit(transaction).await?;
            return Ok(RunnerCertificateRenewalOutcome::Rejected);
        };
        let now_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        let now_seconds = now_ms.div_euclid(1_000);
        let authenticated_expires_at_seconds =
            i64::try_from(request.machine.certificate_expires_at().as_seconds())
                .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
        if authority.runner_id.is_nil()
            || authority.tenant_id.is_empty()
            || authority.external_identity.as_deref()
                != Some(request.machine.external_identity().as_str())
            || authority.desired_state != "active"
            || authority.leaf_sha256.as_slice() != presented_leaf_sha256
            || authority.revoked_at_seconds.is_some()
            || authority.expires_at_seconds != authenticated_expires_at_seconds
            || authority.expires_at_seconds <= now_seconds
        {
            commit(transaction).await?;
            return Ok(RunnerCertificateRenewalOutcome::Rejected);
        }

        let receipt = load_renewal_receipt(&mut transaction, &presented_leaf_sha256).await?;
        if let Some(receipt) = receipt {
            let valid = !receipt.operation_id.is_nil()
                && receipt.runner_id == authority.runner_id
                && receipt.presented_leaf_sha256.as_slice() == presented_leaf_sha256
                && receipt.request_sha256.len() == 32
                && receipt.renewed_leaf_sha256.len() == 32
                && receipt.renewed_leaf_sha256.as_slice() != presented_leaf_sha256
                && !receipt.response.is_empty()
                && receipt.response.len() <= MAX_RUNNER_CERTIFICATE_RENEWAL_RESPONSE_BYTES
                && receipt.renewed_expires_at_seconds > authority.expires_at_seconds
                && receipt.stored_certificate_expires_at_seconds
                    == Some(receipt.renewed_expires_at_seconds);
            if !valid {
                return Err(ManagementRepositoryError::CorruptData);
            }
            let exact = receipt.operation_id == request.operation_id
                && receipt.request_sha256.as_slice() == request.request_sha256;
            commit(transaction).await?;
            return if exact {
                Ok(RunnerCertificateRenewalOutcome::Replayed(receipt.response))
            } else {
                Ok(RunnerCertificateRenewalOutcome::Conflict)
            };
        }
        let operation_collision: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM runner_certificate_renewal_receipts WHERE operation_id=$1)",
        )
        .bind(request.operation_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if operation_collision {
            commit(transaction).await?;
            return Ok(RunnerCertificateRenewalOutcome::Conflict);
        }
        let remaining = authority.expires_at_seconds.saturating_sub(now_seconds);
        if remaining > RUNNER_CERTIFICATE_RENEWAL_WINDOW_SECONDS {
            commit(transaction).await?;
            return Ok(RunnerCertificateRenewalOutcome::NotDue);
        }

        delete_expired_runner_certificate_state(&mut transaction, authority.runner_id, now_seconds)
            .await?;
        let active_certificates: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM runner_machine_certificates
            WHERE runner_id=$1
              AND revoked_at_seconds IS NULL
              AND expires_at_seconds > $2
            ",
        )
        .bind(authority.runner_id)
        .bind(now_seconds)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if active_certificates != 1 {
            return Err(ManagementRepositoryError::CorruptData);
        }

        let Ok(issued) = sign(authority.runner_id, now_ms) else {
            commit(transaction).await?;
            return Ok(RunnerCertificateRenewalOutcome::Rejected);
        };
        if issued.leaf_sha256 == [0; 32]
            || issued.leaf_sha256 == presented_leaf_sha256
            || issued.issued_at_seconds != now_seconds
            || issued.expires_at_seconds <= authority.expires_at_seconds
            || issued
                .expires_at_seconds
                .checked_sub(now_seconds)
                .is_none_or(|remaining| {
                    remaining < MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS
                })
            || issued
                .expires_at_seconds
                .checked_sub(issued.issued_at_seconds)
                .is_none_or(|lifetime| {
                    !(1..=MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS).contains(&lifetime)
                })
            || issued.response.is_empty()
            || issued.response.len() > MAX_RUNNER_CERTIFICATE_RENEWAL_RESPONSE_BYTES
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }

        sqlx::query(
            "INSERT INTO runner_machine_certificates (leaf_sha256,runner_id,expires_at_seconds) VALUES ($1,$2,$3)",
        )
        .bind(issued.leaf_sha256.as_slice())
        .bind(authority.runner_id)
        .bind(issued.expires_at_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        let audit_event_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO security_audit_events (
                event_id,tenant_id,occurred_at_ms,actor_kind,action,outcome,
                resource_kind,resource_id,request_id
            ) VALUES ($1,$2,$3,'system',$4,'succeeded',$5,$6,$7)
            ",
        )
        .bind(audit_event_id)
        .bind(&authority.tenant_id)
        .bind(now_ms)
        .bind(ACTION_CERTIFICATE_RENEW)
        .bind(RESOURCE_RUNNER_CERTIFICATE)
        .bind(authority.runner_id.hyphenated().to_string())
        .bind(request.operation_id.hyphenated().to_string())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        sqlx::query(
            r"
            INSERT INTO runner_certificate_renewal_receipts (
                operation_id,runner_id,presented_leaf_sha256,request_sha256,
                renewed_leaf_sha256,response,renewed_expires_at_seconds,
                created_at_ms,audit_event_id
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ",
        )
        .bind(request.operation_id)
        .bind(authority.runner_id)
        .bind(presented_leaf_sha256.as_slice())
        .bind(request.request_sha256.as_slice())
        .bind(issued.leaf_sha256.as_slice())
        .bind(&issued.response)
        .bind(issued.expires_at_seconds)
        .bind(now_ms)
        .bind(audit_event_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        commit(transaction).await?;
        Ok(RunnerCertificateRenewalOutcome::Applied(issued.response))
    }
}

async fn load_renewal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    presented_leaf_sha256: &[u8; 32],
) -> Result<Option<RenewalReceiptRow>, ManagementRepositoryError> {
    sqlx::query_as::<_, RenewalReceiptRow>(
        r"
        SELECT receipt.operation_id,
               receipt.runner_id,
               receipt.presented_leaf_sha256,
               receipt.request_sha256,
               receipt.renewed_leaf_sha256,
               receipt.response,
               receipt.renewed_expires_at_seconds,
               certificate.expires_at_seconds AS stored_certificate_expires_at_seconds
        FROM runner_certificate_renewal_receipts AS receipt
        LEFT JOIN runner_machine_certificates AS certificate
          ON certificate.runner_id=receipt.runner_id
         AND certificate.leaf_sha256=receipt.renewed_leaf_sha256
        WHERE receipt.presented_leaf_sha256=$1
        ",
    )
    .bind(presented_leaf_sha256.as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)
}

async fn delete_expired_runner_certificate_state(
    transaction: &mut Transaction<'_, Postgres>,
    runner_id: Uuid,
    now_seconds: i64,
) -> Result<(), ManagementRepositoryError> {
    sqlx::query(
        r"
        DELETE FROM runner_certificate_renewal_receipts AS receipt
        USING runner_machine_certificates AS certificate
        WHERE receipt.runner_id=$1
          AND certificate.runner_id=receipt.runner_id
          AND certificate.leaf_sha256=receipt.presented_leaf_sha256
          AND certificate.expires_at_seconds <= $2
        ",
    )
    .bind(runner_id)
    .bind(now_seconds)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    sqlx::query(
        r"
        DELETE FROM runner_machine_certificates
        WHERE runner_id=$1
          AND expires_at_seconds <= $2
        ",
    )
    .bind(runner_id)
    .bind(now_seconds)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

async fn reserve_windows_admission_nonce(
    transaction: &mut Transaction<'_, Postgres>,
    enrollment_id: Uuid,
    admission: &WindowsRunnerAdmissionRecord,
    now_ms: i64,
) -> Result<bool, ManagementRepositoryError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO windows_runner_admission_nonces (
            nonce,enrollment_id,issuer_key_id,envelope_sha256,reserved_at_ms
        ) VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(admission.nonce.as_bytes().as_slice())
    .bind(enrollment_id)
    .bind(&admission.issuer_key_id)
    .bind(admission.envelope_sha256.as_bytes().as_slice())
    .bind(now_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(inserted.rows_affected() == 1)
}

async fn advance_windows_promotion_high_water(
    transaction: &mut Transaction<'_, Postgres>,
    admission: &WindowsRunnerAdmissionRecord,
    now_ms: i64,
) -> Result<bool, ManagementRepositoryError> {
    let promotion_serial = i64::try_from(admission.promotion_serial)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let revocation_generation = i64::try_from(admission.revocation_generation)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let advanced = sqlx::query(
        r"
        INSERT INTO windows_image_promotion_high_water (
            trust_bundle_id,promotion_key_id,promotion_trust_bundle_sha256,
            promotion_public_key_sha256,promotion_payload_sha256,
            promotion_envelope_sha256,image_reference,image_sha256,
            promotion_serial,revocation_generation,promotion_issued_at_ms,
            promotion_expires_at_ms,updated_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (trust_bundle_id,promotion_key_id) DO UPDATE
        SET promotion_payload_sha256=EXCLUDED.promotion_payload_sha256,
            promotion_envelope_sha256=EXCLUDED.promotion_envelope_sha256,
            image_reference=EXCLUDED.image_reference,
            image_sha256=EXCLUDED.image_sha256,
            promotion_serial=EXCLUDED.promotion_serial,
            revocation_generation=EXCLUDED.revocation_generation,
            promotion_issued_at_ms=EXCLUDED.promotion_issued_at_ms,
            promotion_expires_at_ms=EXCLUDED.promotion_expires_at_ms,
            updated_at_ms=GREATEST(
                windows_image_promotion_high_water.updated_at_ms,
                EXCLUDED.updated_at_ms
            )
        WHERE windows_image_promotion_high_water.promotion_trust_bundle_sha256
                  = EXCLUDED.promotion_trust_bundle_sha256
          AND windows_image_promotion_high_water.promotion_public_key_sha256
                  = EXCLUDED.promotion_public_key_sha256
          AND windows_image_promotion_high_water.promotion_serial
                  <= EXCLUDED.promotion_serial
          AND windows_image_promotion_high_water.revocation_generation
                  <= EXCLUDED.revocation_generation
          AND (
              windows_image_promotion_high_water.promotion_serial
                  < EXCLUDED.promotion_serial
              OR windows_image_promotion_high_water.revocation_generation
                  < EXCLUDED.revocation_generation
              OR (
                  windows_image_promotion_high_water.promotion_serial
                      = EXCLUDED.promotion_serial
                  AND windows_image_promotion_high_water.revocation_generation
                      = EXCLUDED.revocation_generation
                  AND windows_image_promotion_high_water.promotion_payload_sha256
                      = EXCLUDED.promotion_payload_sha256
                  AND windows_image_promotion_high_water.promotion_envelope_sha256
                      = EXCLUDED.promotion_envelope_sha256
                  AND windows_image_promotion_high_water.image_reference
                      = EXCLUDED.image_reference
                  AND windows_image_promotion_high_water.image_sha256
                      = EXCLUDED.image_sha256
                  AND windows_image_promotion_high_water.promotion_issued_at_ms
                      = EXCLUDED.promotion_issued_at_ms
                  AND windows_image_promotion_high_water.promotion_expires_at_ms
                      = EXCLUDED.promotion_expires_at_ms
              )
          )
        ",
    )
    .bind(&admission.promotion_trust_bundle_id)
    .bind(&admission.promotion_key_id)
    .bind(admission.evidence_sha256[6].as_bytes().as_slice())
    .bind(admission.evidence_sha256[7].as_bytes().as_slice())
    .bind(admission.promotion_payload_sha256.as_bytes().as_slice())
    .bind(admission.promotion_envelope_sha256.as_bytes().as_slice())
    .bind(&admission.image_reference)
    .bind(admission.image_sha256.as_bytes().as_slice())
    .bind(promotion_serial)
    .bind(revocation_generation)
    .bind(
        i64::try_from(admission.promotion_issued_at_ms)
            .map_err(|_| ManagementRepositoryError::InvalidRequest)?,
    )
    .bind(
        i64::try_from(admission.promotion_expires_at_ms)
            .map_err(|_| ManagementRepositoryError::InvalidRequest)?,
    )
    .bind(now_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(advanced.rows_affected() == 1)
}

fn windows_admission_is_current(
    admission: &WindowsRunnerAdmissionRecord,
    database_now_ms: i64,
) -> bool {
    let Ok(receipt_issued_at_ms) = i64::try_from(admission.receipt_issued_at_ms) else {
        return false;
    };
    let Ok(receipt_expires_at_ms) = i64::try_from(admission.receipt_expires_at_ms) else {
        return false;
    };
    let Ok(promotion_issued_at_ms) = i64::try_from(admission.promotion_issued_at_ms) else {
        return false;
    };
    let Ok(promotion_expires_at_ms) = i64::try_from(admission.promotion_expires_at_ms) else {
        return false;
    };
    receipt_issued_at_ms <= database_now_ms
        && database_now_ms < receipt_expires_at_ms
        && promotion_issued_at_ms <= database_now_ms
        && database_now_ms < promotion_expires_at_ms
}

#[allow(
    clippy::too_many_lines,
    reason = "the insert keeps every authenticated Windows admission field visibly bound"
)]
async fn persist_windows_runner_admission(
    transaction: &mut Transaction<'_, Postgres>,
    enrollment_id: Uuid,
    tenant_id: &str,
    request: &ConsumeRunnerEnrollment,
    admission: &WindowsRunnerAdmissionRecord,
    admitted_at_ms: i64,
) -> Result<(), ManagementRepositoryError> {
    let capabilities = serde_json::to_value(&request.capabilities)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let promotion_serial = i64::try_from(admission.promotion_serial)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let revocation_generation = i64::try_from(admission.revocation_generation)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let promotion_issued_at_ms = i64::try_from(admission.promotion_issued_at_ms)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let promotion_expires_at_ms = i64::try_from(admission.promotion_expires_at_ms)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let receipt_issued_at_ms = i64::try_from(admission.receipt_issued_at_ms)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let receipt_expires_at_ms = i64::try_from(admission.receipt_expires_at_ms)
        .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
    let inserted = sqlx::query(
        r"
        INSERT INTO windows_runner_admissions (
            enrollment_id,tenant_id,runner_id,operation_id,request_sha256,
            schema_version,issuer_key_id,nonce,envelope_sha256,signed_payload,
            authenticator,broker_host_id,sandbox_provider_id,control_origin,enrollment_origin,
            runner_name_sha256,enrollment_token_sha256,csr_sha256,
            request_binding_sha256,environment_profile_id,
            environment_profile_sha256,image_reference,image_sha256,
            probe_contract_sha256,sealed_action_trees,network_disabled,
            promotion_trust_bundle_id,promotion_key_id,
            promotion_payload_sha256,promotion_envelope_sha256,
            promotion_serial,revocation_generation,promotion_issued_at_ms,
            promotion_expires_at_ms,receipt_issued_at_ms,receipt_expires_at_ms,
            capabilities,capabilities_sha256,custody_handle_sha256,
            completion_nonce_sha256,broker_attestation_sha256,
            host_input_attestation_sha256,image_attestation_sha256,
            network_attestation_sha256,profile_contract_sha256,
            authority_attestation_sha256,promotion_trust_bundle_sha256,
            promotion_public_key_sha256,cleanup_receipt_sha256,admitted_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
            $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,
            $31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,
            $45,$46,$47,$48,$49,$50
        )
        ",
    )
    .bind(enrollment_id)
    .bind(tenant_id)
    .bind(request.runner_id)
    .bind(request.operation_id)
    .bind(request.request_sha256.as_slice())
    .bind(i16::try_from(admission.schema_version).unwrap_or_default())
    .bind(&admission.issuer_key_id)
    .bind(admission.nonce.as_bytes().as_slice())
    .bind(admission.envelope_sha256.as_bytes().as_slice())
    .bind(&admission.signed_payload)
    .bind(&admission.authenticator)
    .bind(&admission.broker_host_id)
    .bind(&admission.sandbox_provider_id)
    .bind(&admission.control_origin)
    .bind(&admission.enrollment_origin)
    .bind(admission.runner_name_sha256.as_bytes().as_slice())
    .bind(admission.enrollment_token_sha256.as_bytes().as_slice())
    .bind(admission.csr_sha256.as_bytes().as_slice())
    .bind(admission.request_binding_sha256.as_bytes().as_slice())
    .bind(&admission.environment_profile_id)
    .bind(admission.environment_profile_sha256.as_bytes().as_slice())
    .bind(&admission.image_reference)
    .bind(admission.image_sha256.as_bytes().as_slice())
    .bind(admission.probe_contract_sha256.as_bytes().as_slice())
    .bind(admission.sealed_action_trees)
    .bind(admission.network_disabled)
    .bind(&admission.promotion_trust_bundle_id)
    .bind(&admission.promotion_key_id)
    .bind(admission.promotion_payload_sha256.as_bytes().as_slice())
    .bind(admission.promotion_envelope_sha256.as_bytes().as_slice())
    .bind(promotion_serial)
    .bind(revocation_generation)
    .bind(promotion_issued_at_ms)
    .bind(promotion_expires_at_ms)
    .bind(receipt_issued_at_ms)
    .bind(receipt_expires_at_ms)
    .bind(capabilities)
    .bind(admission.capabilities_sha256.as_bytes().as_slice())
    .bind(admission.custody_handle_sha256.as_bytes().as_slice())
    .bind(admission.completion_nonce_sha256.as_bytes().as_slice())
    .bind(admission.evidence_sha256[0].as_bytes().as_slice())
    .bind(admission.evidence_sha256[1].as_bytes().as_slice())
    .bind(admission.evidence_sha256[2].as_bytes().as_slice())
    .bind(admission.evidence_sha256[3].as_bytes().as_slice())
    .bind(admission.evidence_sha256[4].as_bytes().as_slice())
    .bind(admission.evidence_sha256[5].as_bytes().as_slice())
    .bind(admission.evidence_sha256[6].as_bytes().as_slice())
    .bind(admission.evidence_sha256[7].as_bytes().as_slice())
    .bind(admission.evidence_sha256[8].as_bytes().as_slice())
    .bind(admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    if inserted.rows_affected() != 1 {
        return Err(ManagementRepositoryError::CorruptData);
    }
    Ok(())
}

async fn create_authorized_runner_enrollment(
    mut transaction: Transaction<'_, Postgres>,
    actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    request: &CreateRunnerEnrollmentToken,
) -> Result<ManagementMutationOutcome<RunnerEnrollmentTokenRecord>, ManagementRepositoryError> {
    let spec = EnrollmentTokenSpec::from(request);
    match create_runner_enrollment_token(&mut transaction, EnrollmentIssuer::Human(&actor), &spec)
        .await?
    {
        EnrollmentTokenCreateDecision::Applied(record) => {
            finish_applied(transaction, actor, descriptor, record).await
        }
        EnrollmentTokenCreateDecision::Replayed(record) => {
            // The original transition already appended its audit event. Exact
            // transport replay returns the durable result without a mutation.
            commit(transaction).await?;
            Ok(ManagementMutationOutcome::Applied(record))
        }
        EnrollmentTokenCreateDecision::Conflict => {
            finish_enrollment_conflict(transaction, actor, descriptor).await
        }
        EnrollmentTokenCreateDecision::Refreshed(_)
        | EnrollmentTokenCreateDecision::Consumed(_) => Err(ManagementRepositoryError::CorruptData),
    }
}

async fn create_runner_enrollment_token(
    transaction: &mut Transaction<'_, Postgres>,
    issuer: EnrollmentIssuer<'_>,
    request: &EnrollmentTokenSpec<'_>,
) -> Result<EnrollmentTokenCreateDecision, ManagementRepositoryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,$2))")
        .bind(request.enrollment_id.hyphenated().to_string())
        .bind(RUNNER_ENROLLMENT_CREATE_LOCK_SALT)
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?;
    if let Some(existing) = load_created_enrollment(transaction, request.enrollment_id).await? {
        if !existing.matches(issuer, request)? {
            return Ok(EnrollmentTokenCreateDecision::Conflict);
        }
        let record = existing.record();
        return match issuer {
            EnrollmentIssuer::Human(_) => Ok(EnrollmentTokenCreateDecision::Replayed(record)),
            EnrollmentIssuer::Installation(_) if existing.consumed_at_ms.is_some() => {
                Ok(EnrollmentTokenCreateDecision::Consumed(record))
            }
            EnrollmentIssuer::Installation(_) => {
                let now_ms = database_time_milliseconds(transaction)
                    .await
                    .map_err(map_database_error)?;
                if existing.expires_at_ms > now_ms {
                    return Ok(EnrollmentTokenCreateDecision::Replayed(record));
                }
                let expires_at_ms = now_ms
                    .checked_add(request.lifetime_ms)
                    .ok_or(ManagementRepositoryError::InvalidRequest)?;
                let refreshed = sqlx::query(
                    r"
                    UPDATE runner_enrollment_tokens
                    SET last_refreshed_at_ms=$2,expires_at_ms=$3
                    WHERE id=$1 AND issuer_kind='installation_bootstrap'
                      AND consumed_at_ms IS NULL AND expires_at_ms <= $2
                    ",
                )
                .bind(request.enrollment_id)
                .bind(now_ms)
                .bind(expires_at_ms)
                .execute(&mut **transaction)
                .await
                .map_err(map_database_error)?;
                if refreshed.rows_affected() != 1 {
                    return Err(ManagementRepositoryError::CorruptData);
                }
                Ok(EnrollmentTokenCreateDecision::Refreshed(
                    RunnerEnrollmentTokenRecord {
                        expires_at_ms,
                        ..record
                    },
                ))
            }
        };
    }
    let conflicting_digest: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM runner_enrollment_tokens WHERE token_sha256=$1 FOR UPDATE",
    )
    .bind(request.token_sha256.as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    if conflicting_digest.is_some() {
        return Ok(EnrollmentTokenCreateDecision::Conflict);
    }
    let Some((group_id, expires_at_ms)) =
        try_insert_enrollment(transaction, issuer, request).await?
    else {
        return Ok(EnrollmentTokenCreateDecision::Conflict);
    };
    Ok(EnrollmentTokenCreateDecision::Applied(
        RunnerEnrollmentTokenRecord {
            enrollment_id: request.enrollment_id,
            runner_group_id: group_id,
            runner_group: request.runner_group.to_owned(),
            expires_at_ms,
        },
    ))
}

impl CreatedEnrollmentRow {
    fn matches(
        &self,
        issuer: EnrollmentIssuer<'_>,
        request: &EnrollmentTokenSpec<'_>,
    ) -> Result<bool, ManagementRepositoryError> {
        self.validate()?;
        let issuer_matches = match issuer {
            EnrollmentIssuer::Human(actor) => {
                self.issuer_kind == ISSUER_HUMAN
                    && self.issued_by_principal_id == Some(actor.principal_id)
                    && self.installation_authority_sha256.is_none()
            }
            EnrollmentIssuer::Installation(installation) => {
                self.issuer_kind == ISSUER_INSTALLATION_BOOTSTRAP
                    && self.issued_by_principal_id.is_none()
                    && self.issued_by_session_id.is_none()
                    && self.issued_authorization_revision.is_none()
                    && self.installation_authority_sha256.as_deref()
                        == Some(installation.installation_authority_sha256.as_slice())
            }
        };
        let active_from_ms = self.last_refreshed_at_ms.unwrap_or(self.issued_at_ms);
        Ok(self.tenant_id == issuer.tenant_id()
            && self.runner_group == request.runner_group
            && self.token_sha256.as_slice() == request.token_sha256.as_slice()
            && self.expires_at_ms.checked_sub(active_from_ms) == Some(request.lifetime_ms)
            && issuer_matches)
    }

    fn validate(&self) -> Result<(), ManagementRepositoryError> {
        let active_from_ms = self.last_refreshed_at_ms.unwrap_or(self.issued_at_ms);
        let active_lifetime = self.expires_at_ms.checked_sub(active_from_ms);
        let valid_issuer = match self.issuer_kind.as_str() {
            ISSUER_HUMAN => {
                self.issued_by_principal_id.is_some_and(|id| !id.is_nil())
                    && self.issued_by_session_id.is_some_and(|id| !id.is_nil())
                    && self
                        .issued_authorization_revision
                        .is_some_and(|revision| revision > 0)
                    && self.installation_authority_sha256.is_none()
                    && self.last_refreshed_at_ms.is_none()
                    && active_lifetime.is_some_and(|lifetime| {
                        (MIN_TOKEN_LIFETIME_MS..=MAX_TOKEN_LIFETIME_MS).contains(&lifetime)
                    })
            }
            ISSUER_INSTALLATION_BOOTSTRAP => {
                self.issued_by_principal_id.is_none()
                    && self.issued_by_session_id.is_none()
                    && self.issued_authorization_revision.is_none()
                    && self
                        .installation_authority_sha256
                        .as_deref()
                        .is_some_and(|digest| digest.len() == 32 && digest != [0; 32])
                    && self
                        .last_refreshed_at_ms
                        .is_none_or(|refreshed| refreshed > self.issued_at_ms)
                    && active_lifetime == Some(INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS)
            }
            _ => false,
        };
        if self.id.is_nil()
            || self.tenant_id.is_empty()
            || self.runner_group_id.is_nil()
            || !valid_group(&self.runner_group)
            || self.token_sha256.len() != 32
            || self.token_sha256.as_slice() == [0; 32]
            || self.issued_at_ms < 0
            || self
                .consumed_at_ms
                .is_some_and(|consumed_at_ms| consumed_at_ms < active_from_ms)
            || !valid_issuer
        {
            return Err(ManagementRepositoryError::CorruptData);
        }
        Ok(())
    }

    fn record(&self) -> RunnerEnrollmentTokenRecord {
        RunnerEnrollmentTokenRecord {
            enrollment_id: self.id,
            runner_group_id: self.runner_group_id,
            runner_group: self.runner_group.clone(),
            expires_at_ms: self.expires_at_ms,
        }
    }
}

async fn load_created_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    enrollment_id: Uuid,
) -> Result<Option<CreatedEnrollmentRow>, ManagementRepositoryError> {
    sqlx::query_as::<_, CreatedEnrollmentRow>(
        r"
        SELECT token.id,token.tenant_id,token.runner_group_id,
               groups.name AS runner_group,token.token_sha256,
               token.issuer_kind,token.issued_by_principal_id,
               token.issued_by_session_id,token.issued_authorization_revision,
               token.installation_authority_sha256,token.issued_at_ms,
               token.last_refreshed_at_ms,token.expires_at_ms,
               token.consumed_at_ms
        FROM runner_enrollment_tokens AS token
        JOIN runner_groups AS groups
          ON groups.tenant_id=token.tenant_id
         AND groups.id=token.runner_group_id
        WHERE token.id=$1
        FOR UPDATE
        ",
    )
    .bind(enrollment_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)
}

async fn try_insert_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    issuer: EnrollmentIssuer<'_>,
    request: &EnrollmentTokenSpec<'_>,
) -> Result<Option<(Uuid, i64)>, ManagementRepositoryError> {
    sqlx::query("SAVEPOINT runner_enrollment_token_create")
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?;
    let issued_at_ms = enrollment_database_time_milliseconds(transaction)
        .await
        .map_err(map_database_error)?;
    let group_id = ensure_runner_group(
        transaction,
        issuer.tenant_id(),
        request.runner_group,
        issued_at_ms,
    )
    .await?;
    let expires_at_ms = issued_at_ms
        .checked_add(request.lifetime_ms)
        .ok_or(ManagementRepositoryError::InvalidRequest)?;
    let inserted = sqlx::query(
        r"
        INSERT INTO runner_enrollment_tokens (
            id,tenant_id,runner_group_id,token_sha256,issuer_kind,
            issued_by_principal_id,issued_by_session_id,
            issued_authorization_revision,installation_authority_sha256,
            issued_at_ms,expires_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(request.enrollment_id)
    .bind(issuer.tenant_id())
    .bind(group_id)
    .bind(request.token_sha256.as_slice())
    .bind(issuer.kind())
    .bind(issuer.human_principal_id())
    .bind(issuer.human_session_id())
    .bind(issuer.human_authorization_revision())
    .bind(issuer.installation_authority_sha256())
    .bind(issued_at_ms)
    .bind(expires_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let inserted = inserted.rows_affected() == 1;
    let savepoint_action = if inserted {
        "RELEASE SAVEPOINT runner_enrollment_token_create"
    } else {
        // Also removes a group proposed by the losing concurrent insertion.
        "ROLLBACK TO SAVEPOINT runner_enrollment_token_create"
    };
    sqlx::query(savepoint_action)
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?;
    Ok(inserted.then_some((group_id, expires_at_ms)))
}

async fn finish_enrollment_conflict(
    transaction: Transaction<'_, Postgres>,
    actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
) -> Result<ManagementMutationOutcome<RunnerEnrollmentTokenRecord>, ManagementRepositoryError> {
    super::finish_denied(
        transaction,
        actor,
        descriptor,
        ManagementMutationOutcome::AlreadyExists,
    )
    .await
}

async fn append_installation_bootstrap_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    installation: &ConfiguredDeploymentInstallationProof,
    enrollment_id: Uuid,
    outcome: &'static str,
) -> Result<(), ManagementRepositoryError> {
    let occurred_at_ms = database_time_milliseconds(transaction)
        .await
        .map_err(map_database_error)?;
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id,tenant_id,occurred_at_ms,actor_kind,action,outcome,
            resource_kind,resource_id,request_id
        ) VALUES ($1,$2,$3,'system',$4,$5,$6,$7,$8)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(installation.tenant_id.as_str())
    .bind(occurred_at_ms)
    .bind(ACTION_TOKEN_BOOTSTRAP)
    .bind(outcome)
    .bind(RESOURCE_ENROLLMENT)
    .bind(enrollment_id.hyphenated().to_string())
    .bind(enrollment_id.hyphenated().to_string())
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

fn map_installation_error(error: InstallationRepositoryError) -> ManagementRepositoryError {
    match error {
        InstallationRepositoryError::Unavailable => ManagementRepositoryError::Unavailable,
        InstallationRepositoryError::CorruptData => ManagementRepositoryError::CorruptData,
        InstallationRepositoryError::InvalidRequest
        | InstallationRepositoryError::NotArmed
        | InstallationRepositoryError::ProofRejected
        | InstallationRepositoryError::Expired
        | InstallationRepositoryError::AlreadyBound
        | InstallationRepositoryError::AlreadyConfigured
        | InstallationRepositoryError::VersionConflict
        | InstallationRepositoryError::IdentityConflict
        | InstallationRepositoryError::CredentialCustody => {
            ManagementRepositoryError::InvalidRequest
        }
    }
}

fn enrolled_runner_external_identity(runner_id: Uuid) -> String {
    format!("automata:runner:{}", runner_id.hyphenated())
}

async fn ensure_runner_group(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    group: &str,
    now_ms: i64,
) -> Result<Uuid, ManagementRepositoryError> {
    let proposed = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO runner_groups (id,tenant_id,name,normalized_name,routing_policy,created_at_ms,updated_at_ms)
        VALUES ($1,$2,$3,$3,'{}'::jsonb,$4,$4)
        ON CONFLICT (tenant_id,normalized_name) DO NOTHING
        ",
    )
    .bind(proposed)
    .bind(tenant_id)
    .bind(group)
    .bind(now_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    sqlx::query_scalar(
        "SELECT id FROM runner_groups WHERE tenant_id=$1 AND normalized_name=$2 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(group)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)
}

async fn load_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    token_sha256: &[u8; 32],
    lock: bool,
) -> Result<Option<EnrollmentRow>, ManagementRepositoryError> {
    let row = if lock {
        sqlx::query_as::<_, EnrollmentRow>(
            r"
            SELECT token.id,token.tenant_id,token.runner_group_id,
                   groups.name AS runner_group,token.issued_at_ms,
                   token.last_refreshed_at_ms,token.expires_at_ms,
                   token.consumed_at_ms,token.consumed_runner_id,
                   token.redeem_operation_id,token.redeem_request_sha256,
                   token.redeem_response,token.redeem_certificate_expires_at_seconds
            FROM runner_enrollment_tokens AS token
            JOIN runner_groups AS groups
              ON groups.tenant_id=token.tenant_id
             AND groups.id=token.runner_group_id
            WHERE token.token_sha256=$1
            FOR UPDATE
            ",
        )
        .bind(token_sha256.as_slice())
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, EnrollmentRow>(
            r"
            SELECT token.id,token.tenant_id,token.runner_group_id,
                   groups.name AS runner_group,token.issued_at_ms,
                   token.last_refreshed_at_ms,token.expires_at_ms,
                   token.consumed_at_ms,token.consumed_runner_id,
                   token.redeem_operation_id,token.redeem_request_sha256,
                   token.redeem_response,token.redeem_certificate_expires_at_seconds
            FROM runner_enrollment_tokens AS token
            JOIN runner_groups AS groups
              ON groups.tenant_id=token.tenant_id
             AND groups.id=token.runner_group_id
            WHERE token.token_sha256=$1
            ",
        )
        .bind(token_sha256.as_slice())
        .fetch_optional(&mut **transaction)
        .await
    };
    row.map_err(map_database_error)
}

fn valid_group(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_GROUP_CHARACTERS
        && value.trim() == value
        && value == value.to_lowercase()
        && !value.chars().any(char::is_control)
}

fn valid_runner_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::{human::TenantId, installation::InstallationRevision};

    use super::*;

    fn installation_proof() -> ConfiguredDeploymentInstallationProof {
        ConfiguredDeploymentInstallationProof {
            installation_authority_sha256: [1; 32],
            bootstrap_operation_id: Uuid::new_v4(),
            tenant_id: TenantId::new("local-installation").expect("tenant"),
            tenant_display_name: "Local installation".to_owned(),
            bootstrap_audit_event_id: Uuid::new_v4(),
            configured_at_ms: 1,
            installation_revision: InstallationRevision::new(2).expect("revision"),
        }
    }

    #[test]
    fn installation_request_requires_exact_identity_digest_and_one_hour_lifetime() {
        let installation = installation_proof();
        let group = RunnerGroup::new("default").expect("group");
        for (enrollment_id, digest, lifetime_ms) in [
            (
                Uuid::nil(),
                [1_u8; 32],
                INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
            ),
            (
                Uuid::new_v4(),
                [0_u8; 32],
                INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
            ),
            (
                Uuid::new_v4(),
                [1_u8; 32],
                INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS - 1,
            ),
        ] {
            assert!(
                EnsureInstallationBootstrapRunnerEnrollmentToken::new(
                    installation.clone(),
                    enrollment_id,
                    digest,
                    group.clone(),
                    lifetime_ms,
                )
                .is_err()
            );
        }
        let request = EnsureInstallationBootstrapRunnerEnrollmentToken::new(
            installation,
            Uuid::new_v4(),
            [7_u8; 32],
            group,
            INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
        )
        .expect("valid request");
        let debug = format!("{request:?}");
        assert!(!debug.contains("token_sha256"));
        assert!(!debug.contains("7, 7"));
    }
}
