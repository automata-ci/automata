use std::{
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use automata_ci_core::{GitObjectAlgorithm, GitObjectId, Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_key_management::SecretBytes;
use automata_ci_provider::{
    AuthenticatedProviderWebhook, CompleteProviderDelivery, DeliveryAdapter,
    DeliveryAdapterRegistry, ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId,
    ExternalRepositoryIdentity, NormalizedTrigger, ProviderArchiveLimits,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
    ProviderDefaultBranch, ProviderDeliveryClaimFence, ProviderDeliveryDraft, ProviderDeliveryId,
    ProviderDeliveryNormalization, ProviderDeliveryObservations, ProviderDeliveryRejection,
    ProviderDeliveryWorkerId, ProviderEventName, ProviderGitRef, ProviderGitRefKind,
    ProviderInstanceId, ProviderLifecycleState, ProviderRepository, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderSecret, ProviderSecretGeneration,
    ProviderSecretName, ProviderTypeId, ProviderWebhookAuthenticationError,
    ProviderWebhookAuthenticationRequest, ProviderWebhookEndpointId,
    ProviderWebhookEndpointManifest, ProviderWebhookEndpointRevision, ProviderWebhookEndpointState,
    ProviderWebhookHeaderName, ProviderWebhookHeaders, ProviderWebhookMethod,
    ProviderWebhookRequest, ProviderWebhookSecretCandidates, ProviderWebhookSecretReference,
    ProviderWebhookSignatureEvidence, ProviderWorkflowSource, PushCommitEvidence, PushTrigger,
    RenewProviderDelivery, RepositoryVisibility,
};
use sha2::{Digest as _, Sha256};

const OLD_SECRET: &[u8] = b"old-webhook-secret";
const NEW_SECRET: &[u8] = b"new-webhook-secret";

#[derive(Debug)]
struct FakeAdapter {
    provider_type: ProviderTypeId,
    header_names: Vec<ProviderWebhookHeaderName>,
    parsed: Arc<AtomicBool>,
}

impl FakeAdapter {
    fn new(provider_type: &str, parsed: Arc<AtomicBool>) -> Self {
        Self {
            provider_type: ProviderTypeId::new(provider_type).expect("provider type"),
            header_names: vec![
                ProviderWebhookHeaderName::new("x-fake-signature").expect("signature header"),
            ],
            parsed,
        }
    }
}

impl DeliveryAdapter for FakeAdapter {
    fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    fn selected_header_names(&self) -> &[ProviderWebhookHeaderName] {
        &self.header_names
    }

    fn authenticate(
        &self,
        authentication: ProviderWebhookAuthenticationRequest,
    ) -> Result<AuthenticatedProviderWebhook, ProviderWebhookAuthenticationError> {
        let signature_name = ProviderWebhookHeaderName::new("x-fake-signature")
            .map_err(|_| ProviderWebhookAuthenticationError::InvalidEvidence)?;
        let supplied = authentication
            .request()
            .headers()
            .get(&signature_name)
            .ok_or(ProviderWebhookAuthenticationError::InvalidEvidence)?;
        let accepted = authentication.candidates().iter().find(|candidate| {
            let mut hash = Sha256::new();
            hash.update(candidate.expose_secret());
            hash.update(authentication.request().body());
            hex_digest(&hash.finalize()).as_bytes() == supplied
        });
        let accepted = accepted.ok_or(ProviderWebhookAuthenticationError::InvalidSignature)?;
        let accepted = accepted.reference().clone();
        let evidence = ProviderWebhookSignatureEvidence::new("fake-sha256", accepted)
            .map_err(|_| ProviderWebhookAuthenticationError::InvalidEvidence)?;
        AuthenticatedProviderWebhook::new(authentication.into_request(), evidence)
            .map_err(|_| ProviderWebhookAuthenticationError::InvalidEvidence)
    }

    fn normalize(
        &self,
        authenticated: AuthenticatedProviderWebhook,
    ) -> ProviderDeliveryNormalization {
        self.parsed.store(true, Ordering::SeqCst);
        let parsed: serde_json::Value = match serde_json::from_slice(authenticated.request().body())
        {
            Ok(value) => value,
            Err(_) => {
                return rejected(authenticated, ProviderDeliveryRejection::InvalidPayload);
            }
        };
        if parsed.get("kind").and_then(serde_json::Value::as_str) != Some("push") {
            return rejected(authenticated, ProviderDeliveryRejection::UnknownEvent);
        }
        let instance_id = authenticated.request().endpoint().instance_id();
        let repository = ProviderRepository::new(
            ExternalRepositoryIdentity::new(
                instance_id,
                ExternalRepositoryId::new("repository-42").expect("repository ID"),
            ),
            ProviderRepositoryPath::new("owner/repository").expect("repository path"),
            RepositoryVisibility::Private,
        );
        let trigger = PushTrigger::new(
            repository,
            ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("branch"),
            Some(object('a')),
            Some(object('b')),
            PushCommitEvidence::complete([object('b')]).expect("commit evidence"),
            false,
            None,
        )
        .expect("push");
        ProviderDeliveryNormalization::Accepted(Box::new(
            ProviderDeliveryDraft::new(
                ProviderDeliveryId::new(),
                ExternalDeliveryIdentity::new(
                    instance_id,
                    ExternalDeliveryId::new("delivery-1").expect("delivery ID"),
                ),
                ProviderEventName::new("push").expect("event type"),
                authenticated,
                &NormalizedTrigger::Push(trigger),
                ProviderDeliveryObservations::new(br#"{"fixture":"fake"}"#.to_vec())
                    .expect("observations"),
            )
            .expect("delivery draft"),
        ))
    }
}

fn rejected(
    authenticated: AuthenticatedProviderWebhook,
    reason: ProviderDeliveryRejection,
) -> ProviderDeliveryNormalization {
    let instance_id = authenticated.request().endpoint().instance_id();
    ProviderDeliveryNormalization::Rejected(Box::new(
        automata_ci_provider::RejectedProviderDeliveryDraft::new(
            ProviderDeliveryId::new(),
            ExternalDeliveryIdentity::new(
                instance_id,
                ExternalDeliveryId::new("delivery-1").expect("delivery ID"),
            ),
            ProviderEventName::new("fake").expect("event type"),
            authenticated,
            None,
            reason,
            ProviderDeliveryObservations::new(Vec::new()).expect("observations"),
        )
        .expect("rejected draft"),
    ))
}

fn endpoint(
    provider_type: &str,
    instance_id: ProviderInstanceId,
) -> ProviderWebhookEndpointManifest {
    ProviderWebhookEndpointManifest::new(
        ProviderWebhookEndpointId::new(),
        ProviderWebhookEndpointRevision::new(1).expect("endpoint revision"),
        ProviderWebhookEndpointState::Active,
        ProviderTypeId::new(provider_type).expect("provider type"),
        instance_id,
        ProviderConfigurationRevision::new(2).expect("provider revision"),
        ProviderConnectionId::new(),
        ProviderConnectionRevision::new(1).expect("connection revision"),
        1_024,
        30 * 24 * 60 * 60 * 1_000,
        vec![
            ProviderWebhookSecretReference::new(
                ProviderConfigurationRevision::new(1).expect("old revision"),
                ProviderSecretName::new("webhook-secret").expect("secret name"),
                ProviderSecretGeneration::new(1).expect("old generation"),
            ),
            ProviderWebhookSecretReference::new(
                ProviderConfigurationRevision::new(2).expect("new revision"),
                ProviderSecretName::new("webhook-secret").expect("secret name"),
                ProviderSecretGeneration::new(2).expect("new generation"),
            ),
        ],
        UnixMillis::new(1_000),
        None,
    )
    .expect("endpoint")
}

fn candidates(endpoint: &ProviderWebhookEndpointManifest) -> ProviderWebhookSecretCandidates {
    ProviderWebhookSecretCandidates::new(
        endpoint,
        [
            (
                ProviderConfigurationRevision::new(1).expect("old revision"),
                ProviderSecret::new(
                    ProviderSecretName::new("webhook-secret").expect("secret name"),
                    ProviderSecretGeneration::new(1).expect("old generation"),
                    SecretBytes::new(OLD_SECRET.to_vec()).expect("old secret"),
                ),
            ),
            (
                ProviderConfigurationRevision::new(2).expect("new revision"),
                ProviderSecret::new(
                    ProviderSecretName::new("webhook-secret").expect("secret name"),
                    ProviderSecretGeneration::new(2).expect("new generation"),
                    SecretBytes::new(NEW_SECRET.to_vec()).expect("new secret"),
                ),
            ),
        ],
    )
    .expect("candidate set")
}

fn request(
    endpoint: ProviderWebhookEndpointManifest,
    body: &[u8],
    secret: &[u8],
) -> ProviderWebhookRequest {
    let mut hash = Sha256::new();
    hash.update(secret);
    hash.update(body);
    let signature = hex_digest(&hash.finalize()).into_bytes();
    let connection = connection(&endpoint);
    ProviderWebhookRequest::new(
        endpoint,
        connection,
        ProviderWebhookMethod::Post,
        ProviderWebhookHeaders::new([(
            ProviderWebhookHeaderName::new("x-fake-signature").expect("header name"),
            signature,
        )])
        .expect("headers"),
        body.to_vec(),
        UnixMillis::new(2_000),
    )
    .expect("request")
}

fn connection(endpoint: &ProviderWebhookEndpointManifest) -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        ExternalRepositoryIdentity::new(
            endpoint.instance_id(),
            ExternalRepositoryId::new("repository-42").expect("repository ID"),
        ),
        endpoint.provider_revision(),
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".forgejo/workflows").expect("workflow source"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([5; 32]),
        ),
        ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024).expect("archive limits"),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).expect("policy schema"),
            b"{}".to_vec(),
        )
        .expect("adapter policy"),
    );
    ProviderConnectionManifest::new(
        endpoint.connection_id(),
        endpoint.connection_revision(),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(1_000),
        Some(UnixMillis::new(1_000)),
        None,
    )
    .expect("connection manifest")
}

fn object(hex: char) -> GitObjectId {
    GitObjectId::from_hex(GitObjectAlgorithm::Sha1, &hex.to_string().repeat(40)).expect("object")
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[test]
fn invalid_signature_never_reaches_payload_parsing() {
    let parsed = Arc::new(AtomicBool::new(false));
    let adapter = FakeAdapter::new("forgejo", Arc::clone(&parsed));
    let endpoint = endpoint("forgejo", ProviderInstanceId::new());
    let candidates = candidates(&endpoint);
    let request = request(endpoint, b"not-json", b"wrong-secret");

    assert_eq!(
        adapter
            .authenticate(
                ProviderWebhookAuthenticationRequest::new(request, candidates)
                    .expect("authentication request"),
            )
            .unwrap_err(),
        ProviderWebhookAuthenticationError::InvalidSignature
    );
    assert!(!parsed.load(Ordering::SeqCst));
}

#[test]
fn rotation_records_the_exact_generation_that_verified() {
    let adapter = FakeAdapter::new("forgejo", Arc::new(AtomicBool::new(false)));
    let endpoint = endpoint("forgejo", ProviderInstanceId::new());
    let candidates = candidates(&endpoint);
    let authenticated = adapter
        .authenticate(
            ProviderWebhookAuthenticationRequest::new(
                request(endpoint, br#"{"kind":"push"}"#, OLD_SECRET),
                candidates,
            )
            .expect("authentication request"),
        )
        .expect("old secret accepted");

    assert_eq!(authenticated.signature().secret().generation().get(), 1);
    assert_eq!(
        authenticated
            .signature()
            .secret()
            .configuration_revision()
            .get(),
        1
    );
}

#[test]
fn registry_is_exact_and_instances_do_not_share_secret_candidates() {
    let forgejo = Arc::new(FakeAdapter::new(
        "forgejo",
        Arc::new(AtomicBool::new(false)),
    ));
    let github = Arc::new(FakeAdapter::new("github", Arc::new(AtomicBool::new(false))));
    let registry = DeliveryAdapterRegistry::new([
        Arc::clone(&forgejo) as Arc<dyn DeliveryAdapter>,
        Arc::clone(&github) as Arc<dyn DeliveryAdapter>,
    ])
    .expect("registry");
    let first = endpoint("forgejo", ProviderInstanceId::new());
    let second = endpoint("forgejo", ProviderInstanceId::new());

    assert_eq!(
        registry.resolve(&first).expect("adapter").provider_type(),
        forgejo.provider_type()
    );
    let first_candidates = candidates(&first);
    let second_request = request(second, br#"{"kind":"push"}"#, OLD_SECRET);
    assert!(ProviderWebhookAuthenticationRequest::new(second_request, first_candidates).is_err());
}

#[test]
fn authenticated_invalid_json_is_recorded_without_admission() {
    let parsed = Arc::new(AtomicBool::new(false));
    let adapter = FakeAdapter::new("forgejo", Arc::clone(&parsed));
    let endpoint = endpoint("forgejo", ProviderInstanceId::new());
    let candidates = candidates(&endpoint);
    let authenticated = adapter
        .authenticate(
            ProviderWebhookAuthenticationRequest::new(
                request(endpoint, b"not-json", NEW_SECRET),
                candidates,
            )
            .expect("authentication request"),
        )
        .expect("signature");

    assert!(matches!(
        adapter.normalize(authenticated),
        ProviderDeliveryNormalization::Rejected(_)
    ));
    assert!(parsed.load(Ordering::SeqCst));
}

#[test]
fn worker_fence_rejects_mutations_before_claim_or_at_expiry() {
    let fence = ProviderDeliveryClaimFence::new(
        ProviderDeliveryId::new(),
        ProviderDeliveryWorkerId::new(),
        1,
        UnixMillis::new(100),
        UnixMillis::new(200),
    )
    .expect("fence");

    assert!(CompleteProviderDelivery::new(fence, UnixMillis::new(99)).is_err());
    assert!(CompleteProviderDelivery::new(fence, UnixMillis::new(200)).is_err());
    assert!(CompleteProviderDelivery::new(fence, UnixMillis::new(150)).is_ok());
}

#[test]
fn claim_renewal_must_strictly_extend_a_live_fence() {
    let fence = ProviderDeliveryClaimFence::new(
        ProviderDeliveryId::new(),
        ProviderDeliveryWorkerId::new(),
        1,
        UnixMillis::new(1_000),
        UnixMillis::new(2_000),
    )
    .expect("fence");
    let renewal =
        RenewProviderDelivery::new(fence, UnixMillis::new(1_500), 1_000).expect("strict extension");
    assert_eq!(renewal.fence(), fence);
    assert_eq!(renewal.renewed_at(), UnixMillis::new(1_500));
    assert_eq!(renewal.lease_millis(), 1_000);
    assert!(RenewProviderDelivery::new(fence, UnixMillis::new(1_000), 1_000).is_err());
    assert!(RenewProviderDelivery::new(fence, UnixMillis::new(2_000), 1_000).is_err());

    let near_total_limit = ProviderDeliveryClaimFence::new(
        fence.delivery_id(),
        fence.worker_id(),
        fence.token(),
        UnixMillis::new(1_000),
        UnixMillis::new(3_500_000),
    )
    .expect("claim below total lifetime limit");
    assert!(
        RenewProviderDelivery::new(near_total_limit, UnixMillis::new(3_400_000), 900_000).is_err()
    );
}
