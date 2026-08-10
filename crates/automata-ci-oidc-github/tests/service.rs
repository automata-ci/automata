mod support;

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_oidc_github::{
    AuthorizedOidcIssuance, GithubOidcApi, InMemoryOidcRepository, InMemoryOidcRepositoryLimits,
    OidcAudience, OidcClock, OidcClockError, OidcIdToken, OidcIssuance, OidcIssuanceRepository,
    OidcRepositoryError, OidcRepositoryErrorKind, OidcServiceErrorKind, ReserveOidcIssuance,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};

use support::{
    NOW_SECONDS, TEST_KEY_ID, TEST_REPLACEMENT_KEY_ID, TEST_REPLACEMENT_RSA_MODULUS,
    TEST_RSA_EXPONENT, TEST_RSA_MODULUS, authorized_authority, configured_service,
    configured_service_with_limits, configured_service_with_repository,
    configured_service_with_repository_and_signing_keyring, decode_token,
    prepublished_signing_keyring,
};

fn token_signature_is_valid(token: &OidcIdToken, modulus: &str) -> bool {
    let mut segments = token.expose_secret().split('.');
    let encoded_header = segments.next().expect("header");
    let encoded_claims = segments.next().expect("claims");
    let signature = URL_SAFE_NO_PAD
        .decode(segments.next().expect("signature"))
        .expect("signature encoding");
    assert!(segments.next().is_none());
    let modulus = URL_SAFE_NO_PAD.decode(modulus).expect("modulus encoding");
    let exponent = URL_SAFE_NO_PAD
        .decode(TEST_RSA_EXPONENT)
        .expect("exponent encoding");
    RsaPublicKeyComponents {
        n: &modulus,
        e: &exponent,
    }
    .verify(
        &RSA_PKCS1_2048_8192_SHA256,
        format!("{encoded_header}.{encoded_claims}").as_bytes(),
        &signature,
    )
    .is_ok()
}

#[derive(Clone, Copy, Debug)]
enum HostileTimeShape {
    ExcessiveSignedLifetime,
    NotBeforePredatesBearer,
    AuthorizationPredatesInitialSample,
    TokenTimesFollowAuthorization,
    ExpiredAtAuthorization,
}

#[derive(Debug)]
struct HostileTimeRepository(HostileTimeShape);

#[async_trait]
impl OidcIssuanceRepository for HostileTimeRepository {
    async fn reserve(
        &self,
        request: ReserveOidcIssuance,
    ) -> Result<AuthorizedOidcIssuance, OidcRepositoryError> {
        let authority = authorized_authority();
        let (issued_at_seconds, not_before_seconds, expires_at_seconds, authorized_at_seconds) =
            match self.0 {
                HostileTimeShape::ExcessiveSignedLifetime => (
                    request.request_issued_at_seconds(),
                    request.request_issued_at_seconds(),
                    request.maximum_expires_at_seconds(),
                    request.observed_at_seconds(),
                ),
                HostileTimeShape::NotBeforePredatesBearer => (
                    request.observed_at_seconds(),
                    request
                        .request_issued_at_seconds()
                        .checked_sub(1)
                        .expect("positive request-bearer issuance time"),
                    request.maximum_expires_at_seconds(),
                    request.observed_at_seconds(),
                ),
                HostileTimeShape::AuthorizationPredatesInitialSample => (
                    request.request_issued_at_seconds(),
                    request.request_issued_at_seconds(),
                    request.maximum_expires_at_seconds(),
                    request
                        .observed_at_seconds()
                        .checked_sub(1)
                        .expect("positive observation time"),
                ),
                HostileTimeShape::TokenTimesFollowAuthorization => (
                    request
                        .observed_at_seconds()
                        .checked_add(1)
                        .expect("bounded observation time"),
                    request
                        .observed_at_seconds()
                        .checked_add(1)
                        .expect("bounded observation time"),
                    request.maximum_expires_at_seconds(),
                    request.observed_at_seconds(),
                ),
                HostileTimeShape::ExpiredAtAuthorization => (
                    request.observed_at_seconds(),
                    request.observed_at_seconds(),
                    request
                        .observed_at_seconds()
                        .checked_add(1)
                        .expect("bounded observation time"),
                    request
                        .observed_at_seconds()
                        .checked_add(1)
                        .expect("bounded observation time"),
                ),
            };
        let audience = request
            .requested_audience()
            .unwrap_or_else(|| authority.default_audience())
            .clone();
        let issuance = OidcIssuance::new(
            request.authority_id(),
            request.proposed_token_id(),
            request.proposed_signing_key_id().clone(),
            authority.subject().clone(),
            audience,
            authority.additional_claims().clone(),
            issued_at_seconds,
            not_before_seconds,
            expires_at_seconds,
        )
        .map_err(|_| OidcRepositoryError::new(OidcRepositoryErrorKind::CorruptData))?;
        Ok(AuthorizedOidcIssuance::new(issuance, authorized_at_seconds))
    }
}

struct SentinelRepository;

impl fmt::Debug for SentinelRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("repository-credential-sentinel")
    }
}

#[async_trait]
impl OidcIssuanceRepository for SentinelRepository {
    async fn reserve(
        &self,
        _request: ReserveOidcIssuance,
    ) -> Result<AuthorizedOidcIssuance, OidcRepositoryError> {
        Err(OidcRepositoryError::new(
            OidcRepositoryErrorKind::Unavailable,
        ))
    }
}

struct SentinelClock;

impl fmt::Debug for SentinelClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("clock-credential-sentinel")
    }
}

impl OidcClock for SentinelClock {
    fn now_seconds(&self) -> Result<u64, OidcClockError> {
        Ok(NOW_SECONDS)
    }
}

#[tokio::test]
async fn service_mints_verified_rs256_claims_and_exact_unexpired_replay() {
    let (service, _, bearer) = configured_service();
    let first = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect("first token");
    let replay = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS + 1)
        .await
        .expect("replayed token");
    assert_eq!(first.expose_secret(), replay.expose_secret());

    let (header, claims) = decode_token(&first);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], TEST_KEY_ID);
    assert_eq!(claims["iss"], "https://oidc.example.invalid/");
    assert_eq!(claims["sub"], "repo:example/project:ref:refs/heads/main");
    assert_eq!(claims["aud"], "https://example.invalid/owner");
    assert_eq!(claims["iat"], NOW_SECONDS);
    assert_eq!(claims["nbf"], NOW_SECONDS);
    assert_eq!(claims["exp"], NOW_SECONDS + 300);
    assert_eq!(claims["ref"], "refs/heads/main");
    assert_eq!(claims["repository_id"], "123456");
    assert!(
        claims["jti"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    let advertised = service.supported_claims().as_slice();
    for claim_name in claims.as_object().expect("claims object").keys() {
        assert!(advertised.iter().any(|name| name == claim_name));
    }

    assert!(token_signature_is_valid(&first, TEST_RSA_MODULUS));
}

#[tokio::test]
async fn active_key_rotation_applies_only_to_new_issuances() {
    let repository = Arc::new(InMemoryOidcRepository::default());
    repository
        .upsert_authority(authorized_authority())
        .expect("insert authority");
    let (old_active_service, bearer) = configured_service_with_repository_and_signing_keyring(
        repository.clone(),
        prepublished_signing_keyring(TEST_KEY_ID),
    );
    let before_rotation = old_active_service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect("old-active issuance");

    let (replacement_active_service, _) = configured_service_with_repository_and_signing_keyring(
        repository,
        prepublished_signing_keyring(TEST_REPLACEMENT_KEY_ID),
    );
    let after_rotation = replacement_active_service
        .mint(
            bearer.expose_secret(),
            Some(OidcAudience::new("rotation-audience").expect("audience")),
            NOW_SECONDS + 1,
        )
        .await
        .expect("replacement-active issuance");

    let (old_header, _) = decode_token(&before_rotation);
    let (replacement_header, _) = decode_token(&after_rotation);
    assert_eq!(old_header["kid"], TEST_KEY_ID);
    assert_eq!(replacement_header["kid"], TEST_REPLACEMENT_KEY_ID);
    assert!(token_signature_is_valid(&before_rotation, TEST_RSA_MODULUS));
    assert!(token_signature_is_valid(
        &after_rotation,
        TEST_REPLACEMENT_RSA_MODULUS
    ));
    assert!(!token_signature_is_valid(&after_rotation, TEST_RSA_MODULUS));
}

#[tokio::test]
async fn replay_after_rotation_is_byte_exact_and_pinned_to_the_old_key() {
    let repository = Arc::new(InMemoryOidcRepository::default());
    repository
        .upsert_authority(authorized_authority())
        .expect("insert authority");
    let (old_active_service, bearer) = configured_service_with_repository_and_signing_keyring(
        repository.clone(),
        prepublished_signing_keyring(TEST_KEY_ID),
    );
    let first = old_active_service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect("old-key issuance");

    let (replacement_active_service, _) = configured_service_with_repository_and_signing_keyring(
        repository,
        prepublished_signing_keyring(TEST_REPLACEMENT_KEY_ID),
    );
    let replay = replacement_active_service
        .mint(bearer.expose_secret(), None, NOW_SECONDS + 1)
        .await
        .expect("old-key replay after rotation");

    assert_eq!(first.expose_secret(), replay.expose_secret());
    let (header, _) = decode_token(&replay);
    assert_eq!(header["kid"], TEST_KEY_ID);
    assert!(token_signature_is_valid(&replay, TEST_RSA_MODULUS));
    assert!(!token_signature_is_valid(
        &replay,
        TEST_REPLACEMENT_RSA_MODULUS
    ));
}

#[tokio::test]
async fn custom_audience_is_caller_controlled_but_identity_claims_are_not() {
    let (service, repository, bearer) = configured_service();
    let custom = service
        .mint(
            bearer.expose_secret(),
            Some(OidcAudience::new("api://cloud-exchange").expect("custom audience")),
            NOW_SECONDS,
        )
        .await
        .expect("custom token");
    let (_, claims) = decode_token(&custom);
    assert_eq!(claims["aud"], "api://cloud-exchange");
    assert_eq!(claims["sub"], "repo:example/project:ref:refs/heads/main");
    assert_eq!(claims["repository_id"], "123456");

    repository
        .revoke_authority(support::authority_id())
        .expect("revoke authority");
    let error = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS + 1)
        .await
        .expect_err("revoked authority");
    assert_eq!(error.kind(), OidcServiceErrorKind::Unauthorized);
}

#[tokio::test]
async fn malformed_expired_and_unknown_request_credentials_are_non_disclosing() {
    let (service, _, bearer) = configured_service();
    for credential in ["not-a-jwt", "header.payload.signature"] {
        let error = service
            .mint(credential, None, NOW_SECONDS)
            .await
            .expect_err("invalid credential");
        assert_eq!(error.kind(), OidcServiceErrorKind::Unauthorized);
        assert!(!error.to_string().contains(credential));
    }
    let error = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS + 901)
        .await
        .expect_err("expired credential");
    assert_eq!(error.kind(), OidcServiceErrorKind::Unauthorized);
}

#[tokio::test]
async fn bounded_reference_repository_fails_closed_when_unexpired_capacity_is_full() {
    let limits = InMemoryOidcRepositoryLimits::new(1, 1).expect("repository limits");
    let (service, _, bearer) = configured_service_with_limits(limits);
    service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect("first issuance");
    let error = service
        .mint(
            bearer.expose_secret(),
            Some(OidcAudience::new("second-audience").expect("audience")),
            NOW_SECONDS,
        )
        .await
        .expect_err("issuance capacity");
    assert_eq!(error.kind(), OidcServiceErrorKind::ResourceExhausted);
}

#[tokio::test]
async fn service_rejects_repository_issuance_whose_signed_interval_exceeds_configured_lifetime() {
    let (service, bearer) = configured_service_with_repository(Arc::new(HostileTimeRepository(
        HostileTimeShape::ExcessiveSignedLifetime,
    )));
    let error = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect_err("excessive signed validity interval");
    assert_eq!(error.kind(), OidcServiceErrorKind::Internal);
}

#[tokio::test]
async fn service_rejects_repository_issuance_valid_before_request_bearer() {
    let (service, bearer) = configured_service_with_repository(Arc::new(HostileTimeRepository(
        HostileTimeShape::NotBeforePredatesBearer,
    )));
    let error = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect_err("not-before predates request bearer");
    assert_eq!(error.kind(), OidcServiceErrorKind::Internal);
}

#[tokio::test]
async fn service_rejects_authorization_time_before_initial_trusted_sample() {
    let (service, bearer) = configured_service_with_repository(Arc::new(HostileTimeRepository(
        HostileTimeShape::AuthorizationPredatesInitialSample,
    )));
    let error = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect_err("authorization predates HTTP clock sample");
    assert_eq!(error.kind(), OidcServiceErrorKind::Internal);
}

#[tokio::test]
async fn service_rejects_token_times_after_repository_authorization() {
    let (service, bearer) = configured_service_with_repository(Arc::new(HostileTimeRepository(
        HostileTimeShape::TokenTimesFollowAuthorization,
    )));
    let error = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect_err("token times follow authorization");
    assert_eq!(error.kind(), OidcServiceErrorKind::Internal);
}

#[tokio::test]
async fn service_rejects_issuance_expired_at_repository_authorization() {
    let (service, bearer) = configured_service_with_repository(Arc::new(HostileTimeRepository(
        HostileTimeShape::ExpiredAtAuthorization,
    )));
    let error = service
        .mint(bearer.expose_secret(), None, NOW_SECONDS)
        .await
        .expect_err("issuance expired at authorization");
    assert_eq!(error.kind(), OidcServiceErrorKind::Internal);
}

#[test]
fn service_and_api_debug_do_not_delegate_to_injected_boundaries() {
    let (service, _) = configured_service_with_repository(Arc::new(SentinelRepository));
    let service_debug = format!("{service:?}");
    assert!(!service_debug.contains("repository-credential-sentinel"));
    assert!(service_debug.contains("repository: \"[injected]\""));

    let api = GithubOidcApi::new(service, Arc::new(SentinelClock));
    let api_debug = format!("{api:?}");
    assert!(!api_debug.contains("repository-credential-sentinel"));
    assert!(!api_debug.contains("clock-credential-sentinel"));
    assert!(api_debug.contains("service: \"[configured]\""));
    assert!(api_debug.contains("clock: \"[injected]\""));
}
