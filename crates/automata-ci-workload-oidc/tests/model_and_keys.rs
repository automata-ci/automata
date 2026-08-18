use crate::support;

use automata_ci_workload_oidc::{
    AuthorizedOidcIssuance, MAXIMUM_ID_TOKEN_LIFETIME_SECONDS, MAXIMUM_OIDC_KEYS_PER_KEYRING,
    MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS, MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
    MAXIMUM_SUPPORTED_ADDITIONAL_CLAIMS, OidcAudience, OidcClaimSet, OidcIssuance, OidcIssuer,
    OidcKeyId, OidcModelError, OidcSupportedClaims, OidcTokenId, OidcTokenLifetime,
    OidcTokenLifetimeError, RequestBearerConfig, RequestBearerError, RequestBearerKey,
    RequestBearerKeyring, Rs256KeyError, Rs256SigningKey, RsaPublicJwk,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use support::{
    NOW_SECONDS, TEST_KEY_ID, TEST_REPLACEMENT_KEY_ID, TEST_REPLACEMENT_RSA_MODULUS,
    TEST_RSA_EXPONENT, TEST_RSA_MODULUS, authority_id, authorized_authority,
    prepublished_signing_keyring, private_key_pem, request_keyring,
};

#[test]
fn authorized_issuance_exposes_current_evidence_and_redacts_debug_output() {
    let authority = authorized_authority();
    let issuance = OidcIssuance::new(
        authority.authority_id(),
        OidcTokenId::from_uuid(Uuid::from_u128(1)).expect("token ID"),
        OidcKeyId::new(TEST_KEY_ID).expect("signing key ID"),
        authority.subject().clone(),
        authority.default_audience().clone(),
        authority.additional_claims().clone(),
        NOW_SECONDS,
        NOW_SECONDS,
        NOW_SECONDS + 300,
    )
    .expect("issuance");
    let authorized = AuthorizedOidcIssuance::new(issuance.clone(), NOW_SECONDS + 1);

    assert_eq!(authorized.issuance(), &issuance);
    assert_eq!(authorized.authorized_at_seconds(), NOW_SECONDS + 1);
    assert_eq!(
        format!("{authorized:?}"),
        "AuthorizedOidcIssuance([redacted])"
    );
}

#[test]
fn issuer_audience_and_claim_models_fail_closed_at_their_bounds() {
    assert_eq!(
        OidcIssuer::https(Url::parse("http://issuer.example/").expect("URL")),
        Err(OidcModelError::InvalidIssuer)
    );
    assert_eq!(
        OidcIssuer::https(Url::parse("https://issuer.example/path").expect("URL")),
        Err(OidcModelError::InvalidIssuer)
    );
    assert_eq!(
        OidcIssuer::https(Url::parse("https://user@issuer.example/").expect("URL")),
        Err(OidcModelError::InvalidIssuer)
    );
    assert_eq!(
        OidcAudience::new(" \t"),
        Err(OidcModelError::InvalidAudience)
    );
    assert_eq!(
        OidcClaimSet::new([("iss".to_owned(), "replacement".to_owned())]),
        Err(OidcModelError::InvalidClaim)
    );
    assert_eq!(
        OidcClaimSet::new([
            ("repository_id".to_owned(), "1".to_owned()),
            ("repository_id".to_owned(), "2".to_owned()),
        ]),
        Err(OidcModelError::TooManyClaims)
    );
}

#[test]
fn discovery_claim_universe_is_bounded_canonical_and_excludes_registered_duplicates() {
    let supported = OidcSupportedClaims::new(["repository_id".to_owned(), "ref".to_owned()])
        .expect("supported claims");
    assert_eq!(
        supported.as_slice(),
        [
            "sub",
            "aud",
            "exp",
            "iat",
            "iss",
            "jti",
            "nbf",
            "ref",
            "repository_id",
        ]
    );
    assert!(supported.supports_additional("ref"));
    assert_eq!(
        OidcSupportedClaims::new(["iss".to_owned()]),
        Err(OidcModelError::InvalidClaim)
    );
    assert_eq!(
        OidcSupportedClaims::new(["ref".to_owned(), "ref".to_owned()]),
        Err(OidcModelError::TooManyClaims)
    );
    let excessive = (0..=MAXIMUM_SUPPORTED_ADDITIONAL_CLAIMS).map(|index| format!("claim_{index}"));
    assert_eq!(
        OidcSupportedClaims::new(excessive),
        Err(OidcModelError::TooManyClaims)
    );
}

#[test]
fn request_bearer_is_canonical_authenticated_bounded_and_redacted() {
    let keyring = request_keyring();
    let bearer = keyring
        .issue(authority_id(), NOW_SECONDS, NOW_SECONDS + 300)
        .expect("bearer");
    let verified = keyring
        .verify(bearer.expose_secret(), NOW_SECONDS + 1)
        .expect("verify bearer");
    assert_eq!(verified.authority_id(), authority_id());
    assert_eq!(verified.issued_at_seconds(), NOW_SECONDS);
    assert_eq!(verified.expires_at_seconds(), NOW_SECONDS + 300);
    assert_eq!(format!("{bearer:?}"), "OidcRequestBearer([redacted])");

    let mut tampered = bearer.expose_secret().as_bytes().to_vec();
    let signature_start = tampered
        .iter()
        .rposition(|byte| *byte == b'.')
        .expect("signature separator")
        + 1;
    tampered[signature_start] = if tampered[signature_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let tampered = String::from_utf8(tampered).expect("ASCII JWT");
    assert_eq!(
        keyring.verify(&tampered, NOW_SECONDS + 1),
        Err(RequestBearerError::Invalid)
    );
    assert_eq!(
        keyring.verify(bearer.expose_secret(), NOW_SECONDS + 331),
        Err(RequestBearerError::Expired)
    );
}

#[test]
fn request_bearer_and_id_token_lifetime_boundaries_are_independent() {
    assert_eq!(MAXIMUM_OIDC_KEYS_PER_KEYRING, 16);
    assert_eq!(MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS, 300);
    assert!(OidcTokenLifetime::from_seconds(MAXIMUM_ID_TOKEN_LIFETIME_SECONDS).is_ok());
    assert_eq!(
        OidcTokenLifetime::from_seconds(MAXIMUM_ID_TOKEN_LIFETIME_SECONDS + 1),
        Err(OidcTokenLifetimeError)
    );
    assert!(
        RequestBearerConfig::new(
            "request-issuer",
            "request-audience",
            MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
            0,
        )
        .is_ok()
    );
    assert_eq!(
        RequestBearerConfig::new(
            "request-issuer",
            "request-audience",
            MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS + 1,
            0,
        ),
        Err(RequestBearerError::Policy)
    );
    assert!(
        RequestBearerConfig::new(
            "request-issuer",
            "request-audience",
            MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
            MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS,
        )
        .is_ok()
    );
    assert_eq!(
        RequestBearerConfig::new(
            "request-issuer",
            "request-audience",
            MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
            MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS + 1,
        ),
        Err(RequestBearerError::Policy)
    );

    let keys = |count: usize| {
        (0..count).map(|index| {
            RequestBearerKey::new(
                OidcKeyId::new(format!("request-{index}")).expect("key ID"),
                &[u8::try_from(index).expect("bounded key index"); 32],
            )
            .expect("bounded request key")
        })
    };
    let active = OidcKeyId::new("request-0").expect("active key ID");
    let config = RequestBearerConfig::new(
        "request-issuer",
        "request-audience",
        MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
        0,
    )
    .expect("request config");
    assert!(
        RequestBearerKeyring::new(
            config.clone(),
            active.clone(),
            keys(MAXIMUM_OIDC_KEYS_PER_KEYRING),
        )
        .is_ok()
    );
    assert!(matches!(
        RequestBearerKeyring::new(config, active, keys(MAXIMUM_OIDC_KEYS_PER_KEYRING + 1),),
        Err(RequestBearerError::Policy)
    ));
}

#[test]
fn retained_request_key_reproduces_exact_bytes_across_active_rotation() {
    let old_key_id = OidcKeyId::new("request-old").expect("old key ID");
    let new_key_id = OidcKeyId::new("request-new").expect("new key ID");
    let old_key = RequestBearerKey::new(
        old_key_id.clone(),
        b"synthetic-old-request-key-material-at-least-thirty-two-bytes",
    )
    .expect("old key");
    let new_key = RequestBearerKey::new(
        new_key_id.clone(),
        b"synthetic-new-request-key-material-at-least-thirty-two-bytes",
    )
    .expect("new key");
    let config = RequestBearerConfig::new(
        "request-issuer",
        "request-audience",
        MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
        0,
    )
    .expect("24-hour request config");
    let keyring = RequestBearerKeyring::new(config, new_key_id.clone(), [old_key, new_key])
        .expect("rotated keyring");
    assert_eq!(keyring.active_key_id(), &new_key_id);
    assert_eq!(
        keyring.maximum_lifetime_seconds(),
        MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS
    );
    assert!(keyring.contains_key(&old_key_id));
    assert!(!keyring.contains_key(&OidcKeyId::new("request-retired").expect("retired key ID")));

    let first = keyring
        .issue_with_key_id(
            &old_key_id,
            authority_id(),
            NOW_SECONDS,
            NOW_SECONDS + MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
        )
        .expect("pinned 24-hour bearer");
    let retry = keyring
        .issue_with_key_id(
            &old_key_id,
            authority_id(),
            NOW_SECONDS,
            NOW_SECONDS + MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
        )
        .expect("pinned replay");
    assert_eq!(first.expose_secret(), retry.expose_secret());
    keyring
        .verify(first.expose_secret(), NOW_SECONDS)
        .expect("retained-key verification");
    let encoded_header = first
        .expose_secret()
        .split('.')
        .next()
        .expect("encoded header");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded_header)
            .expect("decode header"),
    )
    .expect("header JSON");
    assert_eq!(header["kid"], old_key_id.as_str());

    let active = keyring
        .issue(
            authority_id(),
            NOW_SECONDS,
            NOW_SECONDS + MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
        )
        .expect("active bearer");
    assert_ne!(active.expose_secret(), first.expose_secret());
    assert_eq!(
        keyring
            .issue_with_key_id(
                &OidcKeyId::new("request-retired").expect("retired key ID"),
                authority_id(),
                NOW_SECONDS,
                NOW_SECONDS + 300,
            )
            .expect_err("retired key"),
        RequestBearerError::MissingIssuanceKey
    );
    assert_eq!(
        keyring
            .issue_with_key_id(
                &old_key_id,
                authority_id(),
                NOW_SECONDS,
                NOW_SECONDS + MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS + 1,
            )
            .expect_err("excessive lifetime"),
        RequestBearerError::Policy
    );
}

#[test]
fn prepublished_multi_key_jwks_is_deterministically_sorted_by_key_id() {
    let keyring = prepublished_signing_keyring(TEST_KEY_ID);
    let jwks = keyring.jwks();
    let key_ids: Vec<_> = jwks
        .keys()
        .iter()
        .map(|key| key.key_id().as_str())
        .collect();
    assert_eq!(key_ids, [TEST_KEY_ID, TEST_REPLACEMENT_KEY_ID]);

    let serialized = serde_json::to_value(jwks).expect("JWKS JSON");
    assert_eq!(serialized["keys"][0]["kid"], TEST_KEY_ID);
    assert_eq!(serialized["keys"][0]["n"], TEST_RSA_MODULUS);
    assert_eq!(serialized["keys"][1]["kid"], TEST_REPLACEMENT_KEY_ID);
    assert_eq!(serialized["keys"][1]["n"], TEST_REPLACEMENT_RSA_MODULUS);
}

#[test]
fn signing_key_loader_proves_the_explicit_public_pair() {
    let jwk = RsaPublicJwk::new(
        OidcKeyId::new("matching").expect("key ID"),
        TEST_RSA_MODULUS,
        TEST_RSA_EXPONENT,
    )
    .expect("JWK");
    let private_key_pem = private_key_pem();
    Rs256SigningKey::from_pem(&private_key_pem, jwk).expect("matching pair");

    let mut mismatched_modulus = TEST_RSA_MODULUS.to_owned();
    mismatched_modulus.replace_range(..1, "2");
    let mismatched = RsaPublicJwk::new(
        OidcKeyId::new("mismatch").expect("key ID"),
        mismatched_modulus,
        TEST_RSA_EXPONENT,
    )
    .expect("valid mismatched JWK");
    assert_eq!(
        Rs256SigningKey::from_pem(&private_key_pem, mismatched).expect_err("mismatch"),
        Rs256KeyError::KeyPairMismatch
    );
}
