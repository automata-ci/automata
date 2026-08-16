use std::time::Duration;

use automata_ci_blob_s3::{
    S3AtRestEncryption, S3BlobStoreConfig, S3BlobStoreConfigError, S3TlsTrust, StaticS3Credentials,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use url::Url;

#[test]
fn production_requires_a_credential_free_https_root_endpoint() {
    let valid = S3BlobStoreConfig::new(
        Url::parse("https://objects.example.test/").expect("URL"),
        "us-east-1",
        "automata-production",
        Some("tenant-a".to_owned()),
        false,
        S3TlsTrust::web_pki(),
        Duration::from_secs(10),
    );
    assert!(valid.is_ok());

    for endpoint in [
        "http://objects.example.test/",
        "https://user:password@objects.example.test/",
        "https://objects.example.test/base/",
        "https://objects.example.test/?query=true",
    ] {
        assert!(
            S3BlobStoreConfig::new(
                Url::parse(endpoint).expect("URL fixture"),
                "us-east-1",
                "automata-production",
                None,
                false,
                S3TlsTrust::web_pki(),
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted {endpoint}"
        );
    }
}

#[test]
fn development_http_is_restricted_to_loopback() {
    for endpoint in ["http://127.0.0.1:9000/", "http://[::1]:9000/"] {
        assert!(
            S3BlobStoreConfig::loopback_development(
                Url::parse(endpoint).expect("URL"),
                "us-east-1",
                "automata-dev",
                None,
                Duration::from_secs(10),
            )
            .is_ok(),
            "rejected {endpoint}"
        );
    }
    for endpoint in [
        "http://localhost:9000/",
        "http://objects.example.test/",
        "http://192.0.2.1:9000/",
    ] {
        assert!(
            S3BlobStoreConfig::loopback_development(
                Url::parse(endpoint).expect("URL"),
                "us-east-1",
                "automata-dev",
                None,
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted {endpoint}"
        );
    }
}

#[test]
fn namespaces_and_credentials_fail_closed() {
    for bucket in ["ABCD", "ab", "-bad", "bad..dots", "127.0.0.1"] {
        assert!(
            S3BlobStoreConfig::new(
                Url::parse("https://objects.example.test/").expect("URL"),
                "us-east-1",
                bucket,
                None,
                false,
                S3TlsTrust::web_pki(),
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted bucket {bucket}"
        );
    }
    for prefix in ["/absolute", "ends/", "a//b", "a/../b"] {
        assert!(
            S3BlobStoreConfig::new(
                Url::parse("https://objects.example.test/").expect("URL"),
                "us-east-1",
                "automata-production",
                Some(prefix.to_owned()),
                false,
                S3TlsTrust::web_pki(),
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted prefix {prefix}"
        );
    }
    assert!(StaticS3Credentials::new("", "secret", None).is_err());
    assert!(StaticS3Credentials::new("access", "", None).is_err());
    assert!(StaticS3Credentials::new("access", "secret", Some(String::new())).is_err());
}

#[test]
fn credential_debug_output_is_redacted() {
    let credentials = StaticS3Credentials::new(
        "visible-access-key",
        "very-secret-value",
        Some("secret-session-token".to_owned()),
    )
    .expect("credentials");
    let debug = format!("{credentials:?}");
    for secret in [
        "visible-access-key",
        "very-secret-value",
        "secret-session-token",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn connected_store_debug_output_is_minimal_after_credentials_and_private_ca_are_bound() {
    let ca_identity_marker = "connected-store-private-ca-marker";
    let key = KeyPair::generate().expect("private CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("private CA params");
    params
        .distinguished_name
        .push(DnType::CommonName, ca_identity_marker);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let certificate_pem = params
        .self_signed(&key)
        .expect("private CA certificate")
        .pem()
        .into_bytes();
    let ca_pem_marker = std::str::from_utf8(&certificate_pem)
        .expect("private CA PEM is ASCII")
        .lines()
        .nth(1)
        .expect("private CA PEM body")
        .get(..32)
        .expect("private CA PEM marker")
        .to_owned();
    let config = S3BlobStoreConfig::new(
        Url::parse("https://objects.example.test/").expect("URL"),
        "us-east-1",
        "automata-production",
        None,
        false,
        S3TlsTrust::private_ca(certificate_pem).expect("one exact private CA"),
        Duration::from_secs(10),
    )
    .expect("S3 configuration");
    let credential_markers = [
        "connected-store-access-marker",
        "connected-store-secret-marker",
        "connected-store-session-marker",
    ];
    let store = config
        .connect(
            StaticS3Credentials::new(
                credential_markers[0],
                credential_markers[1],
                Some(credential_markers[2].to_owned()),
            )
            .expect("credentials"),
        )
        .expect("connected store");

    let debug = format!("{store:?}");
    assert_eq!(debug, "S3BlobStore([connection redacted])");
    for marker in credential_markers {
        assert!(!debug.contains(marker));
    }
    assert!(!debug.contains(ca_identity_marker));
    assert!(!debug.contains(&ca_pem_marker));
}

#[test]
fn encryption_at_rest_is_mandatory_and_kms_identity_is_exact() {
    let config = S3BlobStoreConfig::new(
        Url::parse("https://objects.example.test/").expect("URL"),
        "us-east-1",
        "automata-production",
        None,
        false,
        S3TlsTrust::web_pki(),
        Duration::from_secs(10),
    )
    .expect("S3 configuration");
    assert_eq!(config.at_rest_encryption(), &S3AtRestEncryption::aes256());

    let key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001";
    let kms = S3AtRestEncryption::aws_kms(key_arn).expect("exact KMS identity");
    let configured = config.with_at_rest_encryption(kms.clone());
    assert_eq!(configured.at_rest_encryption(), &kms);

    for invalid in ["", " key", "key\n"] {
        assert!(S3AtRestEncryption::aws_kms(invalid).is_err());
        assert!(S3AtRestEncryption::aws_kms_dsse(invalid).is_err());
    }
}

#[test]
fn private_ca_trust_consumes_the_shared_validated_ca_and_redacts_it() {
    let ca_pem = certificate_pem(true);
    let trust = S3TlsTrust::private_ca(ca_pem).expect("one exact private CA");
    assert_eq!(
        format!("{trust:?}"),
        "S3TlsTrust::PrivateCa([certificate redacted])"
    );
    assert_eq!(
        S3TlsTrust::private_ca(certificate_pem(false)),
        Err(S3BlobStoreConfigError::InvalidPrivateCa)
    );
}

#[test]
fn private_ca_trust_is_incompatible_with_plaintext() {
    let trust = S3TlsTrust::private_ca(certificate_pem(true)).expect("private CA");
    let direct = S3BlobStoreConfig::new(
        Url::parse("http://127.0.0.1:9000/").expect("URL"),
        "us-east-1",
        "automata-tests",
        None,
        true,
        trust.clone(),
        Duration::from_secs(10),
    );
    assert_eq!(direct, Err(S3BlobStoreConfigError::PrivateCaRequiresHttps));
    let result = S3BlobStoreConfig::loopback_development(
        Url::parse("http://127.0.0.1:9000/").expect("URL"),
        "us-east-1",
        "automata-tests",
        None,
        Duration::from_secs(10),
    )
    .expect("loopback configuration")
    .with_tls_trust(trust);
    assert_eq!(result, Err(S3BlobStoreConfigError::PrivateCaRequiresHttps));
}

#[test]
fn validated_https_shape_can_bind_one_late_loaded_exact_trust_policy() {
    let endpoint = Url::parse("https://objects.example.test/").expect("URL");
    let trust = S3TlsTrust::private_ca(certificate_pem(true)).expect("private CA");
    let rebound = S3BlobStoreConfig::new(
        endpoint.clone(),
        "us-east-1",
        "automata-production",
        Some("tenant-a".to_owned()),
        true,
        S3TlsTrust::web_pki(),
        Duration::from_secs(10),
    )
    .expect("validated HTTPS shape")
    .with_tls_trust(trust.clone())
    .expect("late trust binding");
    let direct = S3BlobStoreConfig::new(
        endpoint,
        "us-east-1",
        "automata-production",
        Some("tenant-a".to_owned()),
        true,
        trust,
        Duration::from_secs(10),
    )
    .expect("direct exact configuration");
    assert_eq!(rebound, direct);
}

fn certificate_pem(is_ca: bool) -> Vec<u8> {
    let key_usages = if is_ca {
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
    } else {
        Vec::new()
    };
    certificate_pem_with_usage(is_ca, key_usages)
}

fn certificate_pem_with_usage(is_ca: bool, key_usages: Vec<KeyUsagePurpose>) -> Vec<u8> {
    let key = KeyPair::generate().expect("certificate key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("certificate params");
    if is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    params.key_usages = key_usages;
    params
        .self_signed(&key)
        .expect("self-signed certificate")
        .pem()
        .into_bytes()
}
