use std::time::Duration;

use automata_ci_blob_s3::{S3AtRestEncryption, S3BlobStoreConfig, StaticS3Credentials};
use url::Url;

#[test]
fn production_requires_a_credential_free_https_root_endpoint() {
    let valid = S3BlobStoreConfig::new(
        Url::parse("https://objects.example.test/").expect("URL"),
        "us-east-1",
        "automata-production",
        Some("tenant-a".to_owned()),
        false,
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
fn encryption_at_rest_is_mandatory_and_kms_identity_is_exact() {
    let config = S3BlobStoreConfig::new(
        Url::parse("https://objects.example.test/").expect("URL"),
        "us-east-1",
        "automata-production",
        None,
        false,
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
