use std::time::Duration;

use automata_blob_s3::{S3BlobStoreConfig, StaticS3Credentials};
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
    assert!(
        S3BlobStoreConfig::loopback_development(
            Url::parse("http://127.0.0.1:9000/").expect("URL"),
            "us-east-1",
            "automata-dev",
            None,
            Duration::from_secs(10),
        )
        .is_ok()
    );
    assert!(
        S3BlobStoreConfig::loopback_development(
            Url::parse("http://objects.example.test/").expect("URL"),
            "us-east-1",
            "automata-dev",
            None,
            Duration::from_secs(10),
        )
        .is_err()
    );
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
