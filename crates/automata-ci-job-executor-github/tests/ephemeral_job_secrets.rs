use automata_ci_auth::secret::{SecretString, SharedSensitiveString};
use automata_ci_core::SecretBinding;
use automata_ci_job_executor_github::{
    EphemeralJobSecret, EphemeralJobSecrets, EphemeralJobSecretsError,
    MAX_EPHEMERAL_JOB_SECRET_BYTES, MAX_EPHEMERAL_JOB_SECRETS, NoSecrets, PortErrorKind,
    SecretPort, validate_ephemeral_job_secret_bytes,
};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(EphemeralJobSecret: Clone);
assert_not_impl_any!(EphemeralJobSecrets: Clone);
assert_not_impl_any!(SharedSensitiveString: Into<String>, std::fmt::Display);

fn entry(binding: &str, version: &str, value: String) -> EphemeralJobSecret {
    let binding = SecretBinding::new(binding)
        .unwrap()
        .with_version_id(version)
        .unwrap();
    EphemeralJobSecret::new(&binding, SecretString::new(value).unwrap()).unwrap()
}

#[test]
fn exact_version_bindings_resolve_without_fallback() {
    let secrets = EphemeralJobSecrets::new([
        entry("grant-a", "version-a", "alpha-value".to_owned()),
        entry("grant-b", "version-b", "beta-value".to_owned()),
    ])
    .unwrap();

    assert_eq!(secrets.len(), 2);
    assert!(!secrets.is_empty());
    let resolved = secrets.resolve("grant-a").unwrap();
    assert_eq!(resolved.expose_secret(), "alpha-value");
    assert_eq!(
        secrets.resolve("GRANT-A").unwrap_err().kind(),
        PortErrorKind::NotFound
    );
    assert_eq!(
        secrets.resolve("version-a").unwrap_err().kind(),
        PortErrorKind::NotFound
    );
}

#[test]
fn no_secrets_still_fails_closed_as_not_found() {
    assert_eq!(
        NoSecrets.resolve("any-reference").unwrap_err().kind(),
        PortErrorKind::NotFound
    );
}

#[test]
fn repeated_resolution_shares_the_admitted_plaintext_allocation() {
    let binding = SecretBinding::new("grant-a")
        .unwrap()
        .with_version_id("version-a")
        .unwrap();
    let value = SecretString::new("shared-allocation-sentinel").unwrap();
    let admitted_plaintext_pointer = value.expose_secret().as_ptr();
    let secrets =
        EphemeralJobSecrets::new([EphemeralJobSecret::new(&binding, value).unwrap()]).unwrap();

    let first = secrets.resolve("grant-a").unwrap();
    let second = secrets.resolve("grant-a").unwrap();

    assert_eq!(first.expose_secret(), "shared-allocation-sentinel");
    assert_eq!(first.expose_secret().as_ptr(), admitted_plaintext_pointer);
    assert_eq!(second.expose_secret().as_ptr(), admitted_plaintext_pointer);
    assert!(!format!("{first:?}").contains("shared-allocation-sentinel"));
}

#[test]
fn custody_rejects_missing_versions_duplicates_and_resource_exhaustion() {
    assert_eq!(
        EphemeralJobSecret::new(
            &SecretBinding::new("grant-a").unwrap(),
            SecretString::new("value").unwrap(),
        )
        .unwrap_err(),
        EphemeralJobSecretsError::MissingVersion
    );

    assert_eq!(
        EphemeralJobSecrets::new([
            entry("grant-a", "version-a", "first".to_owned()),
            entry("grant-a", "version-b", "second".to_owned()),
        ])
        .unwrap_err(),
        EphemeralJobSecretsError::DuplicateBinding
    );

    let maximum_value = "x".repeat(65_536);
    let oversized = (0..17)
        .map(|index| {
            entry(
                &format!("large-grant-{index}"),
                "version-a",
                maximum_value.clone(),
            )
        })
        .collect::<Vec<_>>();
    let error =
        EphemeralJobSecrets::new(oversized).expect_err("aggregate plaintext must remain bounded");
    assert_eq!(error, EphemeralJobSecretsError::AggregatePlaintextTooLarge);
}

#[test]
fn ephemeral_secret_count_boundaries() {
    let entries = |count| {
        (0..count)
            .map(|index| entry(&format!("grant-{index}"), "version", "x".to_owned()))
            .collect::<Vec<_>>()
    };

    assert!(EphemeralJobSecrets::new(entries(MAX_EPHEMERAL_JOB_SECRETS - 1)).is_ok());
    assert!(EphemeralJobSecrets::new(entries(MAX_EPHEMERAL_JOB_SECRETS)).is_ok());
    assert_eq!(
        EphemeralJobSecrets::new(entries(MAX_EPHEMERAL_JOB_SECRETS + 1)).unwrap_err(),
        EphemeralJobSecretsError::TooManyBindings
    );
}

#[test]
fn ephemeral_secret_plaintext_byte_boundaries() {
    assert!(validate_ephemeral_job_secret_bytes(MAX_EPHEMERAL_JOB_SECRET_BYTES - 1).is_ok());
    assert!(validate_ephemeral_job_secret_bytes(MAX_EPHEMERAL_JOB_SECRET_BYTES).is_ok());
    assert_eq!(
        validate_ephemeral_job_secret_bytes(MAX_EPHEMERAL_JOB_SECRET_BYTES + 1),
        Err(EphemeralJobSecretsError::AggregatePlaintextTooLarge)
    );
}

#[test]
fn diagnostics_never_contain_binding_values() {
    let sentinel = "top-secret-sentinel";
    let binding = SecretBinding::new("grant-a")
        .unwrap()
        .with_version_id("version-a")
        .unwrap();
    let secret = EphemeralJobSecret::new(&binding, SecretString::new(sentinel).unwrap()).unwrap();
    let entry_debug = format!("{secret:?}");
    assert!(entry_debug.contains("grant-a"));
    assert!(!entry_debug.contains(sentinel));

    let secrets = EphemeralJobSecrets::new([secret]).unwrap();
    let debug = format!("{secrets:?}");
    assert!(debug.contains("binding_count"));
    assert!(!debug.contains("aggregate_plaintext_bytes"));
    assert!(!debug.contains(&sentinel.len().to_string()));
    assert!(!debug.contains("grant-a"));
    assert!(!debug.contains(sentinel));
}
