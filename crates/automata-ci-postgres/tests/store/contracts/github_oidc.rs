use std::sync::Arc;

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_oidc_github::{OidcIssuanceRepository, OidcKeyId};
use automata_ci_postgres::store::{
    PostgresGithubOidcAuthorityRepository, PostgresGithubOidcIssuanceRepository, PostgresStore,
};
use automata_ci_store::{
    GithubOidcAuthorityRepository, GithubOidcCurrentPolicy, GithubOidcCurrentnessClock,
    GithubOidcCurrentnessClockError, GithubOidcKeyRetentionRepository, GithubOidcKeyUse,
    GithubOidcLoadedKey, GithubOidcSubjectPolicyMode, GithubOidcSubjectPolicyRevision,
};
use sqlx::postgres::PgPoolOptions;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn current_policy() -> GithubOidcCurrentPolicy {
    GithubOidcCurrentPolicy::new(
        GithubOidcSubjectPolicyMode::StableOwnerEvidence,
        GithubOidcSubjectPolicyRevision::new(11).expect("policy revision"),
        digest(3),
        digest(5),
        30,
        25,
    )
    .expect("stable-owner current policy")
}

#[tokio::test]
async fn postgres_adapter_requires_bounded_signing_metadata_and_is_object_safe() {
    fn assert_ports(
        _: &dyn GithubOidcAuthorityRepository,
        _: &dyn GithubOidcKeyRetentionRepository,
        _: &dyn OidcIssuanceRepository,
    ) {
    }
    let _ = assert_ports;

    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://postgres:do-not-render@127.0.0.1/automata")
        .expect("lazy pool");
    let store = PostgresStore::from_postgres_pool(pool);
    let clock: Arc<dyn GithubOidcCurrentnessClock> = Arc::new(FixedCurrentnessClock);
    let signing = GithubOidcLoadedKey::new(
        GithubOidcKeyUse::IdTokenSigning,
        OidcKeyId::new("rsa-current").expect("key ID"),
        digest(8),
    );
    let current_policy = current_policy();
    let adapter = PostgresGithubOidcIssuanceRepository::new(
        store.clone(),
        current_policy,
        [signing.clone()],
        Arc::clone(&clock),
    )
    .expect("configured adapter");
    let authority = PostgresGithubOidcAuthorityRepository::new(store.clone(), Arc::clone(&clock));
    assert_ports(&authority, &store, &adapter);
    let rendered = format!("{adapter:?}");
    assert!(rendered.contains("rsa-current"));
    assert!(!rendered.contains("do-not-render"));
    assert!(
        PostgresGithubOidcIssuanceRepository::new(
            store.clone(),
            current_policy,
            [],
            Arc::clone(&clock),
        )
        .is_err(),
        "an empty signing set must fail closed"
    );
    assert!(
        PostgresGithubOidcIssuanceRepository::new(
            store,
            current_policy,
            [signing.clone(), signing],
            clock,
        )
        .is_err(),
        "duplicate IDs must fail closed"
    );
}

#[derive(Debug)]
struct FixedCurrentnessClock;

impl GithubOidcCurrentnessClock for FixedCurrentnessClock {
    fn now_millis(&self) -> Result<UnixMillis, GithubOidcCurrentnessClockError> {
        Ok(UnixMillis::new(12_500))
    }
}
