mod support;

use std::sync::Arc;

use automata_auth::machine::{MachineAuthenticationError, MachineIdentityVerifier};
use automata_core::RunnerId;
use automata_runner_auth::{
    RunnerMachineAuthLimits, RunnerMachineDirectoryError, RunnerMachineRecord,
};
use automata_runner_control::DesiredRunnerState;
use support::{
    EXPIRES_AT, FakeDirectory, MutableClock, NOW, authenticator, digest, evidence, record,
};

#[tokio::test]
async fn identity_comes_only_from_the_server_owned_directory_record() {
    let leaf = b"unparsed DER bytes containing CN=attacker-controlled";
    let runner_id = RunnerId::new();
    let directory = Arc::new(FakeDirectory::new(Some(record(
        leaf,
        "spiffe://automata/runner/server-owned",
        runner_id,
        7,
        EXPIRES_AT,
        DesiredRunnerState::Active,
    ))));
    let clock = Arc::new(MutableClock::new(NOW));
    let verifier = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());
    let evidence = evidence([leaf.to_vec(), b"validated intermediate".to_vec()]);

    let machine = verifier
        .authenticate(&evidence)
        .await
        .expect("authenticated machine");

    assert_eq!(
        machine.external_identity().as_str(),
        "spiffe://automata/runner/server-owned"
    );
    assert_eq!(machine.certificate_sha256(), digest(leaf).as_bytes());
    assert_eq!(machine.authenticated_at().as_seconds(), NOW);
    assert_eq!(machine.certificate_expires_at().as_seconds(), EXPIRES_AT);
    assert_eq!(directory.requests(), vec![digest(leaf)]);
}

#[tokio::test]
async fn unknown_cross_certificate_and_expired_registrations_fail_closed() {
    let leaf = b"validated leaf A";
    let other_leaf = b"validated leaf B";
    let clock = Arc::new(MutableClock::new(NOW));
    let directory = Arc::new(FakeDirectory::new(None));
    let verifier = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());
    let evidence = evidence([leaf.to_vec()]);

    assert_eq!(
        verifier.authenticate(&evidence).await,
        Err(MachineAuthenticationError::Untrusted)
    );

    directory.set_record(Some(record(
        other_leaf,
        "runner.example/other",
        RunnerId::new(),
        1,
        EXPIRES_AT,
        DesiredRunnerState::Active,
    )));
    assert_eq!(
        verifier.authenticate(&evidence).await,
        Err(MachineAuthenticationError::Untrusted)
    );

    directory.set_record(Some(record(
        leaf,
        "runner.example/expired",
        RunnerId::new(),
        1,
        NOW,
        DesiredRunnerState::Active,
    )));
    assert_eq!(
        verifier.authenticate(&evidence).await,
        Err(MachineAuthenticationError::Expired)
    );
}

#[tokio::test]
async fn chain_count_per_certificate_and_aggregate_bytes_are_bounded_before_lookup() {
    let limits = RunnerMachineAuthLimits::new(2, 4, 6).expect("test limits");
    let directory = Arc::new(FakeDirectory::new(None));
    let clock = Arc::new(MutableClock::new(NOW));
    let verifier = authenticator(&directory, &clock, limits);
    let invalid = [
        evidence([vec![1], vec![2], vec![3]]),
        evidence([vec![1; 5]]),
        evidence([vec![1; 4], vec![2; 4]]),
    ];

    for evidence in invalid {
        assert_eq!(
            verifier.authenticate(&evidence).await,
            Err(MachineAuthenticationError::Untrusted)
        );
    }
    assert_eq!(directory.calls(), 0);
}

#[tokio::test]
async fn directory_failures_are_sanitized_as_verifier_unavailability() {
    let leaf = b"validated leaf";
    let directory = Arc::new(FakeDirectory::new(None));
    let clock = Arc::new(MutableClock::new(NOW));
    let verifier = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());
    let evidence = evidence([leaf.to_vec()]);

    for failure in [
        RunnerMachineDirectoryError::Unavailable,
        RunnerMachineDirectoryError::Corrupt,
    ] {
        directory.set_error(failure);
        let error = verifier
            .authenticate(&evidence)
            .await
            .expect_err("directory failure");
        assert_eq!(error, MachineAuthenticationError::Unavailable);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("validated leaf"));
        assert!(!rendered.contains("runner.example"));
    }
}

#[tokio::test]
async fn an_invalid_trusted_clock_sample_never_creates_an_assertion() {
    let leaf = b"validated leaf";
    let directory = Arc::new(FakeDirectory::new(Some(record(
        leaf,
        "runner.example/one",
        RunnerId::new(),
        1,
        EXPIRES_AT,
        DesiredRunnerState::Active,
    ))));
    let clock = Arc::new(MutableClock::new(0));
    let verifier = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());

    assert_eq!(
        verifier.authenticate(&evidence([leaf.to_vec()])).await,
        Err(MachineAuthenticationError::Unavailable)
    );
}

#[test]
fn records_reject_sentinel_authority_values() {
    let identity = automata_auth::machine::ExternalRunnerIdentity::new("runner.example/one")
        .expect("external identity");
    let generation = automata_store::RunnerGeneration::new(1).expect("generation");
    let valid_digest = digest(b"leaf");
    let nil_runner = "00000000-0000-0000-0000-000000000000"
        .parse()
        .expect("nil runner UUID");

    assert!(
        RunnerMachineRecord::new(
            identity.clone(),
            nil_runner,
            generation,
            valid_digest,
            automata_auth::time::UnixTimestamp::from_seconds(EXPIRES_AT),
            DesiredRunnerState::Active,
        )
        .is_err()
    );
    assert!(
        RunnerMachineRecord::new(
            identity.clone(),
            RunnerId::new(),
            generation,
            automata_core::Sha256Digest::from_bytes([0; 32]),
            automata_auth::time::UnixTimestamp::from_seconds(EXPIRES_AT),
            DesiredRunnerState::Active,
        )
        .is_err()
    );
    assert!(
        RunnerMachineRecord::new(
            identity,
            RunnerId::new(),
            generation,
            valid_digest,
            automata_auth::time::UnixTimestamp::from_seconds(0),
            DesiredRunnerState::Active,
        )
        .is_err()
    );
}
