use std::sync::Arc;

use automata_ci_auth::machine::MachineIdentityVerifier;
use automata_ci_control::runner_auth::{RunnerMachineAuthLimits, RunnerMachineDirectoryError};
use automata_ci_control::runner_control::{
    ControlPortError, DesiredRunnerState, RunnerRegistrationAuthorizer,
};
use automata_ci_core::RunnerId;

use super::runner_auth_support::{
    EXPIRES_AT, FakeDirectory, MutableClock, NOW, authenticator, evidence, record,
};

#[tokio::test]
async fn authorization_freshly_loads_generation_and_desired_state() {
    let leaf = b"validated leaf";
    let runner_id = RunnerId::new();
    let directory = Arc::new(FakeDirectory::new(Some(record(
        leaf,
        "runner.example/one",
        runner_id,
        3,
        EXPIRES_AT,
        DesiredRunnerState::Active,
    ))));
    let clock = Arc::new(MutableClock::new(NOW));
    let authority = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());
    let machine = authority
        .authenticate(&evidence([leaf.to_vec()]))
        .await
        .expect("authenticated machine");

    directory.set_record(Some(record(
        leaf,
        "runner.example/one",
        runner_id,
        4,
        EXPIRES_AT,
        DesiredRunnerState::Draining,
    )));
    let registration = authority
        .authorize(&machine)
        .await
        .expect("directory read")
        .expect("authorized registration");

    assert_eq!(registration.runner_id(), runner_id);
    assert_eq!(registration.generation().get(), 4);
    assert_eq!(registration.desired_state(), DesiredRunnerState::Draining);
    assert_eq!(directory.calls(), 2);
}

#[tokio::test]
async fn identity_certificate_and_expiry_drift_reject_the_prior_machine() {
    let leaf = b"validated leaf";
    let other_leaf = b"rotated leaf";
    let runner_id = RunnerId::new();
    let directory = Arc::new(FakeDirectory::new(Some(record(
        leaf,
        "runner.example/one",
        runner_id,
        1,
        EXPIRES_AT,
        DesiredRunnerState::Active,
    ))));
    let clock = Arc::new(MutableClock::new(NOW));
    let authority = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());
    let machine = authority
        .authenticate(&evidence([leaf.to_vec()]))
        .await
        .expect("authenticated machine");

    let drifted = [
        record(
            leaf,
            "runner.example/reassigned",
            runner_id,
            2,
            EXPIRES_AT,
            DesiredRunnerState::Active,
        ),
        record(
            other_leaf,
            "runner.example/one",
            runner_id,
            2,
            EXPIRES_AT,
            DesiredRunnerState::Active,
        ),
        record(
            leaf,
            "runner.example/one",
            runner_id,
            2,
            EXPIRES_AT + 1,
            DesiredRunnerState::Active,
        ),
    ];
    for record in drifted {
        directory.set_record(Some(record));
        assert_eq!(authority.authorize(&machine).await, Ok(None));
    }
    directory.set_record(None);
    assert_eq!(authority.authorize(&machine).await, Ok(None));
}

#[tokio::test]
async fn expiry_and_clock_regression_are_rechecked_after_authentication() {
    let leaf = b"validated leaf";
    let directory = Arc::new(FakeDirectory::new(Some(record(
        leaf,
        "runner.example/one",
        RunnerId::new(),
        1,
        EXPIRES_AT,
        DesiredRunnerState::Active,
    ))));
    let clock = Arc::new(MutableClock::new(NOW));
    let authority = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());
    let machine = authority
        .authenticate(&evidence([leaf.to_vec()]))
        .await
        .expect("authenticated machine");

    clock.set(EXPIRES_AT);
    assert_eq!(authority.authorize(&machine).await, Ok(None));
    clock.set(NOW - 1);
    assert_eq!(
        authority.authorize(&machine).await,
        Err(ControlPortError::Unavailable)
    );
}

#[tokio::test]
async fn directory_failures_map_to_the_existing_control_port_contract() {
    let leaf = b"validated leaf";
    let directory = Arc::new(FakeDirectory::new(Some(record(
        leaf,
        "runner.example/one",
        RunnerId::new(),
        1,
        EXPIRES_AT,
        DesiredRunnerState::Active,
    ))));
    let clock = Arc::new(MutableClock::new(NOW));
    let authority = authenticator(&directory, &clock, RunnerMachineAuthLimits::default());
    let machine = authority
        .authenticate(&evidence([leaf.to_vec()]))
        .await
        .expect("authenticated machine");

    for (directory_error, expected) in [
        (
            RunnerMachineDirectoryError::Unavailable,
            ControlPortError::Unavailable,
        ),
        (
            RunnerMachineDirectoryError::Corrupt,
            ControlPortError::Corrupt,
        ),
    ] {
        directory.set_error(directory_error);
        assert_eq!(authority.authorize(&machine).await, Err(expected));
    }
}
