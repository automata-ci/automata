use automata_ci_control::maintenance::{
    ControlPlaneMaintenanceRepository, ControlPlaneMaintenanceRequest, LeaseFailureLimit,
    MaintenanceBatchSize, MaintenanceValueError, StaleSessionTimeoutMillis,
};
use automata_ci_core::UnixMillis;

fn require_send_sync<T: ?Sized + Send + Sync>() {}

#[test]
fn maintenance_repository_is_a_dyn_compatible_provider_neutral_port() {
    require_send_sync::<dyn ControlPlaneMaintenanceRepository>();
}

#[test]
fn maintenance_policy_values_are_positive_bounded_and_exact() {
    assert!(matches!(
        MaintenanceBatchSize::new(0),
        Err(MaintenanceValueError::InvalidBatchSize)
    ));
    assert!(MaintenanceBatchSize::new(1_000).is_ok());
    assert!(MaintenanceBatchSize::new(1_001).is_err());
    assert!(LeaseFailureLimit::new(0).is_err());
    assert!(LeaseFailureLimit::new(i32::MAX as u32).is_ok());
    assert!(LeaseFailureLimit::new(i32::MAX as u32 + 1).is_err());
    assert!(StaleSessionTimeoutMillis::new(0).is_err());
    assert!(StaleSessionTimeoutMillis::new(i64::MAX as u64).is_ok());
    assert!(StaleSessionTimeoutMillis::new(i64::MAX as u64 + 1).is_err());

    let request = ControlPlaneMaintenanceRequest::new(
        UnixMillis::new(50_000),
        LeaseFailureLimit::new(3).expect("failure limit"),
        MaintenanceBatchSize::new(25).expect("batch size"),
        StaleSessionTimeoutMillis::new(30_000).expect("timeout"),
    )
    .expect("representable cutoff");
    assert_eq!(request.observed_at(), UnixMillis::new(50_000));
    assert_eq!(request.stale_session_cutoff(), UnixMillis::new(20_000));
    assert_eq!(request.maximum_lease_failures().get(), 3);
    assert_eq!(request.batch_size().get(), 25);
}

#[test]
fn stale_cutoff_underflow_is_rejected_instead_of_saturating() {
    let result = ControlPlaneMaintenanceRequest::new(
        UnixMillis::new(i64::MIN),
        LeaseFailureLimit::new(1).expect("failure limit"),
        MaintenanceBatchSize::new(1).expect("batch size"),
        StaleSessionTimeoutMillis::new(1).expect("timeout"),
    );
    assert!(matches!(
        result,
        Err(MaintenanceValueError::StaleSessionCutoffOutOfRange)
    ));
}
