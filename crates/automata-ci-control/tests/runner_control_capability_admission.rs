use automata_ci_control::runner_control::capability_admission::{
    RunnerCapabilityAdmissionError, RunnerCapabilityAdmissionRepository, RunnerCapabilityReadiness,
};

#[test]
fn readiness_is_fail_closed_until_each_optional_product_is_proved_ready() {
    let unavailable = RunnerCapabilityReadiness::unavailable();
    assert!(!unavailable.workload_oidc());
    assert!(unavailable.with_workload_oidc().workload_oidc());
}

#[test]
fn admission_repository_is_an_object_safe_storage_port() {
    fn accepts_port(_port: &dyn RunnerCapabilityAdmissionRepository) {}

    let _ = accepts_port;
    assert!(matches!(
        RunnerCapabilityAdmissionError::drift("runner capability admission"),
        RunnerCapabilityAdmissionError::ConfigurationDrift {
            resource: "runner capability admission"
        }
    ));
}
