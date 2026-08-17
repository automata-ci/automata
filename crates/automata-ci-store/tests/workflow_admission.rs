use automata_ci_core::QueuePolicy;
use automata_ci_store::{
    WorkflowAdmissionIdempotency, WorkflowAdmissionValueError, WorkflowConcurrency,
};

#[test]
fn provider_delivery_idempotency_is_exactly_namespaced_per_workflow() {
    let identity = WorkflowAdmissionIdempotency::namespaced_provider_delivery(
        "github",
        "1327738746",
        "44f04700-9910-11f1-8cb4-03166776c1d4",
        ".ci/workflows/ci.yml",
    )
    .expect("canonical provider delivery coordinates");
    assert_eq!(
        identity.key(),
        "provider-delivery:f968a33256cb8cfd638d7eebd8434372595327fad43f42c3c625fdb67c0d27c7"
    );
    let other_workflow = WorkflowAdmissionIdempotency::namespaced_provider_delivery(
        "github",
        "1327738746",
        "44f04700-9910-11f1-8cb4-03166776c1d4",
        ".ci/workflows/release.yml",
    )
    .expect("canonical provider delivery coordinates");
    assert_ne!(identity, other_workflow);
}

#[test]
fn workflow_concurrency_normalizes_case_and_rejects_conflicting_max_policy() {
    let single = WorkflowConcurrency::new("Deploy-Main", true)
        .expect("valid single-pending cancellation policy");
    assert_eq!(single.display_key(), "Deploy-Main");
    assert_eq!(single.normalized_key(), "deploy-main");
    assert_eq!(single.queue_policy(), QueuePolicy::Single);
    assert!(single.cancel_in_progress());

    let max = WorkflowConcurrency::new("DEPLOY-MAIN", false)
        .expect("valid concurrency key")
        .with_queue_policy(QueuePolicy::Max)
        .expect("max queue without cancellation");
    assert_eq!(max.normalized_key(), single.normalized_key());
    assert_eq!(max.queue_policy(), QueuePolicy::Max);
    assert!(!max.cancel_in_progress());

    assert_eq!(
        WorkflowConcurrency::new("deploy-main", true)
            .expect("valid concurrency key")
            .with_queue_policy(QueuePolicy::Max),
        Err(WorkflowAdmissionValueError::InvalidConcurrencyPolicy)
    );
}
