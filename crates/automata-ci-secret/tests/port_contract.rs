use automata_ci_secret::{ProviderCapability, ProviderErrorKind, SecretProvider};

use crate::support::{DefaultMethodProvider, poll_immediately_ready, reconciliation_request};

static_assertions::assert_obj_safe!(SecretProvider);

#[test]
fn secret_provider_is_object_safe() {
    fn accepts(_: &dyn SecretProvider) {}
    let _ = accepts;
}

#[test]
fn default_reconciliation_is_closed_and_never_delegates_to_create() {
    let provider = DefaultMethodProvider::new("default-reconciliation");
    let erased: &dyn SecretProvider = &provider;
    assert!(
        !erased
            .capabilities()
            .supports(ProviderCapability::ReconcileCreateVersion)
    );

    for _ in 0..2 {
        let error = poll_immediately_ready(
            erased.reconcile_create_version(reconciliation_request(
                "durable-create-request",
                "opaque-locator",
                "opaque-version",
            )),
            "default provider reconciliation unexpectedly yielded",
        )
        .expect_err("default reconciliation must fail closed");
        assert_eq!(error.kind(), ProviderErrorKind::Unsupported);
    }
    assert_eq!(provider.create_call_count(), 0);
}
