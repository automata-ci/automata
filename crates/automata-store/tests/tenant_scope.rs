use automata_store::{TenantScope, TenantScopeError};

#[test]
fn tenant_scope_matches_the_auth_identifier_shape() {
    let scope = TenantScope::from_authenticated_tenant_id("tenant-1").expect("valid scope");
    assert_eq!(scope.as_str(), "tenant-1");

    assert_eq!(
        TenantScope::from_authenticated_tenant_id("").expect_err("empty ID"),
        TenantScopeError::Empty
    );
    assert_eq!(
        TenantScope::from_authenticated_tenant_id("tenant\nother").expect_err("control character"),
        TenantScopeError::ControlCharacter
    );
    assert_eq!(
        TenantScope::from_authenticated_tenant_id("x".repeat(256)).expect_err("oversized ID"),
        TenantScopeError::TooLong { maximum: 255 }
    );
}

#[test]
fn tenant_scope_limit_is_measured_in_utf8_bytes() {
    assert!(TenantScope::from_authenticated_tenant_id("é".repeat(127)).is_ok());
    assert_eq!(
        TenantScope::from_authenticated_tenant_id("é".repeat(128)).expect_err("256 UTF-8 bytes"),
        TenantScopeError::TooLong { maximum: 255 }
    );
}
