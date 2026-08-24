use automata_ci_core::{
    AttemptNumber, FencingToken, IdentifierError, ManagedTenantId, ManagedTenantIdError, RunId,
    RunIdAlias,
};
use uuid::Uuid;

#[test]
fn tenant_ids_are_canonical_and_non_nil() {
    let value = "22222222-2222-4222-8222-222222222222";
    let tenant = ManagedTenantId::parse(value).expect("tenant ID");
    assert_eq!(tenant.to_string(), value);
    assert_eq!(
        serde_json::from_str::<ManagedTenantId>(&format!("\"{value}\"")).expect("deserialize"),
        tenant
    );

    for invalid in [
        "00000000-0000-0000-0000-000000000000",
        "22222222222242228222222222222222",
        "22222222-2222-4222-8222-22222222222A",
    ] {
        assert_eq!(ManagedTenantId::parse(invalid), Err(ManagedTenantIdError));
    }
    assert_eq!(
        ManagedTenantId::from_uuid(Uuid::nil()),
        Err(ManagedTenantIdError)
    );
}

#[test]
fn typed_ids_have_stable_json_string_encoding() {
    let id = RunId::from_uuid(Uuid::nil());
    assert_eq!(
        serde_json::to_string(&id).expect("serialize ID"),
        "\"00000000-0000-0000-0000-000000000000\"",
    );
    assert_eq!(
        serde_json::from_str::<RunId>("\"00000000-0000-0000-0000-000000000000\"")
            .expect("deserialize ID"),
        id,
    );
}

#[test]
fn numeric_identifiers_reject_zero_and_fencing_does_not_wrap() {
    assert_eq!(RunIdAlias::new(0), Err(IdentifierError::ZeroRunIdAlias),);
    assert_eq!(
        RunIdAlias::new(RunIdAlias::MAX + 1),
        Err(IdentifierError::RunIdAliasOutOfRange),
    );
    assert_eq!(
        AttemptNumber::new(0),
        Err(IdentifierError::ZeroAttemptNumber),
    );
    assert_eq!(FencingToken::new(0), Err(IdentifierError::ZeroFencingToken));
    assert_eq!(
        FencingToken::new(FencingToken::MAX + 1),
        Err(IdentifierError::FencingTokenOutOfRange),
    );
    assert_eq!(
        FencingToken::new(FencingToken::MAX)
            .expect("durable maximum is non-zero")
            .checked_next(),
        Err(IdentifierError::FencingTokenExhausted),
    );
}

#[test]
fn run_id_alias_round_trips_its_exact_numeric_contract() {
    let alias = RunIdAlias::new(RunIdAlias::MAX).expect("maximum run alias");
    assert_eq!(alias.get(), RunIdAlias::MAX);
    assert_eq!(alias.to_string(), RunIdAlias::MAX.to_string());
    assert_eq!(
        serde_json::to_string(&alias).expect("serialize run alias"),
        alias.to_string(),
    );
    assert_eq!(
        serde_json::from_str::<RunIdAlias>(&alias.to_string()).expect("deserialize run alias"),
        alias,
    );
    for invalid in ["0".to_owned(), (RunIdAlias::MAX + 1).to_string()] {
        assert!(
            serde_json::from_str::<RunIdAlias>(&invalid).is_err(),
            "accepted invalid run alias {invalid}",
        );
    }
}

#[test]
fn fencing_token_json_cannot_bypass_the_durable_range() {
    assert_eq!(
        serde_json::from_str::<FencingToken>(&FencingToken::MAX.to_string())
            .expect("deserialize durable maximum")
            .get(),
        FencingToken::MAX,
    );

    for invalid in ["0".to_owned(), (FencingToken::MAX + 1).to_string()] {
        assert!(
            serde_json::from_str::<FencingToken>(&invalid).is_err(),
            "accepted invalid fencing token {invalid}",
        );
    }
}
