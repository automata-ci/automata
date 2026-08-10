use automata_ci_core::{AttemptNumber, FencingToken, IdentifierError, RunId};
use uuid::Uuid;

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
