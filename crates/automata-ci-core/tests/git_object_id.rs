use automata_ci_core::{GitObjectAlgorithm, GitObjectId, GitObjectIdError};

const SHA1: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";
const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn sha1_and_sha256_round_trip_with_explicit_algorithms() {
    for (algorithm, hex) in [
        (GitObjectAlgorithm::Sha1, SHA1),
        (GitObjectAlgorithm::Sha256, SHA256),
    ] {
        let object = GitObjectId::from_hex(algorithm, hex).expect("object ID");
        assert_eq!(object.algorithm(), algorithm);
        assert_eq!(object.to_string(), hex);
        assert_eq!(object.as_bytes().len(), algorithm.byte_length());

        let json = serde_json::to_string(&object).expect("serialize");
        assert_eq!(
            json,
            format!(
                r#"{{"algorithm":"{}","hex":"{hex}"}}"#,
                match algorithm {
                    GitObjectAlgorithm::Sha1 => "sha1",
                    GitObjectAlgorithm::Sha256 => "sha256",
                }
            )
        );
        assert_eq!(
            serde_json::from_str::<GitObjectId>(&json).expect("deserialize"),
            object
        );
        assert_eq!(
            GitObjectId::from_bytes(algorithm, object.as_bytes()).expect("raw bytes"),
            object
        );
        assert_eq!(
            GitObjectId::from_durable_bytes(object.as_bytes()).expect("durable bytes"),
            object
        );
        assert_eq!(
            GitObjectId::from_provider_hex(hex).expect("provider hex"),
            object
        );
    }
}

#[test]
fn malformed_ambiguous_and_null_identities_are_rejected() {
    assert!(matches!(
        GitObjectId::from_hex(GitObjectAlgorithm::Sha256, SHA1),
        Err(GitObjectIdError::InvalidLength { .. })
    ));
    assert!(matches!(
        GitObjectId::from_provider_hex("abc"),
        Err(GitObjectIdError::UnsupportedLength { received: 3 })
    ));
    for invalid in [
        "DE0FAC2E4500DABE0009E67214FF5F5447CE83DD",
        "ge0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "0000000000000000000000000000000000000000",
    ] {
        assert!(
            GitObjectId::from_provider_hex(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn durable_decoder_requires_algorithm_and_rejects_deleted_string_form() {
    assert!(serde_json::from_str::<GitObjectId>(&format!(r#""{SHA1}""#)).is_err());
    assert!(
        serde_json::from_str::<GitObjectId>(&format!(r#"{{"algorithm":"sha256","hex":"{SHA1}"}}"#))
            .is_err()
    );
    assert!(
        serde_json::from_str::<GitObjectId>(&format!(
            r#"{{"algorithm":"sha1","hex":"{SHA1}","extra":true}}"#
        ))
        .is_err()
    );
}
