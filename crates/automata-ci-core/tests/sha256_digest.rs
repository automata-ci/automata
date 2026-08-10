use std::str::FromStr;

use automata_ci_core::{
    SHA256_DIGEST_BYTES, SHA256_DIGEST_HEX_LENGTH, Sha256Digest, Sha256DigestError,
};

const LOWER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const UPPER: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

#[test]
fn bytes_hex_and_json_round_trip_canonically() {
    let lower = Sha256Digest::from_str(LOWER).expect("valid digest");
    let upper = Sha256Digest::from_str(UPPER).expect("valid digest");

    assert_eq!(lower, upper);
    assert_eq!(lower.to_string(), LOWER);
    assert_eq!(lower.as_bytes().len(), SHA256_DIGEST_BYTES);
    assert_eq!(lower.into_bytes().len(), SHA256_DIGEST_BYTES);
    assert_eq!(LOWER.len(), SHA256_DIGEST_HEX_LENGTH);

    let json = serde_json::to_string(&lower).expect("serialize");
    assert_eq!(json, format!("\"{LOWER}\""));
    assert_eq!(
        serde_json::from_str::<Sha256Digest>(&json).expect("deserialize"),
        lower
    );
}

#[test]
fn parser_rejects_wrong_lengths_and_non_hexadecimal_bytes() {
    assert_eq!(
        "00".parse::<Sha256Digest>(),
        Err(Sha256DigestError::InvalidLength {
            expected: SHA256_DIGEST_HEX_LENGTH,
            received: 2,
        })
    );
    let invalid = format!("{}g", &LOWER[..LOWER.len() - 1]);
    assert_eq!(
        invalid.parse::<Sha256Digest>(),
        Err(Sha256DigestError::InvalidHex { index: 63 })
    );
}
