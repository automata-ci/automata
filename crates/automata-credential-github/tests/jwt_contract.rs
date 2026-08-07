mod support;

use automata_credential::RepositoryCredentialBroker;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use support::{FixtureServer, NOW, private_key, request, success_response};

#[tokio::test]
async fn rs256_assertion_matches_the_deterministic_claim_vector() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(success_response());
    fixture.enqueue(success_response());
    let broker = fixture.broker();
    broker.issue(&request()).await.unwrap();
    broker.issue(&request()).await.unwrap();

    let requests = fixture.requests();
    let first = requests[0].headers["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap();
    let second = requests[1].headers["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap();
    assert_eq!(
        first, second,
        "RS256 PKCS#1 v1.5 signing must be deterministic"
    );
    let vector_digest: [u8; 32] = Sha256::digest(first.as_bytes()).into();
    assert_eq!(
        vector_digest,
        [
            190, 185, 23, 183, 121, 167, 39, 214, 120, 250, 178, 185, 77, 228, 42, 157, 139, 46,
            168, 160, 228, 174, 185, 165, 65, 101, 133, 218, 133, 41, 187, 19,
        ]
    );

    let segments = first.split('.').collect::<Vec<_>>();
    assert_eq!(segments.len(), 3);
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
    assert_eq!(header, serde_json::json!({"alg":"RS256","typ":"JWT"}));
    assert_eq!(claims["iat"], NOW - 60);
    assert_eq!(claims["exp"], NOW + 540);
    assert_eq!(claims["iss"], support::ISSUER);
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        600
    );

    let (_, private_der) =
        pem_rfc7468::decode_vec(private_key().expose_secret().as_bytes()).unwrap();
    let key_pair = RsaKeyPair::from_der(&private_der).unwrap();
    let verifier =
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key_pair.public_key().as_ref());
    let signature = URL_SAFE_NO_PAD.decode(segments[2]).unwrap();
    verifier
        .verify(
            format!("{}.{}", segments[0], segments[1]).as_bytes(),
            &signature,
        )
        .unwrap();
}
