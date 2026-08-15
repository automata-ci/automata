use crate::support;

use std::{path::PathBuf, sync::Arc};

use automata_ci_oidc_github::{
    GithubOidcApi, OIDC_DISCOVERY_PATH, OIDC_JWKS_CACHE_SECONDS, OIDC_JWKS_PATH, OIDC_TOKEN_PATH,
    OIDC_TOKEN_REQUEST_PATH_AND_QUERY, OidcClock, OidcClockError,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt as _;
use ring::digest::{SHA256, digest};
use serde_json::Value;
use tokio::{net::TcpListener, process::Command};
use tower::ServiceExt as _;

use support::{NOW_SECONDS, TEST_KEY_ID, TEST_RSA_MODULUS, configured_service, decode_token_str};

#[derive(Debug)]
struct FixedClock(u64);

impl OidcClock for FixedClock {
    fn now_seconds(&self) -> Result<u64, OidcClockError> {
        Ok(self.0)
    }
}

fn application() -> (axum::Router, String) {
    let (service, _, bearer) = configured_service();
    (
        GithubOidcApi::new(service, Arc::new(FixedClock(NOW_SECONDS))).router(),
        bearer.expose_secret().to_owned(),
    )
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("JSON response")
}

#[tokio::test]
async fn discovery_and_jwks_publish_the_exact_non_github_issuer_and_rs256_key() {
    let (application, _) = application();
    let discovery = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(OIDC_DISCOVERY_PATH)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("discovery response");
    assert_eq!(discovery.status(), StatusCode::OK);
    assert_eq!(
        discovery.headers()[header::CACHE_CONTROL],
        format!("public, max-age={OIDC_JWKS_CACHE_SECONDS}")
    );
    let discovery = json_body(discovery).await;
    assert_eq!(discovery["issuer"], "https://oidc.example.invalid/");
    assert_eq!(
        discovery["jwks_uri"],
        "https://oidc.example.invalid/.well-known/jwks"
    );
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"][0],
        "RS256"
    );
    let supported = discovery["claims_supported"]
        .as_array()
        .expect("supported claims");
    assert!(supported.iter().any(|claim| claim == "ref"));
    assert!(supported.iter().any(|claim| claim == "repository_id"));

    let jwks = application
        .oneshot(
            Request::builder()
                .uri(OIDC_JWKS_PATH)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("JWKS response");
    assert_eq!(jwks.status(), StatusCode::OK);
    let jwks = json_body(jwks).await;
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
    assert_eq!(jwks["keys"][0]["kid"], TEST_KEY_ID);
    assert_eq!(jwks["keys"][0]["n"], TEST_RSA_MODULUS);
    assert_eq!(jwks["keys"][0]["e"], "AQAB");
}

#[tokio::test]
async fn mint_http_contract_returns_value_and_custom_audience_without_caching() {
    let (application, bearer) = application();
    let response = application
        .oneshot(
            Request::builder()
                .uri(format!(
                    "{OIDC_TOKEN_PATH}?api-version=2.0&audience=api%3A%2F%2Fcloud%20exchange"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("mint response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let response = json_body(response).await;
    let token = response["value"].as_str().expect("token value");
    let (_, claims) = decode_token_str(token);
    assert_eq!(claims["aud"], "api://cloud exchange");
    assert_eq!(claims["iss"], "https://oidc.example.invalid/");
}

#[tokio::test]
async fn mint_http_contract_rejects_ambiguous_query_auth_and_body_shapes() {
    let (application, bearer) = application();
    let cases = [
        format!("{OIDC_TOKEN_PATH}?audience=x"),
        format!("{OIDC_TOKEN_PATH}?api-version=1.0"),
        format!("{OIDC_TOKEN_PATH}?api-version=2.0&unknown=x"),
        format!("{OIDC_TOKEN_PATH}?api-version=2.0&audience=x&audience=y"),
        format!("{OIDC_TOKEN_PATH}?api-version=2.0&audience=%GG"),
    ];
    for uri in cases {
        let response = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    let missing_auth = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{OIDC_TOKEN_PATH}?api-version=2.0"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing_auth.headers()[header::WWW_AUTHENTICATE],
        "Bearer realm=\"oidc\""
    );

    let duplicate_auth = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{OIDC_TOKEN_PATH}?api-version=2.0"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(duplicate_auth.status(), StatusCode::UNAUTHORIZED);

    let nonempty_body = application
        .oneshot(
            Request::builder()
                .uri(format!("{OIDC_TOKEN_PATH}?api-version=2.0"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::from("x"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(nonempty_body.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_actions_core_3_0_1_oidc_module_is_offline_compatible() {
    const UPSTREAM_SHA256: [u8; 32] = [
        0x80, 0x23, 0x2d, 0xde, 0x41, 0x6d, 0xbb, 0x72, 0x07, 0xc7, 0x0d, 0xa8, 0x59, 0x9f, 0xcc,
        0xef, 0x0b, 0x9a, 0x0c, 0x46, 0xc2, 0x35, 0x18, 0x2e, 0xea, 0x12, 0x1b, 0xbc, 0x22, 0x7a,
        0x29, 0x31,
    ];
    let fixture_source = include_bytes!("fixtures/actions-core-3.0.1/oidc-utils.js");
    let upstream_source = fixture_source
        .strip_suffix(b"\n")
        .expect("one repository newline");
    assert_eq!(digest(&SHA256, upstream_source).as_ref(), UPSTREAM_SHA256);

    let (application, bearer) = application();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        axum::serve(listener, application)
            .await
            .expect("OIDC fixture server");
    });
    let fixture_directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/actions-core-3.0.1");
    let output = Command::new("node")
        .arg("--no-warnings")
        .arg("--experimental-loader")
        .arg("./loader.mjs")
        .arg("client.mjs")
        .current_dir(fixture_directory)
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("http://{address}{OIDC_TOKEN_REQUEST_PATH_AND_QUERY}"),
        )
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", bearer)
        .env("OIDC_TEST_AUDIENCE", "api://exchange/custom audience")
        .output()
        .await
        .expect("run Node fixture");
    server.abort();
    assert!(
        output.status.success(),
        "Node fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let token = String::from_utf8(output.stdout).expect("token stdout");
    let (header, claims) = decode_token_str(&token);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(claims["aud"], "api://exchange/custom audience");
}
