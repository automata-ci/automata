use automata_ci::app::conformance_github_stub::{
    HermeticGithubCredential, HermeticGithubStubError, HermeticGithubStubFailure,
    HermeticGithubStubServer, X_AUTOMATA_GITHUB_MUTATION_OUTCOME,
};
use automata_ci::app::conformance_shard::ProductConformanceShard;
use automata_ci_auth::secret::SecretString;
use automata_ci_conformance::{
    GithubMutationOutcome, GithubStubError, GithubStubExchange, GithubStubRequest,
    GithubStubResponse, GithubStubScript, ShardPlan,
};
use reqwest::{Client, StatusCode, header::LINK};
use sha2::{Digest as _, Sha256};

const AUTHORIZATION: &str = "Bearer hermetic-installation-token";
const CREDENTIAL_ID: &str = "installation-42";

fn credential() -> HermeticGithubCredential {
    HermeticGithubCredential::new(
        CREDENTIAL_ID,
        SecretString::new(AUTHORIZATION).expect("fixture authorization"),
    )
    .expect("credential mapping")
}

fn request(method: &str, path_and_query: &str, body: Option<&[u8]>) -> GithubStubRequest {
    GithubStubRequest {
        method: method.to_owned(),
        path_and_query: path_and_query.to_owned(),
        body_sha256: body.map(body_sha256),
        credential_id: Some(CREDENTIAL_ID.to_owned()),
    }
}

fn body_sha256(body: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(body) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[test]
fn credential_debug_never_exposes_authorization() {
    let credential = HermeticGithubCredential::new(
        "installation-42",
        SecretString::new("Bearer super-secret-fixture-token").expect("secret"),
    )
    .expect("credential");
    let debug = format!("{credential:?}");
    assert!(debug.contains("installation-42"));
    assert!(!debug.contains("super-secret-fixture-token"));
    assert!(debug.contains("[REDACTED]"));
}

#[tokio::test]
async fn shard_reservation_is_transferred_directly_to_the_stub() {
    let plan = ShardPlan::derive("github-stub-held-listener", 1).expect("shard plan");
    let shard = ProductConformanceShard::from_plan(&plan, 0).expect("product shard");
    let reservation = shard
        .reserve_loopback_port("github-stub")
        .await
        .expect("held loopback listener");
    let reserved_addr = reservation.local_addr();
    let script = GithubStubScript::new(vec![GithubStubExchange {
        request: GithubStubRequest {
            method: "GET".to_owned(),
            path_and_query: "/held-listener".to_owned(),
            body_sha256: None,
            credential_id: None,
        },
        response: GithubStubResponse::Page {
            status: 200,
            body: b"reserved".to_vec(),
            next: None,
        },
    }])
    .expect("script");

    let server = HermeticGithubStubServer::start_with_listener(
        reservation.into_listener(),
        script,
        Vec::new(),
    )
    .expect("stub consumes held listener");
    assert_eq!(server.local_addr(), reserved_addr);
    let response = Client::new()
        .get(format!("{}/held-listener", server.origin()))
        .send()
        .await
        .expect("stub response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.expect("body"), "reserved");
    server.finish().await.expect("script consumed");
}

#[tokio::test]
async fn loopback_server_serves_all_closed_github_failure_classes() {
    let mutation = br#"{"name":"completed"}"#;
    let script = GithubStubScript::new(vec![
        GithubStubExchange {
            request: request("GET", "/repos/o/r/actions/runs?page=1", None),
            response: GithubStubResponse::Page {
                status: 200,
                body: br#"[{"id":1}]"#.to_vec(),
                next: Some("/repos/o/r/actions/runs?page=2".to_owned()),
            },
        },
        GithubStubExchange {
            request: request("GET", "/repos/o/r/actions/runs?page=2", None),
            response: GithubStubResponse::RateLimited {
                retry_after_millis: 1_001,
            },
        },
        GithubStubExchange {
            request: request("PATCH", "/repos/o/r/check-runs/7", Some(mutation)),
            response: GithubStubResponse::Mutation {
                status: 503,
                outcome: GithubMutationOutcome::Indeterminate,
                body: br#"{"message":"upstream outcome unknown"}"#.to_vec(),
            },
        },
        GithubStubExchange {
            request: request("GET", "/installation/repositories", None),
            response: GithubStubResponse::CredentialFailure { status: 401 },
        },
    ])
    .expect("exact script");
    let server = HermeticGithubStubServer::start(script, vec![credential()])
        .await
        .expect("loopback server");
    assert!(server.local_addr().ip().is_loopback());
    let origin = server.origin().to_owned();
    let client = Client::new();

    let first = client
        .get(format!("{origin}/repos/o/r/actions/runs?page=1"))
        .header(reqwest::header::AUTHORIZATION, AUTHORIZATION)
        .send()
        .await
        .expect("first page");
    assert_eq!(first.status(), StatusCode::OK);
    let expected_link = format!("<{origin}/repos/o/r/actions/runs?page=2>; rel=\"next\"");
    assert_eq!(
        first
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok()),
        Some(expected_link.as_str())
    );
    assert_eq!(
        first.bytes().await.expect("page body").as_ref(),
        br#"[{"id":1}]"#
    );

    let limited = client
        .get(format!("{origin}/repos/o/r/actions/runs?page=2"))
        .header(reqwest::header::AUTHORIZATION, AUTHORIZATION)
        .send()
        .await
        .expect("rate limit");
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers()[reqwest::header::RETRY_AFTER], "2");
    assert_eq!(limited.headers()["x-ratelimit-remaining"], "0");

    let indeterminate = client
        .patch(format!("{origin}/repos/o/r/check-runs/7"))
        .header(reqwest::header::AUTHORIZATION, AUTHORIZATION)
        .body(mutation.to_vec())
        .send()
        .await
        .expect("indeterminate mutation");
    assert_eq!(indeterminate.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        indeterminate.headers()[X_AUTOMATA_GITHUB_MUTATION_OUTCOME],
        "indeterminate"
    );

    let rejected = client
        .get(format!("{origin}/installation/repositories"))
        .header(reqwest::header::AUTHORIZATION, AUTHORIZATION)
        .send()
        .await
        .expect("credential failure");
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

    server.finish().await.expect("complete exact script");
}

#[tokio::test]
async fn reordered_requests_fail_closed_and_remain_unconsumed() {
    let script = GithubStubScript::new(vec![GithubStubExchange {
        request: request("GET", "/expected", None),
        response: GithubStubResponse::Page {
            status: 200,
            body: Vec::new(),
            next: None,
        },
    }])
    .expect("script");
    let server = HermeticGithubStubServer::start(script, vec![credential()])
        .await
        .expect("server");
    let response = Client::new()
        .get(format!("{}/out-of-order", server.origin()))
        .header(reqwest::header::AUTHORIZATION, AUTHORIZATION)
        .send()
        .await
        .expect("mismatched request response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(matches!(
        server.finish().await,
        Err(HermeticGithubStubError::Observed(
            HermeticGithubStubFailure::Script(GithubStubError::RequestMismatch)
        ))
    ));
}

#[tokio::test]
async fn unregistered_credentials_never_satisfy_an_anonymous_exchange() {
    let script = GithubStubScript::new(vec![GithubStubExchange {
        request: GithubStubRequest {
            method: "GET".to_owned(),
            path_and_query: "/anonymous".to_owned(),
            body_sha256: None,
            credential_id: None,
        },
        response: GithubStubResponse::Page {
            status: 200,
            body: Vec::new(),
            next: None,
        },
    }])
    .expect("script");
    let server = HermeticGithubStubServer::start(script, Vec::new())
        .await
        .expect("server");
    let response = Client::new()
        .get(format!("{}/anonymous", server.origin()))
        .header(reqwest::header::AUTHORIZATION, "Bearer unknown")
        .send()
        .await
        .expect("credential rejection");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(
        server.finish().await,
        Err(HermeticGithubStubError::Observed(
            HermeticGithubStubFailure::UnknownCredential
        ))
    ));
}

#[tokio::test]
async fn stopping_early_reports_the_unconsumed_script() {
    let script = GithubStubScript::new(vec![GithubStubExchange {
        request: request("GET", "/never-requested", None),
        response: GithubStubResponse::Page {
            status: 200,
            body: Vec::new(),
            next: None,
        },
    }])
    .expect("script");
    let server = HermeticGithubStubServer::start(script, vec![credential()])
        .await
        .expect("server");
    assert!(matches!(
        server.finish().await,
        Err(HermeticGithubStubError::IncompleteScript(
            GithubStubError::UnconsumedExchange
        ))
    ));
}
use std::fmt::Write as _;
