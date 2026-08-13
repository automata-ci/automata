use automata_ci_conformance::{
    GithubMutationOutcome, GithubStubError, GithubStubExchange, GithubStubRequest,
    GithubStubResponse, GithubStubScript,
};

fn request(path: &str) -> GithubStubRequest {
    GithubStubRequest {
        method: "GET".to_owned(),
        path_and_query: path.to_owned(),
        body_sha256: None,
        credential_id: Some("installation-42".to_owned()),
    }
}

#[test]
fn pagination_rate_limit_credential_and_indeterminate_mutation_are_scriptable() {
    let first = request("/repos/o/r/actions/runs?page=1");
    let second = request("/repos/o/r/actions/runs?page=2");
    let mut mutation = request("/repos/o/r/check-runs/7");
    mutation.method = "PATCH".to_owned();
    mutation.body_sha256 = Some("a".repeat(64));
    let script = GithubStubScript::new(vec![
        GithubStubExchange {
            request: first.clone(),
            response: GithubStubResponse::Page {
                status: 200,
                body: b"[]".to_vec(),
                next: Some("/repos/o/r/actions/runs?page=2".to_owned()),
            },
        },
        GithubStubExchange {
            request: second.clone(),
            response: GithubStubResponse::RateLimited {
                retry_after_millis: 1_000,
            },
        },
        GithubStubExchange {
            request: mutation.clone(),
            response: GithubStubResponse::Mutation {
                status: 503,
                outcome: GithubMutationOutcome::Indeterminate,
                body: Vec::new(),
            },
        },
    ])
    .expect("script");
    assert!(matches!(
        script.respond(&first).expect("page"),
        GithubStubResponse::Page { .. }
    ));
    assert!(matches!(
        script.respond(&second).expect("rate limit"),
        GithubStubResponse::RateLimited { .. }
    ));
    assert!(matches!(
        script.respond(&mutation).expect("mutation"),
        GithubStubResponse::Mutation {
            outcome: GithubMutationOutcome::Indeterminate,
            ..
        }
    ));
    script.finish().expect("fully consumed");
}

#[test]
fn request_order_and_unconsumed_exchanges_fail_closed() {
    let first = request("/first");
    let second = request("/second");
    let script = GithubStubScript::new(vec![GithubStubExchange {
        request: first.clone(),
        response: GithubStubResponse::CredentialFailure { status: 401 },
    }])
    .expect("script");
    assert_eq!(
        script.respond(&second),
        Err(GithubStubError::RequestMismatch)
    );
    assert_eq!(script.finish(), Err(GithubStubError::UnconsumedExchange));
    assert!(matches!(
        script.respond(&first).expect("credential failure"),
        GithubStubResponse::CredentialFailure { status: 401 }
    ));
    assert_eq!(
        script.respond(&first),
        Err(GithubStubError::UnexpectedRequest)
    );
}
