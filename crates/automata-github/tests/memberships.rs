mod support;

use std::time::Duration;

use automata_auth::{
    github::{GithubCurrentUserRequest, GithubEndpoint, GithubEndpointError},
    secret::SecretString,
};
use automata_github::GithubHttpLimits;
use axum::http::StatusCode;
use support::{FixtureServer, ResponseSpec};

fn token() -> SecretString {
    SecretString::new("ghu_membership_secret").unwrap()
}

#[tokio::test]
async fn active_organizations_and_teams_are_paginated_into_one_snapshot() {
    let fixture = FixtureServer::spawn().await;
    let organization_page_two =
        fixture.url("api/user/memberships/orgs?state=active&per_page=100&page=2");
    let team_page_two = fixture.url("api/user/teams?per_page=100&page=2");
    fixture.enqueue(
        ResponseSpec::json(
            StatusCode::OK,
            r#"[{"state":"active","organization":{"login":"Acme"}}]"#,
        )
        .header(
            "link",
            format!(
                "<{organization_page_two}>; rel=\"next\", <{organization_page_two}>; rel=\"last\""
            ),
        ),
    );
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"state":"active","organization":{"login":"Beta_Org"}}]"#,
    ));
    fixture.enqueue(
        ResponseSpec::json(
            StatusCode::OK,
            r#"[{"slug":"Platform","organization":{"login":"Acme"}}]"#,
        )
        .header("link", format!("<{team_page_two}>; rel=\"next\"")),
    );
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"slug":"release-engineering","organization":{"login":"Beta_Org"}}]"#,
    ));
    let endpoint = fixture.endpoint();
    let token = token();
    let snapshot = endpoint
        .memberships(GithubCurrentUserRequest {
            access_token: &token,
        })
        .await
        .unwrap();

    let organizations: Vec<_> = snapshot
        .organizations()
        .iter()
        .map(automata_auth::github::GithubOrganizationName::as_str)
        .collect();
    assert_eq!(organizations, ["acme", "beta_org"]);
    let teams: Vec<_> = snapshot
        .teams()
        .iter()
        .map(|team| (team.organization.as_str(), team.slug.as_str()))
        .collect();
    assert_eq!(
        teams,
        [("acme", "platform"), ("beta_org", "release-engineering")]
    );

    let requests = fixture.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[0].uri,
        "/api/user/memberships/orgs?state=active&per_page=100"
    );
    assert_eq!(
        requests[1].uri,
        "/api/user/memberships/orgs?state=active&per_page=100&page=2"
    );
    assert_eq!(requests[2].uri, "/api/user/teams?per_page=100");
    assert_eq!(requests[3].uri, "/api/user/teams?per_page=100&page=2");
    assert!(
        requests
            .iter()
            .all(|request| { request.headers["authorization"] == "Bearer ghu_membership_secret" })
    );
}

#[tokio::test]
async fn pagination_never_forwards_a_token_to_an_untrusted_origin() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(
        ResponseSpec::json(
            StatusCode::OK,
            r#"[{"state":"active","organization":{"login":"acme"}}]"#,
        )
        .header(
            "link",
            "<https://attacker.example/collect?page=2&per_page=100&state=active>; rel=\"next\"",
        ),
    );
    let endpoint = fixture.endpoint();
    let token = token();
    let error = endpoint
        .memberships(GithubCurrentUserRequest {
            access_token: &token,
        })
        .await
        .unwrap_err();
    assert_eq!(error, GithubEndpointError::InvalidResponse);
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn aggregate_page_and_item_caps_fail_closed() {
    let page_fixture = FixtureServer::spawn().await;
    let page_two = page_fixture.url("api/user/memberships/orgs?state=active&per_page=100&page=2");
    page_fixture.enqueue(
        ResponseSpec::json(
            StatusCode::OK,
            r#"[{"state":"active","organization":{"login":"acme"}}]"#,
        )
        .header("link", format!("<{page_two}>; rel=\"next\"")),
    );
    let page_limits = GithubHttpLimits::new(
        4_096,
        1,
        100,
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .unwrap();
    let page_endpoint = page_fixture.endpoint_with_limits(page_limits);
    let token = token();
    assert_eq!(
        page_endpoint
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );
    assert_eq!(page_fixture.requests().len(), 1);

    let item_fixture = FixtureServer::spawn().await;
    item_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[
            {"state":"active","organization":{"login":"acme"}},
            {"state":"active","organization":{"login":"beta"}}
        ]"#,
    ));
    let item_limits =
        GithubHttpLimits::new(4_096, 10, 1, Duration::from_secs(1), Duration::from_secs(2))
            .unwrap();
    let item_endpoint = item_fixture.endpoint_with_limits(item_limits);
    assert_eq!(
        item_endpoint
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );
    assert_eq!(item_fixture.requests().len(), 1);
}

#[tokio::test]
async fn pending_memberships_and_orphan_teams_are_rejected() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"state":"pending","organization":{"login":"acme"}}]"#,
    ));
    let endpoint = fixture.endpoint();
    let token = token();
    assert_eq!(
        endpoint
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );

    let orphan_fixture = FixtureServer::spawn().await;
    orphan_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"state":"active","organization":{"login":"acme"}}]"#,
    ));
    orphan_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"slug":"platform","organization":{"login":"other"}}]"#,
    ));
    let orphan_endpoint = orphan_fixture.endpoint();
    assert_eq!(
        orphan_endpoint
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );
}
