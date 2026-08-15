use crate::support;

use std::time::Duration;

use automata_ci_auth::{
    github::{
        GithubCurrentUserRequest, GithubEndpoint, GithubEndpointError,
        GithubOrganizationMembershipRole,
    },
    secret::SecretString,
};
use automata_ci_github::GithubHttpLimits;
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
            r#"[{"state":"active","role":"admin","organization":{"id":101,"login":"Acme"}}]"#,
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
        r#"[{"state":"active","role":"member","organization":{"id":202,"login":"Beta_Org"}}]"#,
    ));
    fixture.enqueue(
        ResponseSpec::json(
            StatusCode::OK,
            r#"[{"id":1001,"slug":"Platform","organization":{"id":101,"login":"Acme"}}]"#,
        )
        .header("link", format!("<{team_page_two}>; rel=\"next\"")),
    );
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"id":1002,"slug":"release-engineering","organization":{"id":202,"login":"Beta_Org"}}]"#,
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
        .map(|membership| {
            (
                membership.id().get(),
                membership.login().as_str(),
                membership.role(),
            )
        })
        .collect();
    assert_eq!(
        organizations,
        [
            (101, "acme", GithubOrganizationMembershipRole::Admin),
            (202, "beta_org", GithubOrganizationMembershipRole::Member),
        ]
    );
    let teams: Vec<_> = snapshot
        .teams()
        .map(|team| {
            (
                team.id().get(),
                team.organization_id().get(),
                team.organization_login().as_str(),
                team.slug().as_str(),
            )
        })
        .collect();
    assert_eq!(
        teams,
        [
            (1001, 101, "acme", "platform"),
            (1002, 202, "beta_org", "release-engineering"),
        ]
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
            r#"[{"state":"active","role":"member","organization":{"id":101,"login":"acme"}}]"#,
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
            r#"[{"state":"active","role":"member","organization":{"id":101,"login":"acme"}}]"#,
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
            {"state":"active","role":"member","organization":{"id":101,"login":"acme"}},
            {"state":"active","role":"member","organization":{"id":202,"login":"beta"}}
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
        r#"[{"state":"pending","role":"member","organization":{"id":101,"login":"acme"}}]"#,
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
        r#"[{"state":"active","role":"member","organization":{"id":101,"login":"acme"}}]"#,
    ));
    orphan_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"id":1001,"slug":"platform","organization":{"id":202,"login":"other"}}]"#,
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

#[tokio::test]
async fn malformed_or_conflicting_stable_membership_identity_is_rejected() {
    let zero_id_fixture = FixtureServer::spawn().await;
    zero_id_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"state":"active","role":"member","organization":{"id":0,"login":"acme"}}]"#,
    ));
    let token = token();
    assert_eq!(
        zero_id_fixture
            .endpoint()
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );

    let duplicate_organization_fixture = FixtureServer::spawn().await;
    duplicate_organization_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[
            {"state":"active","role":"member","organization":{"id":101,"login":"acme"}},
            {"state":"active","role":"admin","organization":{"id":101,"login":"renamed"}}
        ]"#,
    ));
    duplicate_organization_fixture.enqueue(ResponseSpec::json(StatusCode::OK, r"[]"));
    assert_eq!(
        duplicate_organization_fixture
            .endpoint()
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );

    let inconsistent_parent_fixture = FixtureServer::spawn().await;
    inconsistent_parent_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"state":"active","role":"member","organization":{"id":101,"login":"acme"}}]"#,
    ));
    inconsistent_parent_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"id":1001,"slug":"platform","organization":{"id":101,"login":"lookalike"}}]"#,
    ));
    assert_eq!(
        inconsistent_parent_fixture
            .endpoint()
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );

    let conflicting_team_fixture = FixtureServer::spawn().await;
    conflicting_team_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"state":"active","role":"member","organization":{"id":101,"login":"acme"}}]"#,
    ));
    conflicting_team_fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[
            {"id":1001,"slug":"platform","organization":{"id":101,"login":"acme"}},
            {"id":1002,"slug":"platform","organization":{"id":101,"login":"acme"}}
        ]"#,
    ));
    assert_eq!(
        conflicting_team_fixture
            .endpoint()
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );
}

#[tokio::test]
async fn organization_membership_role_is_required_and_exact() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"[{"state":"active","role":"owner","organization":{"id":101,"login":"acme"}}]"#,
    ));
    let token = token();
    assert_eq!(
        fixture
            .endpoint()
            .memberships(GithubCurrentUserRequest {
                access_token: &token
            })
            .await
            .unwrap_err(),
        GithubEndpointError::InvalidResponse
    );
}
