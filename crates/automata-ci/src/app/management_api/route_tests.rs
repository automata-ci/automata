use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use automata_ci_auth::{
    authorization::AuthorizationContext,
    human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
    management::{
        DirectBindingGrantOptionsState, DirectRoleBindingSource, ManagementBindingRole,
        ManagementDetailFuture, ManagementMutationCapabilities, ManagementMutationFuture,
        ManagementReadFuture, ManagementScopeRecord, ProviderRoleMappingId,
        ReadDirectBindingGrantOptions, ReadManagementMutationCapabilities, RoleKind,
        RolePermissionRecord,
    },
    request_auth::ViewerDisplayMetadata,
    session::{DurableSession, DurableSessionIdentity, SessionId},
};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::*;

const ACTOR: &str = "11111111-1111-4111-8111-111111111111";
const TARGET: &str = "22222222-2222-4222-8222-222222222222";
const OTHER_TARGET: &str = "33333333-3333-4333-8333-333333333333";
const ROLE: &str = "44444444-4444-4444-8444-444444444444";
const OTHER_ROLE: &str = "55555555-5555-4555-8555-555555555555";
const DIRECT_BINDING: &str = "66666666-6666-4666-8666-666666666666";
const PROVIDER_BINDING: &str = "77777777-7777-4777-8777-777777777777";
const NEXT_BINDING: &str = "88888888-8888-4888-8888-888888888888";
const PROVIDER_MAPPING: &str = "99999999-9999-4999-8999-999999999999";
const AUTHORIZATION_REVISION: u64 = 7;

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecordedRead {
    Member {
        principal_id: ManagedPrincipalId,
        authorization_revision: ManagementRevision,
    },
    Assignments {
        principal_id: Option<ManagedPrincipalId>,
        cursor: Option<String>,
        limit: u16,
        authorization_revision: ManagementRevision,
    },
    Role {
        role_id: RoleId,
        authorization_revision: ManagementRevision,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecordedMutation {
    MemberStatus {
        principal_id: ManagedPrincipalId,
        expected_revision: ManagementRevision,
    },
    RoleUpdate {
        role_id: RoleId,
        expected_revision: ManagementRevision,
    },
}

#[derive(Debug)]
struct DetailRepository {
    member: MemberReadResult,
    assignments: AssignmentReadResult,
    role: RoleReadResult,
    member_mutation: MemberMutationResult,
    role_mutation: RoleMutationResult,
    reads: Mutex<Vec<RecordedRead>>,
    mutations: Mutex<Vec<RecordedMutation>>,
}

type MemberReadResult = Result<ManagementDetailOutcome<MemberRecord>, ManagementRepositoryError>;
type AssignmentReadResult = Result<
    ManagementReadOutcome<ManagementPage<ManagementRoleBindingRecord>>,
    ManagementRepositoryError,
>;
type RoleReadResult = Result<ManagementDetailOutcome<RoleDetailRecord>, ManagementRepositoryError>;
type MemberMutationResult =
    Result<ManagementMutationOutcome<MemberRecord>, ManagementRepositoryError>;
type RoleMutationResult = Result<ManagementMutationOutcome<RoleRecord>, ManagementRepositoryError>;

impl DetailRepository {
    fn new(
        member: MemberReadResult,
        assignments: AssignmentReadResult,
        role: RoleReadResult,
    ) -> Arc<Self> {
        Self::with_mutations(
            member,
            assignments,
            role,
            Err(ManagementRepositoryError::Unavailable),
            Err(ManagementRepositoryError::Unavailable),
        )
    }

    fn with_mutations(
        member: MemberReadResult,
        assignments: AssignmentReadResult,
        role: RoleReadResult,
        member_mutation: MemberMutationResult,
        role_mutation: RoleMutationResult,
    ) -> Arc<Self> {
        Arc::new(Self {
            member,
            assignments,
            role,
            member_mutation,
            role_mutation,
            reads: Mutex::new(Vec::new()),
            mutations: Mutex::new(Vec::new()),
        })
    }

    fn reads(&self) -> Vec<RecordedRead> {
        self.reads.lock().expect("read log lock").clone()
    }

    fn mutations(&self) -> Vec<RecordedMutation> {
        self.mutations.lock().expect("mutation log lock").clone()
    }
}

fn unavailable_read<'a, T: Send + 'a>() -> ManagementReadFuture<'a, T> {
    Box::pin(async { Err(ManagementRepositoryError::Unavailable) })
}

fn unavailable_mutation<'a, T: Send + 'a>() -> ManagementMutationFuture<'a, T> {
    Box::pin(async { Err(ManagementRepositoryError::Unavailable) })
}

impl HumanRbacManagementRepository for DetailRepository {
    fn read_mutation_capabilities<'a>(
        &'a self,
        _request: &'a ReadManagementMutationCapabilities,
    ) -> ManagementReadFuture<'a, ManagementMutationCapabilities> {
        unavailable_read()
    }

    fn read_direct_binding_grant_options<'a>(
        &'a self,
        _request: &'a ReadDirectBindingGrantOptions,
    ) -> ManagementReadFuture<'a, DirectBindingGrantOptionsState> {
        unavailable_read()
    }

    fn list_members<'a>(
        &'a self,
        _request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<MemberRecord>> {
        unavailable_read()
    }

    fn list_roles<'a>(
        &'a self,
        _request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<RoleRecord>> {
        unavailable_read()
    }

    fn list_role_bindings<'a>(
        &'a self,
        _request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<RoleBindingRecord>> {
        unavailable_read()
    }

    fn read_member_detail<'a>(
        &'a self,
        request: &'a ReadMemberDetail,
    ) -> ManagementDetailFuture<'a, MemberRecord> {
        self.reads
            .lock()
            .expect("read log lock")
            .push(RecordedRead::Member {
                principal_id: request.principal_id(),
                authorization_revision: request.actor().authorization_revision(),
            });
        let result = self.member.clone();
        Box::pin(async move { result })
    }

    fn read_role_detail<'a>(
        &'a self,
        request: &'a ReadRoleDetail,
    ) -> ManagementDetailFuture<'a, RoleDetailRecord> {
        self.reads
            .lock()
            .expect("read log lock")
            .push(RecordedRead::Role {
                role_id: request.role_id(),
                authorization_revision: request.actor().authorization_revision(),
            });
        let result = self.role.clone();
        Box::pin(async move { result })
    }

    fn list_management_role_bindings<'a>(
        &'a self,
        request: &'a ListManagementRoleBindings,
    ) -> ManagementReadFuture<'a, ManagementPage<ManagementRoleBindingRecord>> {
        self.reads
            .lock()
            .expect("read log lock")
            .push(RecordedRead::Assignments {
                principal_id: request.principal_id(),
                cursor: request.cursor().map(ManagementRoleBindingCursor::encode),
                limit: request.limit().value(),
                authorization_revision: request.actor().authorization_revision(),
            });
        let result = self.assignments.clone();
        Box::pin(async move { result })
    }

    fn create_role(&self, _request: CreateRole) -> ManagementMutationFuture<'_, RoleRecord> {
        unavailable_mutation()
    }

    fn update_role(&self, request: UpdateRole) -> ManagementMutationFuture<'_, RoleRecord> {
        self.mutations
            .lock()
            .expect("mutation log lock")
            .push(RecordedMutation::RoleUpdate {
                role_id: request.role_id(),
                expected_revision: request.expected_revision(),
            });
        let result = self.role_mutation.clone();
        Box::pin(async move { result })
    }

    fn delete_role(&self, _request: DeleteRole) -> ManagementMutationFuture<'_, ()> {
        unavailable_mutation()
    }

    fn set_role_permission(
        &self,
        _request: SetRolePermission,
    ) -> ManagementMutationFuture<'_, RoleRecord> {
        unavailable_mutation()
    }

    fn grant_role(&self, _request: GrantRole) -> ManagementMutationFuture<'_, RoleBindingRecord> {
        unavailable_mutation()
    }

    fn revoke_role(&self, _request: RevokeRole) -> ManagementMutationFuture<'_, RoleBindingRecord> {
        unavailable_mutation()
    }

    fn change_member_status(
        &self,
        request: ChangeMemberStatus,
    ) -> ManagementMutationFuture<'_, MemberRecord> {
        self.mutations
            .lock()
            .expect("mutation log lock")
            .push(RecordedMutation::MemberStatus {
                principal_id: request.principal_id(),
                expected_revision: request.expected_revision(),
            });
        let result = self.member_mutation.clone();
        Box::pin(async move { result })
    }
}

#[derive(Clone, Copy, Debug)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        UnixTimestamp::from_seconds(700)
    }
}

fn revision(value: u64) -> ManagementRevision {
    ManagementRevision::new(value).expect("management revision")
}

fn principal(value: &str) -> ManagedPrincipalId {
    ManagedPrincipalId::new(value).expect("managed principal")
}

fn role_id(value: &str) -> RoleId {
    RoleId::new(value).expect("role ID")
}

fn member(status: MemberStatus) -> MemberRecord {
    member_at_revision(status, 13)
}

fn member_at_revision(status: MemberStatus, target_revision: u64) -> MemberRecord {
    MemberRecord::new(
        principal(TARGET),
        ProviderId::new("github").expect("provider"),
        "octocat",
        Some("Octo Cat".to_owned()),
        status,
        revision(11),
        revision(target_revision),
    )
    .expect("member")
}

fn role(kind: RoleKind) -> RoleRecord {
    role_at_revision(kind, 17)
}

fn role_at_revision(kind: RoleKind, target_revision: u64) -> RoleRecord {
    let (name, display_name, immutable) = match kind {
        RoleKind::BuiltIn => ("auditor", "Auditor", true),
        RoleKind::Custom => ("release-reviewer", "Release reviewer", false),
    };
    RoleRecord::new(
        role_id(ROLE),
        RoleName::new(name).expect("role name"),
        display_name,
        kind,
        immutable,
        revision(target_revision),
        BTreeSet::from([Permission::new("members:read").expect("permission")]),
    )
    .expect("role")
}

fn role_detail(kind: RoleKind) -> RoleDetailRecord {
    RoleDetailRecord::new(
        role(kind),
        vec![
            RolePermissionRecord::new(
                Permission::new("members:read").expect("permission"),
                "Read tenant members.",
                false,
                true,
            )
            .expect("permission record"),
            RolePermissionRecord::new(
                Permission::new("roles:read").expect("permission"),
                "Read tenant roles.",
                true,
                false,
            )
            .expect("permission record"),
        ],
    )
    .expect("role detail")
}

fn assignment(
    id: &str,
    user: &MemberRecord,
    source: ManagementRoleBindingSource,
    valid_until: Option<u64>,
) -> ManagementRoleBindingRecord {
    ManagementRoleBindingRecord::new(
        RoleBindingId::new(id).expect("binding ID"),
        user.clone(),
        ManagementBindingRole::new(
            role_id(ROLE),
            RoleName::new("release-reviewer").expect("role name"),
            "Release reviewer",
        )
        .expect("binding role"),
        ManagementScopeRecord::new(
            AuthorizationScope::tenant(TenantId::new("tenant-a").expect("tenant")),
            "Tenant A",
        )
        .expect("management scope"),
        source,
        automata_ci_auth::management::RoleBindingStatus::Active,
        valid_until.map(UnixTimestamp::from_seconds),
        revision(19),
    )
    .expect("assignment")
}

fn assignment_page(
    items: Vec<ManagementRoleBindingRecord>,
    next_cursor: Option<String>,
    limit: u16,
) -> ManagementPage<ManagementRoleBindingRecord> {
    ManagementPage::new_authorized(
        items,
        next_cursor,
        ManagementPageSize::new(limit).expect("page size"),
        revision(AUTHORIZATION_REVISION),
    )
    .expect("assignment page")
}

fn snapshot(kind: SessionKind) -> AuthenticatedRequestSnapshot {
    let tenant = TenantId::new("tenant-a").expect("tenant");
    let principal_id = PrincipalId::new(ACTOR).expect("principal");
    let provider = ProviderId::new("github").expect("provider");
    let subject = ProviderSubject::new("42").expect("subject");
    let identity = DurableSessionIdentity::new(
        SessionId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("session"),
        tenant.clone(),
        principal_id.clone(),
        provider.clone(),
        subject.clone(),
        kind,
    )
    .expect("identity");
    let session = DurableSession::new(
        identity,
        AUTHORIZATION_REVISION,
        UnixTimestamp::from_seconds(1),
        UnixTimestamp::from_seconds(2),
        UnixTimestamp::from_seconds(900),
        UnixTimestamp::from_seconds(1_000),
        None,
    )
    .expect("session");
    let human = AuthenticatedHuman::new(
        principal_id.clone(),
        provider,
        subject,
        "manager",
        Some("Manager".to_owned()),
        UnixTimestamp::from_seconds(1),
    )
    .expect("human");
    let authorization = AuthorizationContext::authenticated_at_revision(
        tenant,
        principal_id,
        BTreeSet::new(),
        AUTHORIZATION_REVISION,
    )
    .expect("authorization");
    AuthenticatedRequestSnapshot::new(
        session,
        human,
        ViewerDisplayMetadata::new("Manager").expect("viewer"),
        authorization,
    )
    .expect("snapshot")
}

fn router(repository: Arc<DetailRepository>) -> Router {
    let repository: Arc<dyn HumanRbacManagementRepository> = repository;
    management_api_router(repository, Arc::new(FixedClock))
}

fn get_request(uri: &str, session_kind: Option<SessionKind>, body: Body) -> Request<Body> {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(kind) = session_kind {
        builder = builder.extension(snapshot(kind));
    }
    builder.body(body).expect("request")
}

async fn response_body(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("bounded response body")
        .to_vec()
}

async fn response_json(response: Response) -> Value {
    serde_json::from_slice(&response_body(response).await).expect("JSON response")
}

async fn detail_revision(app: Router, uri: &str, entity: &str) -> u64 {
    let response = app
        .oneshot(get_request(uri, Some(SessionKind::Cli), Body::empty()))
        .await
        .expect("detail response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::ETAG).is_none());
    response_json(response).await[entity]["revision"]
        .as_u64()
        .expect("detail revision")
}

fn assert_value_free(document: &Value) {
    let encoded = serde_json::to_string(document).expect("encoded document");
    for forbidden in [
        "csrf",
        "action",
        "expected_revision",
        "authorization_revision",
        "capabilit",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[tokio::test]
async fn user_detail_is_value_free_and_pages_exact_direct_and_provider_assignments() {
    let user = member(MemberStatus::Active);
    let assignments = assignment_page(
        vec![
            assignment(
                DIRECT_BINDING,
                &user,
                ManagementRoleBindingSource::Direct(DirectRoleBindingSource::Manual),
                None,
            ),
            assignment(
                PROVIDER_BINDING,
                &user,
                ManagementRoleBindingSource::ProviderObserved {
                    mapping_id: ProviderRoleMappingId::new(PROVIDER_MAPPING)
                        .expect("provider mapping"),
                },
                Some(900),
            ),
        ],
        Some(format!("d:{NEXT_BINDING}")),
        2,
    );
    let repository = DetailRepository::new(
        Ok(ManagementDetailOutcome::Authorized(user)),
        Ok(ManagementReadOutcome::Authorized(assignments)),
        Ok(ManagementDetailOutcome::NotFound),
    );
    let response = router(Arc::clone(&repository))
        .oneshot(get_request(
            &format!("/api/v1/users/{TARGET}?limit=2"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert!(response.headers().get(header::ETAG).is_none());
    let document = response_json(response).await;
    assert_eq!(
        document["user"],
        json!({
            "principal_id": TARGET,
            "provider_id": "github",
            "provider_login": "octocat",
            "display_name": "Octo Cat",
            "status": "active",
            "revision": 13
        })
    );
    assert_eq!(
        document["role_assignments"]["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        document["role_assignments"]["items"][0],
        json!({
            "id": DIRECT_BINDING,
            "role": {
                "id": ROLE,
                "name": "release-reviewer",
                "display_name": "Release reviewer"
            },
            "scope": {"kind": "tenant", "display_name": "Tenant A"},
            "source": "direct",
            "status": "active",
            "valid_until_seconds": null
        })
    );
    assert_eq!(
        document["role_assignments"]["items"][1]["source"],
        "provider_observed"
    );
    assert_eq!(
        document["role_assignments"]["next_cursor"],
        format!("d:{NEXT_BINDING}")
    );
    assert_value_free(&document);
    assert_eq!(
        repository.reads(),
        vec![
            RecordedRead::Member {
                principal_id: principal(TARGET),
                authorization_revision: revision(AUTHORIZATION_REVISION),
            },
            RecordedRead::Assignments {
                principal_id: Some(principal(TARGET)),
                cursor: None,
                limit: 2,
                authorization_revision: revision(AUTHORIZATION_REVISION),
            },
        ]
    );
}

#[tokio::test]
async fn suspended_user_detail_uses_the_same_bounded_read_only_shape() {
    let user = member(MemberStatus::Suspended);
    let repository = DetailRepository::new(
        Ok(ManagementDetailOutcome::Authorized(user)),
        Ok(ManagementReadOutcome::Authorized(assignment_page(
            Vec::new(),
            None,
            DEFAULT_DETAIL_ASSIGNMENT_PAGE_SIZE,
        ))),
        Ok(ManagementDetailOutcome::NotFound),
    );
    let response = router(repository)
        .oneshot(get_request(
            &format!("/api/v1/users/{TARGET}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let document = response_json(response).await;
    assert_eq!(document["user"]["status"], "suspended");
    assert_eq!(document["role_assignments"]["items"], json!([]));
    assert_eq!(document["role_assignments"]["next_cursor"], Value::Null);
}

#[tokio::test]
async fn role_detail_projects_built_in_and_custom_roles_with_the_complete_catalog() {
    for kind in [RoleKind::BuiltIn, RoleKind::Custom] {
        let repository = DetailRepository::new(
            Ok(ManagementDetailOutcome::NotFound),
            Err(ManagementRepositoryError::Unavailable),
            Ok(ManagementDetailOutcome::Authorized(role_detail(kind))),
        );
        let response = router(Arc::clone(&repository))
            .oneshot(get_request(
                &format!("/api/v1/roles/{ROLE}"),
                Some(SessionKind::Cli),
                Body::empty(),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::ETAG).is_none());
        let document = response_json(response).await;
        assert_eq!(document["role"]["id"], ROLE);
        assert_eq!(
            document["role"]["kind"],
            match kind {
                RoleKind::BuiltIn => "built_in",
                RoleKind::Custom => "custom",
            }
        );
        assert_eq!(document["role"]["immutable"], kind == RoleKind::BuiltIn);
        assert_eq!(document["role"]["revision"], 17);
        assert_eq!(document["role"]["permission_count"], 1);
        assert_eq!(
            document["permission_catalog"],
            json!([
                {
                    "name": "members:read",
                    "description": "Read tenant members.",
                    "critical": false,
                    "granted": true
                },
                {
                    "name": "roles:read",
                    "description": "Read tenant roles.",
                    "critical": true,
                    "granted": false
                }
            ])
        );
        let encoded = serde_json::to_string(&document).expect("encoded document");
        assert!(!encoded.contains("csrf"));
        assert!(!encoded.contains("action"));
        assert_eq!(
            repository.reads(),
            vec![RecordedRead::Role {
                role_id: role_id(ROLE),
                authorization_revision: revision(AUTHORIZATION_REVISION),
            }]
        );
    }
}

#[tokio::test]
async fn detail_revisions_round_trip_as_exact_mutation_preconditions() {
    let repository = DetailRepository::with_mutations(
        Ok(ManagementDetailOutcome::Authorized(member(
            MemberStatus::Active,
        ))),
        Ok(ManagementReadOutcome::Authorized(assignment_page(
            Vec::new(),
            None,
            DEFAULT_DETAIL_ASSIGNMENT_PAGE_SIZE,
        ))),
        Ok(ManagementDetailOutcome::Authorized(role_detail(
            RoleKind::Custom,
        ))),
        Ok(ManagementMutationOutcome::Applied(member_at_revision(
            MemberStatus::Suspended,
            14,
        ))),
        Ok(ManagementMutationOutcome::Applied(role_at_revision(
            RoleKind::Custom,
            18,
        ))),
    );
    let app = router(Arc::clone(&repository));

    let user_revision =
        detail_revision(app.clone(), &format!("/api/v1/users/{TARGET}"), "user").await;
    assert_eq!(user_revision, 13);

    let changed_user = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/users/{TARGET}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, format!("\"{user_revision}\""))
                .extension(snapshot(SessionKind::Cli))
                .body(Body::from(
                    r#"{"status":"suspended","reason":"policy review"}"#,
                ))
                .expect("status mutation request"),
        )
        .await
        .expect("status mutation response");
    assert_eq!(changed_user.status(), StatusCode::OK);
    assert_eq!(changed_user.headers()[header::ETAG], "\"14\"");
    assert_eq!(response_json(changed_user).await["revision"], 14);

    let role_revision =
        detail_revision(app.clone(), &format!("/api/v1/roles/{ROLE}"), "role").await;
    assert_eq!(role_revision, 17);

    let updated_role = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/roles/{ROLE}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, format!("\"{role_revision}\""))
                .extension(snapshot(SessionKind::Cli))
                .body(Body::from(r#"{"display_name":"Release approver"}"#))
                .expect("role mutation request"),
        )
        .await
        .expect("role mutation response");
    assert_eq!(updated_role.status(), StatusCode::OK);
    assert_eq!(updated_role.headers()[header::ETAG], "\"18\"");
    assert_eq!(response_json(updated_role).await["revision"], 18);

    assert_eq!(
        repository.mutations(),
        vec![
            RecordedMutation::MemberStatus {
                principal_id: principal(TARGET),
                expected_revision: revision(13),
            },
            RecordedMutation::RoleUpdate {
                role_id: role_id(ROLE),
                expected_revision: revision(17),
            },
        ]
    );
}

#[tokio::test]
async fn stale_detail_revisions_return_exact_409_conflicts_with_current_revisions() {
    let repository = DetailRepository::with_mutations(
        Ok(ManagementDetailOutcome::Authorized(member(
            MemberStatus::Active,
        ))),
        Ok(ManagementReadOutcome::Authorized(assignment_page(
            Vec::new(),
            None,
            DEFAULT_DETAIL_ASSIGNMENT_PAGE_SIZE,
        ))),
        Ok(ManagementDetailOutcome::Authorized(role_detail(
            RoleKind::Custom,
        ))),
        Ok(ManagementMutationOutcome::RevisionConflict {
            current: revision(14),
        }),
        Ok(ManagementMutationOutcome::RevisionConflict {
            current: revision(18),
        }),
    );
    let app = router(Arc::clone(&repository));

    for (method, uri, stale, body, current) in [
        (
            Method::PATCH,
            format!("/api/v1/users/{TARGET}"),
            13,
            r#"{"status":"suspended","reason":"policy review"}"#,
            14,
        ),
        (
            Method::PATCH,
            format!("/api/v1/roles/{ROLE}"),
            17,
            r#"{"display_name":"Release approver"}"#,
            18,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::IF_MATCH, format!("\"{stale}\""))
                    .extension(snapshot(SessionKind::Cli))
                    .body(Body::from(body))
                    .expect("stale mutation request"),
            )
            .await
            .expect("stale mutation response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(response.headers().get(header::ETAG).is_none());
        assert_eq!(
            response_json(response).await,
            json!({"error": "revision_conflict", "current_revision": current})
        );
    }

    assert_eq!(
        repository.mutations(),
        vec![
            RecordedMutation::MemberStatus {
                principal_id: principal(TARGET),
                expected_revision: revision(13),
            },
            RecordedMutation::RoleUpdate {
                role_id: role_id(ROLE),
                expected_revision: revision(17),
            },
        ]
    );
}

#[test]
fn assignment_queries_are_bounded_canonical_and_principal_scoped() {
    let target = principal(TARGET);
    let (cursor, limit) = assignment_query(None, target).expect("default query");
    assert_eq!(cursor, None);
    assert_eq!(limit.value(), DEFAULT_DETAIL_ASSIGNMENT_PAGE_SIZE);

    let direct = format!("d:{DIRECT_BINDING}");
    let (cursor, limit) = assignment_query(Some(&format!("cursor={direct}&limit=100")), target)
        .expect("direct cursor");
    assert_eq!(cursor.as_deref(), Some(direct.as_str()));
    assert_eq!(limit.value(), 100);

    let provider = format!("g:{TARGET}:{PROVIDER_MAPPING}");
    assert!(assignment_query(Some(&format!("cursor={provider}&limit=1")), target).is_ok());
    for invalid in [
        "",
        "limit=0",
        "limit=01",
        "limit=101",
        "limit=1&limit=2",
        "cursor=not-a-cursor",
        &format!("cursor=g:{OTHER_TARGET}:{PROVIDER_MAPPING}"),
        "unknown=1",
    ] {
        assert_eq!(
            assignment_query(Some(invalid), target),
            Err(ApiError::InvalidRequest),
            "query {invalid:?} must fail closed"
        );
    }
    assert_eq!(
        assignment_query(Some(&"x".repeat(MAX_QUERY_BYTES + 1)), target),
        Err(ApiError::InvalidRequest)
    );
}

#[tokio::test]
async fn detail_routes_require_cli_auth_and_keep_forbidden_targets_non_enumerating() {
    let forbidden = || {
        DetailRepository::new(
            Ok(ManagementDetailOutcome::Forbidden),
            Err(ManagementRepositoryError::Unavailable),
            Ok(ManagementDetailOutcome::Forbidden),
        )
    };
    let forbidden_response = router(forbidden())
        .oneshot(get_request(
            &format!("/api/v1/users/{TARGET}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("forbidden response");
    let not_found = DetailRepository::new(
        Ok(ManagementDetailOutcome::NotFound),
        Err(ManagementRepositoryError::Unavailable),
        Ok(ManagementDetailOutcome::NotFound),
    );
    let missing_response = router(not_found)
        .oneshot(get_request(
            &format!("/api/v1/users/{OTHER_TARGET}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("not-found response");
    assert_eq!(forbidden_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(missing_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_body(forbidden_response).await,
        response_body(missing_response).await
    );

    let existing_user = member(MemberStatus::Active);
    let assignment_forbidden = DetailRepository::new(
        Ok(ManagementDetailOutcome::Authorized(existing_user)),
        Ok(ManagementReadOutcome::Forbidden),
        Ok(ManagementDetailOutcome::NotFound),
    );
    let assignment_forbidden_response = router(assignment_forbidden)
        .oneshot(get_request(
            &format!("/api/v1/users/{TARGET}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("assignment-forbidden response");
    let missing = DetailRepository::new(
        Ok(ManagementDetailOutcome::NotFound),
        Err(ManagementRepositoryError::Unavailable),
        Ok(ManagementDetailOutcome::NotFound),
    );
    let missing_response = router(missing)
        .oneshot(get_request(
            &format!("/api/v1/users/{OTHER_TARGET}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("missing response");
    assert_eq!(
        assignment_forbidden_response.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        response_body(assignment_forbidden_response).await,
        response_body(missing_response).await
    );

    for kind in [None, Some(SessionKind::Browser)] {
        let repository = forbidden();
        let response = router(Arc::clone(&repository))
            .oneshot(get_request(
                &format!("/api/v1/roles/{ROLE}"),
                kind,
                Body::empty(),
            ))
            .await
            .expect("unauthorized response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer realm=\"automata\""
        );
        assert!(repository.reads().is_empty());
    }
}

#[tokio::test]
async fn stale_detail_or_assignment_authority_returns_the_same_sanitized_unauthorized_contract() {
    let stale_role = DetailRepository::new(
        Ok(ManagementDetailOutcome::NotFound),
        Err(ManagementRepositoryError::Unavailable),
        Ok(ManagementDetailOutcome::SessionStale),
    );
    let role_response = router(stale_role)
        .oneshot(get_request(
            &format!("/api/v1/roles/{ROLE}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("stale response");

    let user = member(MemberStatus::Active);
    let stale_assignments = DetailRepository::new(
        Ok(ManagementDetailOutcome::Authorized(user)),
        Ok(ManagementReadOutcome::SessionStale),
        Ok(ManagementDetailOutcome::NotFound),
    );
    let user_response = router(stale_assignments)
        .oneshot(get_request(
            &format!("/api/v1/users/{TARGET}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("stale response");
    assert_eq!(role_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(user_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_body(role_response).await,
        response_body(user_response).await
    );
}

#[tokio::test]
async fn corrupt_unavailable_and_misdirected_repository_results_fail_closed() {
    for (error, status, code) in [
        (
            ManagementRepositoryError::CorruptData,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        ),
        (
            ManagementRepositoryError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
        ),
    ] {
        let repository = DetailRepository::new(
            Ok(ManagementDetailOutcome::NotFound),
            Err(ManagementRepositoryError::Unavailable),
            Err(error),
        );
        let response = router(repository)
            .oneshot(get_request(
                &format!("/api/v1/roles/{ROLE}"),
                Some(SessionKind::Cli),
                Body::empty(),
            ))
            .await
            .expect("error response");
        assert_eq!(response.status(), status);
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        }
        assert_eq!(response_json(response).await, json!({"error": code}));
    }

    let wrong_role = RoleDetailRecord::new(
        RoleRecord::new(
            role_id(OTHER_ROLE),
            RoleName::new("other-role").expect("role name"),
            "Other role",
            RoleKind::Custom,
            false,
            revision(1),
            BTreeSet::from([Permission::new("members:read").expect("permission")]),
        )
        .expect("role"),
        vec![
            RolePermissionRecord::new(
                Permission::new("members:read").expect("permission"),
                "Read tenant members.",
                false,
                true,
            )
            .expect("permission record"),
        ],
    )
    .expect("role detail");
    let repository = DetailRepository::new(
        Ok(ManagementDetailOutcome::NotFound),
        Err(ManagementRepositoryError::Unavailable),
        Ok(ManagementDetailOutcome::Authorized(wrong_role)),
    );
    let response = router(repository)
        .oneshot(get_request(
            &format!("/api/v1/roles/{ROLE}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("misdirected response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let user = member(MemberStatus::Active);
    let page_without_authorization_fence = ManagementPage::new(
        Vec::<ManagementRoleBindingRecord>::new(),
        None,
        ManagementPageSize::new(1).expect("page size"),
    )
    .expect("unfenced page");
    let repository = DetailRepository::new(
        Ok(ManagementDetailOutcome::Authorized(user)),
        Ok(ManagementReadOutcome::Authorized(
            page_without_authorization_fence,
        )),
        Ok(ManagementDetailOutcome::NotFound),
    );
    let response = router(repository)
        .oneshot(get_request(
            &format!("/api/v1/users/{TARGET}"),
            Some(SessionKind::Cli),
            Body::empty(),
        ))
        .await
        .expect("unfenced response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn assignment_repository_failures_are_sanitized_after_the_exact_member_read() {
    for (error, status, code) in [
        (
            ManagementRepositoryError::InvalidRequest,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        ),
        (
            ManagementRepositoryError::CorruptData,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        ),
        (
            ManagementRepositoryError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
        ),
    ] {
        let repository = DetailRepository::new(
            Ok(ManagementDetailOutcome::Authorized(member(
                MemberStatus::Active,
            ))),
            Err(error),
            Ok(ManagementDetailOutcome::NotFound),
        );
        let response = router(repository)
            .oneshot(get_request(
                &format!("/api/v1/users/{TARGET}"),
                Some(SessionKind::Cli),
                Body::empty(),
            ))
            .await
            .expect("assignment error response");
        assert_eq!(response.status(), status);
        assert_eq!(response_json(response).await, json!({"error": code}));
    }
}

#[tokio::test]
async fn item_routes_reject_alias_queries_bodies_and_noncanonical_paths_before_storage() {
    let repository = DetailRepository::new(
        Ok(ManagementDetailOutcome::Forbidden),
        Err(ManagementRepositoryError::Unavailable),
        Ok(ManagementDetailOutcome::Forbidden),
    );
    for (uri, body) in [
        (format!("/api/v1/roles/{ROLE}?limit=1"), Body::empty()),
        (format!("/api/v1/roles/{ROLE}?"), Body::empty()),
        (format!("/api/v1/users/{TARGET}?unknown=1"), Body::empty()),
        (format!("/api/v1/users/{TARGET}"), Body::from("x")),
        (
            "/api/v1/users/00000000-0000-0000-0000-000000000000".to_owned(),
            Body::empty(),
        ),
        (
            "/api/v1/roles/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".to_owned(),
            Body::empty(),
        ),
    ] {
        let response = router(Arc::clone(&repository))
            .oneshot(get_request(&uri, Some(SessionKind::Cli), body))
            .await
            .expect("invalid response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    assert!(repository.reads().is_empty());

    for uri in [
        format!("/api/v1/users/{TARGET}/extra"),
        format!("/api/v1/roles/{ROLE}/extra"),
        "/api/v1/users/".to_owned(),
    ] {
        let response = router(Arc::clone(&repository))
            .oneshot(get_request(&uri, Some(SessionKind::Cli), Body::empty()))
            .await
            .expect("unreachable response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }

    let response = router(Arc::clone(&repository))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/users/{TARGET}"))
                .extension(snapshot(SessionKind::Cli))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("method response");
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(repository.reads().is_empty());
}

#[tokio::test]
async fn bodyless_collection_and_mutation_routes_reject_payloads_before_storage() {
    let repository = DetailRepository::new(
        Ok(ManagementDetailOutcome::NotFound),
        Err(ManagementRepositoryError::Unavailable),
        Ok(ManagementDetailOutcome::NotFound),
    );

    for uri in [USERS_PATH, ROLES_PATH, DIRECT_BINDINGS_PATH] {
        let response = router(Arc::clone(&repository))
            .oneshot(get_request(
                uri,
                Some(SessionKind::Cli),
                Body::from("ignored"),
            ))
            .await
            .expect("collection response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{uri}");
    }

    for (method, uri) in [
        (Method::DELETE, format!("/api/v1/roles/{ROLE}")),
        (
            Method::PUT,
            format!("/api/v1/roles/{ROLE}/permissions/members:read"),
        ),
    ] {
        let response = router(Arc::clone(&repository))
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .header(header::IF_MATCH, "\"17\"")
                    .extension(snapshot(SessionKind::Cli))
                    .body(Body::from("ignored"))
                    .expect("bodyless mutation request"),
            )
            .await
            .expect("bodyless mutation response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{uri}");
    }

    let response = router(repository)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(USERS_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .extension(snapshot(SessionKind::Cli))
                .body(Body::empty())
                .expect("typed empty request"),
        )
        .await
        .expect("typed empty response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn json_mutations_distinguish_media_size_and_document_errors_before_storage() {
    let repository = DetailRepository::new(
        Ok(ManagementDetailOutcome::NotFound),
        Err(ManagementRepositoryError::Unavailable),
        Ok(ManagementDetailOutcome::NotFound),
    );
    for (content_type, body, status, error) in [
        (
            None,
            Body::from("{}"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ),
        (
            Some("text/plain"),
            Body::from("{}"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ),
        (
            Some("application/json"),
            Body::from("{"),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            Some("application/json"),
            Body::from(vec![b'x'; MAX_REQUEST_BYTES + 1]),
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
        ),
    ] {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(ROLES_PATH)
            .extension(snapshot(SessionKind::Cli));
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        let response = router(Arc::clone(&repository))
            .oneshot(builder.body(body).expect("mutation request"))
            .await
            .expect("classified response");
        assert_eq!(response.status(), status);
        assert_eq!(response_json(response).await, json!({"error": error}));
    }

    let duplicate_content_type = Request::builder()
        .method(Method::POST)
        .uri(ROLES_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(snapshot(SessionKind::Cli))
        .body(Body::from("{}"))
        .expect("duplicate media-type request");
    let response = router(Arc::clone(&repository))
        .oneshot(duplicate_content_type)
        .await
        .expect("duplicate media-type response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        response_json(response).await,
        json!({"error": "unsupported_media_type"})
    );
    assert!(repository.reads().is_empty());
}
