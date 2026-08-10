//! Browser mutation boundary for repository publication preferences.

use std::{fmt, sync::Arc};

use automata_ci_auth::{
    authorization::{OutputVisibility, RepositoryPublicationPolicy},
    management::{ManagementActor, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    secret::SecretString,
    session::SessionKind,
    time::{Clock, UnixTimestamp},
};
use automata_ci_store::{
    HumanWorkflowReadRepository, PublicationRepositoryError, RepositoryCoordinate, RepositoryId,
    RepositoryPublicationRepository, RepositoryPublicationSettings, StoreError, TenantScope,
    UpdateRepositoryPublication, UpdateRepositoryPublicationOutcome,
};
use axum::{
    Router,
    body::Body,
    extract::{Extension, OriginalUri, Path, State, rejection::PathRejection},
    http::{Response, StatusCode, header},
    response::{IntoResponse, Redirect},
    routing::post,
};

use crate::app::web::{
    apply_static_page_headers, error_page_response, error_page_response_with_action,
};

pub(crate) const MAX_PUBLICATION_SETTINGS_FORM_BYTES: usize = 4 * 1_024;
const SCM_PROVIDER: &str = "github";

#[derive(Clone)]
struct PublicationSettingsState {
    reads: Arc<dyn HumanWorkflowReadRepository>,
    publications: Arc<dyn RepositoryPublicationRepository>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for PublicationSettingsState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationSettingsState")
            .finish_non_exhaustive()
    }
}

/// Exact nonsecret fields admitted by the browser form after CSRF verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPublicationSettingsForm {
    expected_revision: ManagementRevision,
    policy: RepositoryPublicationPolicy,
}

/// Business-field result retained only after the browser CSRF envelope passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationSettingsFormSubmission {
    Valid(VerifiedPublicationSettingsForm),
    Invalid,
}

impl VerifiedPublicationSettingsForm {
    const fn new(
        expected_revision: ManagementRevision,
        policy: RepositoryPublicationPolicy,
    ) -> Self {
        Self {
            expected_revision,
            policy,
        }
    }

    pub(crate) const fn expected_revision(self) -> ManagementRevision {
        self.expected_revision
    }

    pub(crate) const fn policy(self) -> RepositoryPublicationPolicy {
        self.policy
    }
}

/// Parsed form evidence whose CSRF value remains redacted and zeroized.
pub(crate) struct ParsedPublicationSettingsForm {
    verified: VerifiedPublicationSettingsForm,
}

impl ParsedPublicationSettingsForm {
    pub(crate) fn into_verified(self) -> VerifiedPublicationSettingsForm {
        self.verified
    }
}

impl fmt::Debug for ParsedPublicationSettingsForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedPublicationSettingsForm")
            .field("verified", &self.verified)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationSettingsFormError;

pub(crate) fn is_publication_settings_form(method: &axum::http::Method, path: &str) -> bool {
    if method != axum::http::Method::POST {
        return false;
    }
    let Some(path) = path.strip_prefix('/') else {
        return false;
    };
    let mut segments = path.split('/');
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ),
        (Some(owner), Some(repository), Some("settings"), Some("access"), None)
            if !owner.is_empty() && !repository.is_empty()
    )
}

pub(crate) fn parse_publication_settings_form(
    body: &[u8],
) -> Result<ParsedPublicationSettingsForm, PublicationSettingsFormError> {
    if body.is_empty() || body.len() > MAX_PUBLICATION_SETTINGS_FORM_BYTES {
        return Err(PublicationSettingsFormError);
    }
    let mut csrf_token = None;
    let mut expected_revision = None;
    let mut dashboard = None;
    let mut logs = None;
    let mut artifacts = None;
    let mut field_count = 0_usize;
    for pair in body.split(|byte| *byte == b'&') {
        if pair.is_empty() {
            return Err(PublicationSettingsFormError);
        }
        field_count = field_count
            .checked_add(1)
            .ok_or(PublicationSettingsFormError)?;
        if field_count > 5 {
            return Err(PublicationSettingsFormError);
        }
        let Some(separator) = pair.iter().position(|byte| *byte == b'=') else {
            return Err(PublicationSettingsFormError);
        };
        let name = decode_form_component(&pair[..separator])?;
        let value = decode_form_component(&pair[separator + 1..])?;
        match name.as_str() {
            "csrf_token" => {
                let token = SecretString::new(value).map_err(|_| PublicationSettingsFormError)?;
                set_once(&mut csrf_token, token)?;
            }
            "expected_revision" => set_once(&mut expected_revision, parse_revision(&value)?)?,
            "dashboard_audience" => set_once(&mut dashboard, parse_audience(&value)?)?,
            "log_audience" => set_once(&mut logs, parse_audience(&value)?)?,
            "artifact_audience" => set_once(&mut artifacts, parse_audience(&value)?)?,
            _ => return Err(PublicationSettingsFormError),
        }
    }
    let (Some(_csrf_token), Some(expected_revision), Some(dashboard), Some(logs), Some(artifacts)) =
        (csrf_token, expected_revision, dashboard, logs, artifacts)
    else {
        return Err(PublicationSettingsFormError);
    };
    Ok(ParsedPublicationSettingsForm {
        verified: VerifiedPublicationSettingsForm::new(
            expected_revision,
            RepositoryPublicationPolicy::new(dashboard, logs, artifacts),
        ),
    })
}

pub(crate) fn publication_settings_csrf_token(
    body: &[u8],
) -> Result<SecretString, PublicationSettingsFormError> {
    if body.is_empty() || body.len() > MAX_PUBLICATION_SETTINGS_FORM_BYTES {
        return Err(PublicationSettingsFormError);
    }
    let mut csrf_token = None;
    for pair in body.split(|byte| *byte == b'&') {
        let Some(separator) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if &pair[..separator] != b"csrf_token" {
            continue;
        }
        let value = decode_form_component(&pair[separator + 1..])?;
        set_once(
            &mut csrf_token,
            SecretString::new(value).map_err(|_| PublicationSettingsFormError)?,
        )?;
    }
    csrf_token.ok_or(PublicationSettingsFormError)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), PublicationSettingsFormError> {
    if slot.replace(value).is_some() {
        return Err(PublicationSettingsFormError);
    }
    Ok(())
}

fn parse_revision(value: &str) -> Result<ManagementRevision, PublicationSettingsFormError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PublicationSettingsFormError);
    }
    let revision = value
        .parse::<u64>()
        .ok()
        .and_then(|revision| ManagementRevision::new(revision).ok())
        .ok_or(PublicationSettingsFormError)?;
    if revision.value() >= i64::MAX.unsigned_abs() {
        return Err(PublicationSettingsFormError);
    }
    Ok(revision)
}

fn parse_audience(value: &str) -> Result<OutputVisibility, PublicationSettingsFormError> {
    match value {
        "private" => Ok(OutputVisibility::Private),
        "authenticated" => Ok(OutputVisibility::Authenticated),
        "public" => Ok(OutputVisibility::Public),
        _ => Err(PublicationSettingsFormError),
    }
}

fn decode_form_component(value: &[u8]) -> Result<String, PublicationSettingsFormError> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0_usize;
    while index < value.len() {
        match value[index] {
            b'%' if index + 2 < value.len() => {
                let Some(high) = hex(value[index + 1]) else {
                    return Err(PublicationSettingsFormError);
                };
                let Some(low) = hex(value[index + 2]) else {
                    return Err(PublicationSettingsFormError);
                };
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return Err(PublicationSettingsFormError),
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| PublicationSettingsFormError)
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn publication_settings_router(
    reads: Arc<dyn HumanWorkflowReadRepository>,
    publications: Arc<dyn RepositoryPublicationRepository>,
    clock: Arc<dyn Clock>,
) -> Router {
    Router::new()
        .route(
            "/{owner}/{repository}/settings/access",
            post(update_publication_settings),
        )
        .with_state(PublicationSettingsState {
            reads,
            publications,
            clock,
        })
}

async fn update_publication_settings(
    State(state): State<PublicationSettingsState>,
    path: Result<Path<(String, String)>, PathRejection>,
    OriginalUri(original_uri): OriginalUri,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    form: Option<Extension<PublicationSettingsFormSubmission>>,
) -> Response<Body> {
    if original_uri.query().is_some() {
        return bad_request();
    }
    let Some(Extension(snapshot)) = snapshot else {
        return unauthorized();
    };
    let Some(Extension(form)) = form else {
        return forbidden();
    };
    let PublicationSettingsFormSubmission::Valid(form) = form else {
        return bad_request();
    };
    let Ok(Path((owner, repository))) = path else {
        return bad_request();
    };
    let Ok(coordinate) = RepositoryCoordinate::new(SCM_PROVIDER, owner, repository) else {
        return not_found();
    };
    let settings_href = repository_settings_href(&coordinate);
    let identity = snapshot.session().identity();
    if identity.kind() != SessionKind::Browser {
        return settings_unauthorized(&settings_href);
    }
    let Ok(tenant) = TenantScope::from_authenticated_tenant_id(identity.tenant_id().as_str())
    else {
        return settings_internal_server_error(&settings_href);
    };
    let repository = match state.reads.resolve_repository(&tenant, &coordinate).await {
        Ok(Some(repository)) => repository,
        Ok(None) => return not_found(),
        Err(error) => return read_error(&error, &settings_href),
    };
    if repository.scm_provider != SCM_PROVIDER
        || repository.owner != coordinate.owner()
        || repository.name != coordinate.name()
        || repository.resource.tenant_id() != identity.tenant_id()
        || repository.resource.repository_id().as_uuid() != repository.id.as_uuid()
    {
        return settings_internal_server_error(&settings_href);
    }
    let Ok(authorization_revision) =
        ManagementRevision::new(snapshot.session().authorization_revision())
    else {
        return settings_unauthorized(&settings_href);
    };
    let observed_at = state.clock.now();
    let actor = ManagementActor::new(
        identity.tenant_id().clone(),
        identity.principal_id().clone(),
        identity.session_id().clone(),
        authorization_revision,
        None,
        observed_at,
    );
    let request = UpdateRepositoryPublication::new(
        actor,
        repository.id,
        form.expected_revision(),
        form.policy(),
    );
    match state
        .publications
        .update_repository_publication(request)
        .await
    {
        Ok(UpdateRepositoryPublicationOutcome::Applied(applied)) => {
            if !applied_matches(&applied, repository.id, form, observed_at) {
                return settings_internal_server_error(&settings_href);
            }
            redirect(&settings_href)
        }
        Ok(UpdateRepositoryPublicationOutcome::RevisionConflict { .. }) => {
            error_page_response_with_action(
                StatusCode::CONFLICT,
                "Settings changed",
                "Reload the repository settings and review the current access policy before saving again.",
                &settings_href,
                "Review repository settings",
            )
        }
        Ok(
            UpdateRepositoryPublicationOutcome::Forbidden
            | UpdateRepositoryPublicationOutcome::NotFound,
        ) => not_found(),
        Ok(UpdateRepositoryPublicationOutcome::SessionStale) => {
            settings_unauthorized(&settings_href)
        }
        Err(PublicationRepositoryError::Unavailable) => {
            settings_service_unavailable(&settings_href)
        }
        Err(PublicationRepositoryError::InvalidRequest) => settings_bad_request(&settings_href),
        Err(PublicationRepositoryError::CorruptData) => {
            settings_internal_server_error(&settings_href)
        }
    }
}

fn redirect(path: &str) -> Response<Body> {
    let mut response = Redirect::to(path).into_response();
    apply_static_page_headers(response.headers_mut());
    response
}

fn not_found() -> Response<Body> {
    error_page_response(
        StatusCode::NOT_FOUND,
        "Page not found",
        "The requested repository settings are not available.",
    )
}

fn applied_matches(
    applied: &RepositoryPublicationSettings,
    repository_id: RepositoryId,
    form: VerifiedPublicationSettingsForm,
    observed_at: UnixTimestamp,
) -> bool {
    form.expected_revision()
        .value()
        .checked_add(1)
        .is_some_and(|next_revision| {
            applied.repository_id() == repository_id
                && applied.policy() == form.policy()
                && applied.revision().value() == next_revision
                && applied.updated_at() == observed_at
        })
}

fn read_error(error: &StoreError, settings_href: &str) -> Response<Body> {
    if matches!(error, StoreError::CorruptData(_)) {
        settings_internal_server_error(settings_href)
    } else {
        settings_service_unavailable(settings_href)
    }
}

fn bad_request() -> Response<Body> {
    error_page_response(
        StatusCode::BAD_REQUEST,
        "Invalid settings request",
        "Reload the repository settings and try again.",
    )
}

fn forbidden() -> Response<Body> {
    error_page_response(
        StatusCode::FORBIDDEN,
        "Request not accepted",
        "Reload the repository settings before trying again.",
    )
}

fn unauthorized() -> Response<Body> {
    error_page_response(
        StatusCode::UNAUTHORIZED,
        "Sign in again",
        "Your session is no longer current. Sign in again before changing repository settings.",
    )
}

fn settings_unauthorized(settings_href: &str) -> Response<Body> {
    error_page_response_with_action(
        StatusCode::UNAUTHORIZED,
        "Sign in again",
        "Your session is no longer current. Sign in again before changing repository settings.",
        settings_href,
        "Return to repository settings",
    )
}

fn settings_bad_request(settings_href: &str) -> Response<Body> {
    error_page_response_with_action(
        StatusCode::BAD_REQUEST,
        "Invalid settings request",
        "Reload the repository settings and try again.",
        settings_href,
        "Review repository settings",
    )
}

fn settings_service_unavailable(settings_href: &str) -> Response<Body> {
    let mut response = error_page_response_with_action(
        StatusCode::SERVICE_UNAVAILABLE,
        "Settings temporarily unavailable",
        "Repository settings are temporarily unavailable. Try again in a moment.",
        settings_href,
        "Try repository settings again",
    );
    response.headers_mut().insert(
        header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("1"),
    );
    response
}

fn settings_internal_server_error(settings_href: &str) -> Response<Body> {
    error_page_response_with_action(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to update settings",
        "An unexpected error prevented this update.",
        settings_href,
        "Return to repository settings",
    )
}

fn repository_settings_href(coordinate: &RepositoryCoordinate) -> String {
    format!(
        "/{}/{}/settings/access",
        percent_encode_path_segment(coordinate.owner()),
        percent_encode_path_segment(coordinate.name()),
    )
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Mutex};

    use async_trait::async_trait;
    use automata_ci_auth::{
        authorization::{
            AuthorizationContext, Permission, RepositoryResource, RepositoryResourceId,
        },
        human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
        request_auth::ViewerDisplayMetadata,
        session::{DurableSession, DurableSessionIdentity, SessionId, SessionKind},
        time::UnixTimestamp,
    };
    use automata_ci_core::RunId;
    use automata_ci_store::{HumanRepository, RepositoryId, RepositoryPublicationSettings};
    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;

    const CSRF: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    fn valid_form() -> Vec<u8> {
        format!(
            "csrf_token={CSRF}&expected_revision=7&dashboard_audience=public&\
             log_audience=authenticated&artifact_audience=private"
        )
        .into_bytes()
    }

    #[test]
    fn form_parser_keeps_three_audiences_independent_and_redacts_csrf() {
        let parsed = parse_publication_settings_form(&valid_form()).expect("valid form");
        assert!(!format!("{parsed:?}").contains(CSRF));
        let verified = parsed.into_verified();
        assert_eq!(verified.expected_revision().value(), 7);
        assert_eq!(verified.policy().dashboard(), OutputVisibility::Public);
        assert_eq!(verified.policy().logs(), OutputVisibility::Authenticated);
        assert_eq!(verified.policy().artifacts(), OutputVisibility::Private);
    }

    #[test]
    fn form_parser_rejects_duplicates_unknowns_aliases_and_malformed_encoding() {
        for body in [
            b"".as_slice(),
            b"csrf_token=x".as_slice(),
            b"csrf_token=x&csrf_token=y&expected_revision=1&dashboard_audience=private&log_audience=private&artifact_audience=private".as_slice(),
            b"csrf_token=x&expected_revision=01&dashboard_audience=private&log_audience=private&artifact_audience=private".as_slice(),
            b"csrf_token=x&expected_revision=1&dashboard_audience=world&log_audience=private&artifact_audience=private".as_slice(),
            b"csrf_token=x&expected_revision=1&dashboard_audience=private&log_audience=private&artifact_audience=private&extra=x".as_slice(),
            b"csrf_token=%GG&expected_revision=1&dashboard_audience=private&log_audience=private&artifact_audience=private".as_slice(),
            b"csrf_token=%FF&expected_revision=1&dashboard_audience=private&log_audience=private&artifact_audience=private".as_slice(),
        ] {
            assert!(parse_publication_settings_form(body).is_err());
        }
        assert!(
            parse_publication_settings_form(&vec![b'a'; MAX_PUBLICATION_SETTINGS_FORM_BYTES + 1])
                .is_err()
        );

        let maximum = format!(
            "csrf_token={CSRF}&expected_revision={}&dashboard_audience=private&\
             log_audience=private&artifact_audience=private",
            i64::MAX
        );
        assert!(parse_publication_settings_form(maximum.as_bytes()).is_err());
        let above_maximum = format!(
            "csrf_token={CSRF}&expected_revision={}&dashboard_audience=private&\
             log_audience=private&artifact_audience=private",
            i64::MAX.unsigned_abs() + 1
        );
        assert!(parse_publication_settings_form(above_maximum.as_bytes()).is_err());
    }

    #[test]
    fn csrf_envelope_is_independent_from_business_field_validation() {
        let invalid_business =
            format!("csrf_token={CSRF}&expected_revision=07&dashboard_audience=world&broken=%GG");
        let token = publication_settings_csrf_token(invalid_business.as_bytes())
            .expect("the exact CSRF field remains independently verifiable");
        assert_eq!(token.expose_secret(), CSRF);
        assert!(parse_publication_settings_form(invalid_business.as_bytes()).is_err());
        assert!(
            publication_settings_csrf_token(
                format!("csrf_token={CSRF}&csrf_token={CSRF}").as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn only_the_exact_repository_settings_post_is_a_form_csrf_surface() {
        assert!(is_publication_settings_form(
            &axum::http::Method::POST,
            "/acme/repository/settings/access"
        ));
        for (method, path) in [
            (axum::http::Method::GET, "/acme/repository/settings/access"),
            (axum::http::Method::POST, "/settings/access"),
            (axum::http::Method::POST, "/acme/repository/settings"),
            (
                axum::http::Method::POST,
                "/acme/repository/settings/access/more",
            ),
        ] {
            assert!(!is_publication_settings_form(&method, path));
        }
    }

    #[derive(Debug)]
    struct FakeReads {
        repository: HumanRepository,
    }

    #[async_trait]
    impl HumanWorkflowReadRepository for FakeReads {
        async fn resolve_repository(
            &self,
            _tenant: &TenantScope,
            _coordinate: &RepositoryCoordinate,
        ) -> Result<Option<HumanRepository>, StoreError> {
            Ok(Some(self.repository.clone()))
        }

        async fn list_repositories(
            &self,
            _query: &automata_ci_store::HumanRepositoryListQuery,
            _context: &AuthorizationContext,
            _permissions: &[Permission],
        ) -> Result<automata_ci_store::HumanRepositoryPage, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }

        async fn list_workflows(
            &self,
            _query: &automata_ci_store::HumanWorkflowListQuery,
            _context: &AuthorizationContext,
            _permission: &Permission,
        ) -> Result<Option<automata_ci_store::HumanWorkflowPage>, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }

        async fn list_runs(
            &self,
            _query: &automata_ci_store::HumanRunListQuery,
            _context: &AuthorizationContext,
            _permission: &Permission,
        ) -> Result<Option<automata_ci_store::HumanRunPage>, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }

        async fn get_run(
            &self,
            _scope: &automata_ci_store::HumanRunScope,
        ) -> Result<Option<automata_ci_store::HumanRunDetail>, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }

        async fn get_job(
            &self,
            _scope: &automata_ci_store::HumanJobScope,
        ) -> Result<Option<automata_ci_store::HumanJobDetail>, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }

        async fn list_log_segments(
            &self,
            _query: &automata_ci_store::HumanLogSegmentQuery,
        ) -> Result<Option<automata_ci_store::HumanLogSegmentPage>, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }

        async fn get_artifact(
            &self,
            _scope: &automata_ci_store::HumanArtifactScope,
        ) -> Result<Option<automata_ci_store::HumanArtifactDownload>, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }

        async fn is_repository_request_allowed(
            &self,
            _tenant: &TenantScope,
            _repository_id: RepositoryId,
            _context: &AuthorizationContext,
            _target: &automata_ci_store::HumanAuthorizationTarget,
        ) -> Result<bool, StoreError> {
            unimplemented!("not used by publication settings mutation tests")
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum FakeMutationOutcome {
        Applied,
        MismatchedApplied,
        Conflict,
        Forbidden,
        NotFound,
        SessionStale,
        InvalidRequest,
        Unavailable,
        Corrupt,
    }

    #[derive(Debug)]
    struct FakePublications {
        outcome: FakeMutationOutcome,
        requests: Mutex<Vec<UpdateRepositoryPublication>>,
    }

    #[async_trait]
    impl RepositoryPublicationRepository for FakePublications {
        async fn update_repository_publication(
            &self,
            request: UpdateRepositoryPublication,
        ) -> Result<UpdateRepositoryPublicationOutcome, PublicationRepositoryError> {
            let applied = RepositoryPublicationSettings::new(
                request.repository_id(),
                request.policy(),
                ManagementRevision::new(request.expected_revision().value() + 1)
                    .expect("next revision"),
                request.actor().now(),
            );
            self.requests
                .lock()
                .expect("publication requests")
                .push(request);
            match self.outcome {
                FakeMutationOutcome::Applied => {
                    Ok(UpdateRepositoryPublicationOutcome::Applied(applied))
                }
                FakeMutationOutcome::MismatchedApplied => {
                    Ok(UpdateRepositoryPublicationOutcome::Applied(
                        RepositoryPublicationSettings::new(
                            RepositoryId::from_uuid(RunId::new().as_uuid()),
                            applied.policy(),
                            applied.revision(),
                            applied.updated_at(),
                        ),
                    ))
                }
                FakeMutationOutcome::Conflict => {
                    Ok(UpdateRepositoryPublicationOutcome::RevisionConflict {
                        current: applied.revision(),
                    })
                }
                FakeMutationOutcome::Forbidden => Ok(UpdateRepositoryPublicationOutcome::Forbidden),
                FakeMutationOutcome::NotFound => Ok(UpdateRepositoryPublicationOutcome::NotFound),
                FakeMutationOutcome::SessionStale => {
                    Ok(UpdateRepositoryPublicationOutcome::SessionStale)
                }
                FakeMutationOutcome::InvalidRequest => {
                    Err(PublicationRepositoryError::InvalidRequest)
                }
                FakeMutationOutcome::Unavailable => Err(PublicationRepositoryError::Unavailable),
                FakeMutationOutcome::Corrupt => Err(PublicationRepositoryError::CorruptData),
            }
        }
    }

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(500)
        }
    }

    fn repository_fixture() -> HumanRepository {
        let tenant_id = TenantId::new("tenant-a").expect("tenant");
        let repository_id = RepositoryId::from_uuid(RunId::new().as_uuid());
        let resource_id = RepositoryResourceId::from_uuid(repository_id.as_uuid())
            .expect("repository resource ID");
        HumanRepository {
            id: repository_id,
            resource: RepositoryResource::new(tenant_id, resource_id),
            scm_provider: SCM_PROVIDER.to_owned(),
            provider_repository_id: "123".to_owned(),
            owner: "acme".to_owned(),
            name: "payments".to_owned(),
            publication: RepositoryPublicationPolicy::default(),
            publication_revision: 7,
        }
    }

    fn snapshot() -> AuthenticatedRequestSnapshot {
        let tenant_id = TenantId::new("tenant-a").expect("tenant");
        let principal_id =
            PrincipalId::new("11111111-1111-4111-8111-111111111111").expect("principal");
        let provider_id = ProviderId::new("github").expect("provider");
        let provider_subject = ProviderSubject::new("123").expect("subject");
        let identity = DurableSessionIdentity::new(
            SessionId::new("22222222-2222-4222-8222-222222222222").expect("session"),
            tenant_id.clone(),
            principal_id.clone(),
            provider_id.clone(),
            provider_subject.clone(),
            SessionKind::Browser,
        )
        .expect("session identity");
        let session = DurableSession::new(
            identity,
            4,
            UnixTimestamp::from_seconds(1),
            UnixTimestamp::from_seconds(2),
            UnixTimestamp::from_seconds(900),
            UnixTimestamp::from_seconds(1_000),
            None,
        )
        .expect("session");
        let human = AuthenticatedHuman::new(
            principal_id.clone(),
            provider_id,
            provider_subject,
            "octocat",
            Some("Octocat".to_owned()),
            UnixTimestamp::from_seconds(1),
        )
        .expect("human");
        let authorization = AuthorizationContext::authenticated_at_revision(
            tenant_id,
            principal_id,
            BTreeSet::new(),
            4,
        )
        .expect("authorization");
        AuthenticatedRequestSnapshot::new(
            session,
            human,
            ViewerDisplayMetadata::new("Octocat").expect("viewer"),
            authorization,
        )
        .expect("snapshot")
    }

    async fn mutation_response(
        outcome: FakeMutationOutcome,
    ) -> (Response<Body>, Arc<FakePublications>) {
        let publications = Arc::new(FakePublications {
            outcome,
            requests: Mutex::new(Vec::new()),
        });
        let reads: Arc<dyn HumanWorkflowReadRepository> = Arc::new(FakeReads {
            repository: repository_fixture(),
        });
        let publications_port: Arc<dyn RepositoryPublicationRepository> = publications.clone();
        let app = publication_settings_router(reads, publications_port, Arc::new(FixedClock))
            .layer(Extension(snapshot()))
            .layer(Extension(PublicationSettingsFormSubmission::Valid(
                VerifiedPublicationSettingsForm::new(
                    ManagementRevision::new(7).expect("revision"),
                    RepositoryPublicationPolicy::new(
                        OutputVisibility::Public,
                        OutputVisibility::Authenticated,
                        OutputVisibility::Private,
                    ),
                ),
            )));
        let response = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/acme/payments/settings/access")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        (response, publications)
    }

    #[tokio::test]
    async fn mutation_binds_actor_repository_policy_revision_and_closed_redirect() {
        let (response, publications) = mutation_response(FakeMutationOutcome::Applied).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[header::LOCATION],
            "/acme/payments/settings/access"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        {
            let requests = publications.requests.lock().expect("requests");
            assert_eq!(requests.len(), 1);
            let request = &requests[0];
            assert_eq!(request.actor().tenant_id().as_str(), "tenant-a");
            assert_eq!(request.actor().authorization_revision().value(), 4);
            assert_eq!(request.expected_revision().value(), 7);
            assert_eq!(request.policy().dashboard(), OutputVisibility::Public);
            assert_eq!(request.policy().logs(), OutputVisibility::Authenticated);
            assert_eq!(request.policy().artifacts(), OutputVisibility::Private);
        }

        let (conflict, _) = mutation_response(FakeMutationOutcome::Conflict).await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(conflict.headers().get(header::LOCATION).is_none());
        assert_eq!(conflict.headers()[header::CACHE_CONTROL], "no-store");
        assert!(conflict.headers().contains_key("content-security-policy"));
        let conflict = axum::body::to_bytes(conflict.into_body(), 64 * 1_024)
            .await
            .expect("conflict body");
        assert!(
            String::from_utf8_lossy(&conflict).contains("href=\"/acme/payments/settings/access\"")
        );
    }

    #[tokio::test]
    async fn forbidden_and_missing_mutations_are_indistinguishable() {
        let (forbidden, _) = mutation_response(FakeMutationOutcome::Forbidden).await;
        let (missing, _) = mutation_response(FakeMutationOutcome::NotFound).await;
        assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);
        assert_eq!(forbidden.status(), missing.status());
        assert_eq!(forbidden.headers(), missing.headers());
        let forbidden = axum::body::to_bytes(forbidden.into_body(), 64 * 1_024)
            .await
            .expect("body");
        let missing = axum::body::to_bytes(missing.into_body(), 64 * 1_024)
            .await
            .expect("body");
        assert_eq!(forbidden, missing);
    }

    #[tokio::test]
    async fn mutation_outcomes_map_without_trusting_inconsistent_applied_data() {
        for (outcome, expected) in [
            (
                FakeMutationOutcome::MismatchedApplied,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (FakeMutationOutcome::SessionStale, StatusCode::UNAUTHORIZED),
            (FakeMutationOutcome::InvalidRequest, StatusCode::BAD_REQUEST),
            (
                FakeMutationOutcome::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                FakeMutationOutcome::Corrupt,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let (response, _) = mutation_response(outcome).await;
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(response.headers().contains_key("content-security-policy"));
            if expected == StatusCode::SERVICE_UNAVAILABLE {
                assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            }
        }
    }
}
