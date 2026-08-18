use std::{fmt, time::Instant};

use async_trait::async_trait;
use automata_ci_core::GitObjectId;
use automata_ci_core::Sha256Digest;
use automata_ci_provider_github::{
    GithubHttpEndpoint, GithubPullRequestDiffAuthority, GithubPullRequestDiffOutcome,
    GithubPullRequestDiffRequest, GithubPushDiffAuthority, GithubPushDiffOutcome,
    GithubPushDiffRange, GithubPushDiffRequest, GithubRepositoryVisibility, GithubWebhookRefKind,
    VerifiedGithubPullRequest, VerifiedGithubPush,
};
use automata_ci_scm::RepositoryId;
use automata_ci_store::ProviderRepositoryVisibility;

use crate::{
    GithubChangedFileSelection, GithubChangedFilesDisposition,
    GithubPullRequestChangedFilesAuthority, GithubPullRequestChangedFilesRequest,
    GithubPushChangedFilesAuthority, GithubPushChangedFilesProvider, GithubPushChangedFilesRequest,
};

/// Product-composed delivery adapter for bounded GitHub changed-file evidence.
///
/// Pushes use Compare REST. Pull requests use the paginated pull-request-files
/// endpoint with exact pre/post pull-request snapshots.
#[derive(Clone)]
pub struct GithubRestPushChangedFilesProvider {
    endpoint: GithubHttpEndpoint,
}

impl GithubRestPushChangedFilesProvider {
    /// Creates an adapter around one fixed, hardened GitHub HTTP endpoint.
    #[must_use]
    pub const fn new(endpoint: GithubHttpEndpoint) -> Self {
        Self { endpoint }
    }

    async fn resolve(
        &self,
        request: &GithubPushChangedFilesRequest<'_>,
    ) -> GithubChangedFilesDisposition {
        if !validate_delivery_binding(request) {
            return GithubChangedFilesDisposition::Invalid;
        }
        let Ok(repository) = RepositoryId::new(request.push().repository().full_name()) else {
            return GithubChangedFilesDisposition::Invalid;
        };
        let Ok(range) = push_range(request.push()) else {
            return GithubChangedFilesDisposition::Invalid;
        };
        let authority = push_authority(request.authority());
        let Some(deadline) =
            Instant::now().checked_add(self.endpoint.trusted_origins().limits().request_timeout())
        else {
            return GithubChangedFilesDisposition::RetryableUnavailable;
        };
        let outcome = self
            .endpoint
            .push_changed_files(GithubPushDiffRequest::new(
                &repository,
                range,
                authority,
                deadline,
            ))
            .await;
        translate_outcome(outcome)
    }

    async fn resolve_pull_request(
        &self,
        request: &GithubPullRequestChangedFilesRequest<'_>,
    ) -> GithubChangedFilesDisposition {
        if !validate_pull_request_delivery_binding(request) {
            return GithubChangedFilesDisposition::Invalid;
        }
        let pull_request = request.pull_request();
        let Ok(repository) = RepositoryId::new(pull_request.repository().full_name()) else {
            return GithubChangedFilesDisposition::Invalid;
        };
        let Ok(head_repository) = RepositoryId::new(pull_request.head_repository().full_name())
        else {
            return GithubChangedFilesDisposition::Invalid;
        };
        let authority = match request.authority() {
            GithubPullRequestChangedFilesAuthority::InstallationPullRequestsRead(token) => {
                GithubPullRequestDiffAuthority::new(token)
            }
        };
        let Some(deadline) =
            Instant::now().checked_add(self.endpoint.trusted_origins().limits().request_timeout())
        else {
            return GithubChangedFilesDisposition::RetryableUnavailable;
        };
        let outcome = self
            .endpoint
            .pull_request_changed_files(GithubPullRequestDiffRequest::new(
                &repository,
                &head_repository,
                pull_request.number(),
                pull_request.base_revision(),
                pull_request.head_revision(),
                authority,
                deadline,
            ))
            .await;
        translate_pull_request_outcome(outcome)
    }
}

impl fmt::Debug for GithubRestPushChangedFilesProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRestPushChangedFilesProvider")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

#[async_trait]
impl GithubPushChangedFilesProvider for GithubRestPushChangedFilesProvider {
    async fn changed_files(
        &self,
        request: GithubPushChangedFilesRequest<'_>,
    ) -> GithubChangedFilesDisposition {
        self.resolve(&request).await
    }

    async fn pull_request_changed_files(
        &self,
        request: GithubPullRequestChangedFilesRequest<'_>,
    ) -> GithubChangedFilesDisposition {
        self.resolve_pull_request(&request).await
    }
}

fn validate_delivery_binding(request: &GithubPushChangedFilesRequest<'_>) -> bool {
    let push = request.push();
    let identity = request.identity();
    if identity.provider() != "github" || identity.delivery_id() != push.delivery_id() {
        return false;
    }
    let visibility_matches = matches!(
        (
            identity.repository_visibility(),
            push.repository().visibility(),
        ),
        (
            ProviderRepositoryVisibility::Public,
            GithubRepositoryVisibility::Public,
        ) | (
            ProviderRepositoryVisibility::Private,
            GithubRepositoryVisibility::Private,
        )
    );
    if !visibility_matches
        || identity.repository_identity() != push.repository().full_name()
        || identity.repository_id().get() != push.repository().id().get()
        || identity.installation_id().get() != push.installation_id().get()
        || request.required_through() <= request.observed_at()
    {
        return false;
    }
    true
}

fn validate_pull_request_delivery_binding(
    request: &GithubPullRequestChangedFilesRequest<'_>,
) -> bool {
    let pull_request = request.pull_request();
    validate_common_delivery_binding(
        request.identity(),
        pull_request,
        request.observed_at(),
        request.required_through(),
    )
}

fn validate_common_delivery_binding(
    identity: &automata_ci_store::ProviderDeliveryIdentity,
    pull_request: &VerifiedGithubPullRequest,
    observed_at: automata_ci_core::UnixMillis,
    required_through: automata_ci_core::UnixMillis,
) -> bool {
    if identity.provider() != "github" || identity.delivery_id() != pull_request.delivery_id() {
        return false;
    }
    let visibility_matches = matches!(
        (
            identity.repository_visibility(),
            pull_request.repository().visibility(),
        ),
        (
            ProviderRepositoryVisibility::Public,
            GithubRepositoryVisibility::Public,
        ) | (
            ProviderRepositoryVisibility::Private,
            GithubRepositoryVisibility::Private,
        )
    );
    if !visibility_matches
        || identity.repository_identity() != pull_request.repository().full_name()
        || identity.repository_id().get() != pull_request.repository().id().get()
        || identity.installation_id().get() != pull_request.installation_id().get()
        || required_through <= observed_at
    {
        return false;
    }
    true
}

fn push_range(push: &VerifiedGithubPush) -> Result<GithubPushDiffRange, ()> {
    if push.git_ref().kind() != GithubWebhookRefKind::Branch {
        return Err(());
    }
    if push.deleted() {
        return Ok(GithubPushDiffRange::Deleted);
    }
    if push.created() {
        return Ok(GithubPushDiffRange::Created);
    }
    if push.forced() {
        return Ok(GithubPushDiffRange::Forced);
    }
    let before = GitObjectId::from_provider_hex(push.before_commit_sha()).map_err(|_| ())?;
    let after = GitObjectId::from_provider_hex(push.after_commit_sha()).map_err(|_| ())?;
    let pushed_commits = push.complete_pushed_commit_revisions().ok_or(())?;
    Ok(GithubPushDiffRange::Existing {
        before,
        after,
        pushed_commits: pushed_commits.to_vec(),
    })
}

fn push_authority<'credential>(
    authority: &'credential GithubPushChangedFilesAuthority<'_>,
) -> GithubPushDiffAuthority<'credential> {
    match authority {
        GithubPushChangedFilesAuthority::InstallationContentsRead(token) => {
            GithubPushDiffAuthority::new(token)
        }
    }
}

fn translate_outcome(outcome: GithubPushDiffOutcome) -> GithubChangedFilesDisposition {
    match outcome {
        GithubPushDiffOutcome::Complete(evidence) => GithubChangedFilesDisposition::Complete {
            evidence_digest: core_digest(evidence.evidence_digest()),
            files: evidence
                .into_changed_files()
                .iter()
                .map(changed_file_selection)
                .collect(),
        },
        GithubPushDiffOutcome::RetryableUnavailable => {
            GithubChangedFilesDisposition::RetryableUnavailable
        }
        _ => GithubChangedFilesDisposition::Invalid,
    }
}

fn translate_pull_request_outcome(
    outcome: GithubPullRequestDiffOutcome,
) -> GithubChangedFilesDisposition {
    match outcome {
        GithubPullRequestDiffOutcome::Complete(evidence) => {
            let evidence = *evidence;
            GithubChangedFilesDisposition::Complete {
                evidence_digest: core_digest(evidence.evidence_digest()),
                files: evidence
                    .into_changed_files()
                    .iter()
                    .map(changed_file_selection)
                    .collect(),
            }
        }
        GithubPullRequestDiffOutcome::RetryableUnavailable => {
            GithubChangedFilesDisposition::RetryableUnavailable
        }
        _ => GithubChangedFilesDisposition::Invalid,
    }
}

fn core_digest(
    digest: automata_ci_provider_github::GithubChangedFilesEvidenceDigest,
) -> Sha256Digest {
    Sha256Digest::from_bytes(*digest.as_bytes())
}

fn changed_file_selection(
    file: &automata_ci_provider_github::GithubChangedFile,
) -> GithubChangedFileSelection {
    match file.previous_path() {
        Some(previous_path) => {
            GithubChangedFileSelection::renamed(previous_path, file.current_path())
        }
        None => GithubChangedFileSelection::changed(file.current_path()),
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::secret::SecretString;
    use automata_ci_provider_github::{
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubPushDiffIncompleteReason,
        GithubRepositoryVisibility, GithubWebhookBodyDigest, StoredAuthenticatedGithubWebhook,
        VerifiedGithubWebhook, rehydrate_stored_authenticated_github_webhook,
    };
    use bytes::Bytes;
    use sha2::{Digest as _, Sha256};

    use super::*;

    const BEFORE: &str = "1111111111111111111111111111111111111111";
    const AFTER: &str = "2222222222222222222222222222222222222222";
    const ZERO: &str = "0000000000000000000000000000000000000000";

    #[test]
    fn verified_push_shape_maps_without_inventing_a_diff_base() {
        let existing = push("refs/heads/main", BEFORE, AFTER, false, false, false);
        let GithubPushDiffRange::Existing {
            before,
            after,
            pushed_commits,
        } = push_range(&existing).unwrap()
        else {
            panic!("expected existing range");
        };
        assert_eq!(before.to_string(), BEFORE);
        assert_eq!(after.to_string(), AFTER);
        assert_eq!(
            pushed_commits,
            [GitObjectId::from_provider_hex(AFTER).unwrap()]
        );

        let created = push("refs/heads/new", ZERO, AFTER, true, false, false);
        assert!(matches!(
            push_range(&created).unwrap(),
            GithubPushDiffRange::Created
        ));
        let deleted = push("refs/heads/old", BEFORE, ZERO, false, true, false);
        assert!(matches!(
            push_range(&deleted).unwrap(),
            GithubPushDiffRange::Deleted
        ));
        let forced = push("refs/heads/main", BEFORE, AFTER, false, false, true);
        assert!(matches!(
            push_range(&forced).unwrap(),
            GithubPushDiffRange::Forced
        ));
        let tag = push("refs/tags/v1", BEFORE, AFTER, false, false, false);
        assert!(push_range(&tag).is_err());
    }

    #[test]
    fn authority_mapping_is_disjoint_and_debug_redacted() {
        let token = SecretString::new("adapter-token").unwrap();
        let authority = GithubPushChangedFilesAuthority::InstallationContentsRead(&token);
        let mapped = push_authority(&authority);
        assert_eq!(format!("{mapped:?}"), "GithubPushDiffAuthority([redacted])");
        assert!(!format!("{authority:?}").contains("adapter-token"));
    }

    #[test]
    fn every_incomplete_http_disposition_fails_closed() {
        for reason in [
            GithubPushDiffIncompleteReason::CreatedPush,
            GithubPushDiffIncompleteReason::DeletedPush,
            GithubPushDiffIncompleteReason::DivergedPush,
            GithubPushDiffIncompleteReason::FileListCapped,
            GithubPushDiffIncompleteReason::InvalidEvidence,
            GithubPushDiffIncompleteReason::ProviderRejected,
        ] {
            assert_eq!(
                translate_outcome(GithubPushDiffOutcome::Invalid(reason)),
                GithubChangedFilesDisposition::Invalid
            );
        }
        assert_eq!(
            translate_outcome(GithubPushDiffOutcome::RetryableUnavailable),
            GithubChangedFilesDisposition::RetryableUnavailable
        );
    }

    fn push(
        git_ref: &str,
        before: &str,
        after: &str,
        created: bool,
        deleted: bool,
        forced: bool,
    ) -> VerifiedGithubPush {
        let commits = if deleted {
            "[]".to_owned()
        } else {
            format!(r#"[{{"id":"{after}"}}]"#)
        };
        let body = Bytes::from(format!(
            r#"{{"ref":"{git_ref}","before":"{before}","after":"{after}","created":{created},"deleted":{deleted},"forced":{forced},"repository":{{"id":42,"private":false,"visibility":"public","name":"repo","full_name":"owner/repo","owner":{{"id":7,"login":"owner"}}}},"installation":{{"id":9}},"commits":{commits}}}"#
        ));
        let digest = Sha256::digest(&body);
        let mut digest_bytes = [0_u8; 32];
        digest_bytes.copy_from_slice(&digest);
        let encoded_size = u64::try_from(body.len()).unwrap();
        let event = rehydrate_stored_authenticated_github_webhook(
            StoredAuthenticatedGithubWebhook::from_durable_coordinates(
                body,
                GithubWebhookBodyDigest::from_bytes(digest_bytes),
                encoded_size,
                GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
                "push",
                "delivery-test",
                9,
                42,
                7,
                GithubRepositoryVisibility::Public,
                "owner",
                "repo",
            ),
        )
        .unwrap();
        let VerifiedGithubWebhook::Push(push) = event else {
            panic!("expected push fixture");
        };
        push
    }
}
