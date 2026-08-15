use std::{fmt, time::Instant};

use async_trait::async_trait;
use automata_ci_core::Sha256Digest;
use automata_ci_github::{
    GithubHttpEndpoint, GithubPullRequestDiffAuthority, GithubPullRequestDiffOutcome,
    GithubPullRequestDiffRequest, GithubPushDiffAuthority, GithubPushDiffOutcome,
    GithubPushDiffRange, GithubPushDiffRequest, GithubPushRefKind, GithubRepositoryVisibility,
    VerifiedGithubPullRequest, VerifiedGithubPush,
};
use automata_ci_scm::{ExactRevision, RepositoryId};
use automata_ci_store::ProviderRepositoryVisibility;

use crate::{
    GithubChangedFilesDisposition, GithubPullRequestChangedFilesAuthority,
    GithubPullRequestChangedFilesRequest, GithubPushChangedFilesAuthority,
    GithubPushChangedFilesProvider, GithubPushChangedFilesRequest,
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
            GithubPullRequestChangedFilesAuthority::PublicAnonymous => {
                GithubPullRequestDiffAuthority::PublicAnonymous
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
            request.authority(),
        ),
        (
            ProviderRepositoryVisibility::Public,
            GithubRepositoryVisibility::Public,
            GithubPushChangedFilesAuthority::PublicAnonymous,
        ) | (
            ProviderRepositoryVisibility::Private,
            GithubRepositoryVisibility::Private,
            GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(_),
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
        request.authority(),
        request.observed_at(),
        request.required_through(),
    )
}

fn validate_common_delivery_binding(
    identity: &automata_ci_store::ProviderDeliveryIdentity,
    pull_request: &VerifiedGithubPullRequest,
    authority: &GithubPullRequestChangedFilesAuthority,
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
            authority,
        ),
        (
            ProviderRepositoryVisibility::Public,
            GithubRepositoryVisibility::Public,
            GithubPullRequestChangedFilesAuthority::PublicAnonymous,
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
    if push.git_ref().kind() != GithubPushRefKind::Branch {
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
    let before = ExactRevision::new(push.before_commit_sha()).map_err(|_| ())?;
    let after = ExactRevision::new(push.after_commit_sha()).map_err(|_| ())?;
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
        GithubPushChangedFilesAuthority::PublicAnonymous => {
            GithubPushDiffAuthority::PublicAnonymous
        }
        GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(token) => {
            GithubPushDiffAuthority::PrivateInstallationContentsRead(token)
        }
    }
}

fn translate_outcome(outcome: GithubPushDiffOutcome) -> GithubChangedFilesDisposition {
    match outcome {
        GithubPushDiffOutcome::Complete(evidence) => GithubChangedFilesDisposition::Complete {
            evidence_digest: core_digest(evidence.evidence_digest()),
            files: evidence.into_changed_paths(),
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
            GithubChangedFilesDisposition::Complete {
                evidence_digest: core_digest(evidence.evidence_digest()),
                files: evidence.into_changed_paths(),
            }
        }
        GithubPullRequestDiffOutcome::RetryableUnavailable => {
            GithubChangedFilesDisposition::RetryableUnavailable
        }
        _ => GithubChangedFilesDisposition::Invalid,
    }
}

fn core_digest(digest: automata_ci_github::GithubChangedFilesEvidenceDigest) -> Sha256Digest {
    Sha256Digest::from_bytes(*digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::secret::SecretString;
    use automata_ci_github::{
        GITHUB_PUSH_EVENT_MEDIA_TYPE, GithubPushDiffIncompleteReason, GithubRepositoryVisibility,
        GithubWebhookBodyDigest, StoredAuthenticatedGithubPush,
        rehydrate_stored_authenticated_github_push,
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
        assert_eq!(before.as_str(), BEFORE);
        assert_eq!(after.as_str(), AFTER);
        assert_eq!(pushed_commits, [ExactRevision::new(AFTER).unwrap()]);

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
        let public = GithubPushChangedFilesAuthority::PublicAnonymous;
        assert!(matches!(
            push_authority(&public),
            GithubPushDiffAuthority::PublicAnonymous
        ));

        let token = SecretString::new("private-adapter-token").unwrap();
        let private = GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(&token);
        let mapped = push_authority(&private);
        assert!(matches!(
            mapped,
            GithubPushDiffAuthority::PrivateInstallationContentsRead(_)
        ));
        assert!(!format!("{private:?}").contains("private-adapter-token"));
    }

    #[test]
    fn every_incomplete_http_disposition_fails_closed() {
        for reason in [
            GithubPushDiffIncompleteReason::CreatedPush,
            GithubPushDiffIncompleteReason::DeletedPush,
            GithubPushDiffIncompleteReason::DivergedPush,
            GithubPushDiffIncompleteReason::FileListCapped,
            GithubPushDiffIncompleteReason::RenamedPath,
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
        rehydrate_stored_authenticated_github_push(
            StoredAuthenticatedGithubPush::from_durable_coordinates(
                body,
                GithubWebhookBodyDigest::from_bytes(digest_bytes),
                encoded_size,
                GITHUB_PUSH_EVENT_MEDIA_TYPE,
                "delivery-test",
                9,
                42,
                7,
                GithubRepositoryVisibility::Public,
                "owner",
                "repo",
            ),
        )
        .unwrap()
    }
}
