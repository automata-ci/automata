use std::{fmt, time::Instant};

use async_trait::async_trait;
use automata_ci_github::{
    GithubHttpEndpoint, GithubPushDiffAuthority, GithubPushDiffError, GithubPushDiffOutcome,
    GithubPushDiffRange, GithubPushDiffRequest, GithubPushRefKind, GithubRepositoryVisibility,
    VerifiedGithubPush,
};
use automata_ci_scm::{ExactRevision, RepositoryId};
use automata_ci_store::ProviderRepositoryVisibility;
use automata_ci_workflow_github::GithubChangedFilesV1;

use crate::{
    GithubPushChangedFilesAuthority, GithubPushChangedFilesError, GithubPushChangedFilesProvider,
    GithubPushChangedFilesRequest,
};

/// Product-composed delivery adapter for GitHub's bounded Compare REST evidence.
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
    ) -> Result<GithubChangedFilesV1, GithubPushChangedFilesError> {
        validate_delivery_binding(request)?;
        let repository = RepositoryId::new(request.push().repository().full_name())
            .map_err(|_| GithubPushChangedFilesError::InvalidEvidence)?;
        let range = push_range(request.push())?;
        let authority = push_authority(request.authority());
        let deadline = Instant::now()
            .checked_add(self.endpoint.trusted_origins().limits().request_timeout())
            .ok_or(GithubPushChangedFilesError::Unavailable)?;
        let outcome = self
            .endpoint
            .push_changed_files(GithubPushDiffRequest::new(
                &repository,
                range,
                authority,
                deadline,
            ))
            .await
            .map_err(map_http_error)?;
        translate_outcome(outcome)
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
    ) -> Result<GithubChangedFilesV1, GithubPushChangedFilesError> {
        self.resolve(&request).await
    }
}

fn validate_delivery_binding(
    request: &GithubPushChangedFilesRequest<'_>,
) -> Result<(), GithubPushChangedFilesError> {
    let push = request.push();
    let identity = request.identity();
    if identity.provider() != "github" || identity.delivery_id() != push.delivery_id() {
        return Err(GithubPushChangedFilesError::InvalidEvidence);
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
        return Err(GithubPushChangedFilesError::InvalidEvidence);
    }
    Ok(())
}

fn push_range(
    push: &VerifiedGithubPush,
) -> Result<GithubPushDiffRange, GithubPushChangedFilesError> {
    if push.git_ref().kind() != GithubPushRefKind::Branch {
        return Err(GithubPushChangedFilesError::InvalidEvidence);
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
    let before = ExactRevision::new(push.before_commit_sha())
        .map_err(|_| GithubPushChangedFilesError::InvalidEvidence)?;
    let after = ExactRevision::new(push.after_commit_sha())
        .map_err(|_| GithubPushChangedFilesError::InvalidEvidence)?;
    let pushed_commits = push
        .complete_pushed_commit_revisions()
        .ok_or(GithubPushChangedFilesError::InvalidEvidence)?;
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

fn translate_outcome(
    outcome: GithubPushDiffOutcome,
) -> Result<GithubChangedFilesV1, GithubPushChangedFilesError> {
    match outcome {
        GithubPushDiffOutcome::Complete(evidence) => Ok(GithubChangedFilesV1::complete(
            evidence.into_changed_paths(),
        )),
        _ => Err(GithubPushChangedFilesError::InvalidEvidence),
    }
}

fn map_http_error(error: GithubPushDiffError) -> GithubPushChangedFilesError {
    match error {
        GithubPushDiffError::Unavailable => GithubPushChangedFilesError::Unavailable,
    }
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
        assert_eq!(
            push_range(&tag).unwrap_err(),
            GithubPushChangedFilesError::InvalidEvidence
        );
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
                translate_outcome(GithubPushDiffOutcome::Incomplete(reason)).unwrap_err(),
                GithubPushChangedFilesError::InvalidEvidence
            );
        }
        assert_eq!(
            map_http_error(GithubPushDiffError::Unavailable),
            GithubPushChangedFilesError::Unavailable
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
