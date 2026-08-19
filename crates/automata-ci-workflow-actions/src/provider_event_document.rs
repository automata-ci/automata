//! Canonical Actions-dialect event documents projected from normalized provider facts.

use std::fmt;

use automata_ci_provider::{
    ExternalSubjectIdentity, ExternalSubjectKind, MergeQueueActivity, NormalizedTrigger,
    ProviderRepository, PullRequestActivity, RepositoryVisibility,
};
use serde_json::{Map, Value, json};
use thiserror::Error;

/// Maximum canonical bytes in one Actions-dialect provider event document.
pub const MAX_ACTIONS_PROVIDER_EVENT_BYTES: usize = 256 * 1_024;

/// Exact canonical event JSON consumed by the Actions workflow dialect.
///
/// Host-provider payloads never cross this boundary. GitHub, Forgejo, and
/// future adapters first authenticate and normalize their native webhook, then
/// project the same bounded dialect document. This keeps `github.event`
/// deterministic without making the workflow runtime depend on a host's raw
/// webhook schema.
#[derive(Clone, Eq, PartialEq)]
pub struct ActionsProviderEventDocument {
    event_name: &'static str,
    bytes: Vec<u8>,
}

impl ActionsProviderEventDocument {
    /// Projects one authenticated normalized trigger into canonical JSON.
    ///
    /// # Errors
    ///
    /// Rejects a repository-dispatch input that is not one canonical JSON
    /// value, serialization failure, or a projected document above the fixed
    /// dialect bound.
    pub fn from_normalized_trigger(
        trigger: &NormalizedTrigger,
    ) -> Result<Self, ActionsProviderEventDocumentError> {
        let (event_name, document) = match trigger {
            NormalizedTrigger::Push(push) => (
                "push",
                json!({
                    "after": push.after().map(|value| value.to_string()),
                    "before": push.before().map(|value| value.to_string()),
                    "created": push.before().is_none(),
                    "deleted": push.after().is_none(),
                    "forced": push.forced(),
                    "ref": push.git_ref().full(),
                    "repository": repository(push.repository()),
                    "sender": subject(push.actor()),
                }),
            ),
            NormalizedTrigger::PullRequest(pull_request) => (
                "pull_request",
                json!({
                    "action": pull_request_activity_name(pull_request.activity()),
                    "number": pull_request.change_id().as_str(),
                    "pull_request": {
                        "base": {
                            "ref": pull_request.base_ref().short_name(),
                            "repo": repository(pull_request.target_repository()),
                            "sha": pull_request.base_object().to_string(),
                        },
                        "draft": pull_request.draft(),
                        "head": {
                            "ref": pull_request.head_ref().short_name(),
                            "repo": repository(pull_request.source_repository()),
                            "sha": pull_request.head_object().to_string(),
                        },
                        "id": pull_request.change_id().as_str(),
                        "merge_commit_sha": pull_request
                            .merge_object()
                            .map(|value| value.to_string()),
                        "merged": pull_request.activity() == PullRequestActivity::Merged,
                        "number": pull_request.change_id().as_str(),
                        "user": subject(pull_request.author()),
                    },
                    "repository": repository(pull_request.target_repository()),
                    "sender": subject(pull_request.actor()),
                }),
            ),
            NormalizedTrigger::MergeQueue(merge_queue) => (
                "merge_group",
                json!({
                    "action": merge_queue_activity_name(merge_queue.activity()),
                    "merge_group": {
                        "base_ref": merge_queue.target_ref().full(),
                        "base_sha": merge_queue.target_object().to_string(),
                        "head_ref": merge_queue.candidate_ref().full(),
                        "head_sha": merge_queue.candidate_object().to_string(),
                        "id": merge_queue.queue_id().as_str(),
                    },
                    "repository": repository(merge_queue.repository()),
                    "sender": subject(merge_queue.actor()),
                }),
            ),
            NormalizedTrigger::RepositoryDispatch(dispatch) => {
                let input = serde_json::from_slice::<Value>(dispatch.input().canonical_bytes())
                    .map_err(|_| ActionsProviderEventDocumentError::InvalidDispatchInput)?;
                (
                    "repository_dispatch",
                    json!({
                        "action": dispatch.event_type().as_str(),
                        "client_payload": input,
                        "repository": repository(dispatch.repository()),
                        "sender": subject(dispatch.actor()),
                    }),
                )
            }
        };
        let bytes = serde_json::to_vec(&document)
            .map_err(|_| ActionsProviderEventDocumentError::Encoding)?;
        if bytes.is_empty() || bytes.len() > MAX_ACTIONS_PROVIDER_EVENT_BYTES {
            return Err(ActionsProviderEventDocumentError::TooLarge);
        }
        Ok(Self { event_name, bytes })
    }

    /// Returns the Actions trigger name paired with this document.
    #[must_use]
    pub const fn event_name(&self) -> &'static str {
        self.event_name
    }

    /// Returns canonical JSON bytes suitable for immutable admission evidence.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the document and returns its canonical JSON bytes.
    #[must_use]
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for ActionsProviderEventDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionsProviderEventDocument")
            .field("event_name", &self.event_name)
            .field("bytes", &"[CANONICAL]")
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

/// Sanitized Actions event projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ActionsProviderEventDocumentError {
    /// Repository-dispatch input was not one valid JSON value.
    #[error("provider dispatch input is not valid Actions event JSON")]
    InvalidDispatchInput,
    /// Canonical JSON serialization failed.
    #[error("Actions provider event encoding failed")]
    Encoding,
    /// Projected event exceeded the fixed dialect bound.
    #[error("Actions provider event exceeds its byte limit")]
    TooLarge,
}

pub(crate) const fn pull_request_activity_name(activity: PullRequestActivity) -> &'static str {
    match activity {
        PullRequestActivity::Opened => "opened",
        PullRequestActivity::Reopened => "reopened",
        PullRequestActivity::Synchronized => "synchronize",
        PullRequestActivity::Closed | PullRequestActivity::Merged => "closed",
        PullRequestActivity::ReadyForReview => "ready_for_review",
        PullRequestActivity::ConvertedToDraft => "converted_to_draft",
        PullRequestActivity::MetadataChanged => "edited",
    }
}

pub(crate) const fn merge_queue_activity_name(activity: MergeQueueActivity) -> &'static str {
    match activity {
        MergeQueueActivity::Queued => "checks_requested",
        MergeQueueActivity::Removed => "destroyed",
    }
}

fn repository(value: &ProviderRepository) -> Value {
    json!({
        "full_name": value.path().as_str(),
        "id": value.identity().external_id().as_str(),
        "owner": {
            "id": value.owner_id().as_str(),
        },
        "private": value.visibility() != RepositoryVisibility::Public,
        "visibility": match value.visibility() {
            RepositoryVisibility::Public => "public",
            RepositoryVisibility::Internal => "internal",
            RepositoryVisibility::Private => "private",
        },
    })
}

fn subject(value: Option<&ExternalSubjectIdentity>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    let mut subject = Map::new();
    subject.insert(
        "id".to_owned(),
        Value::String(value.external_id().as_str().to_owned()),
    );
    subject.insert(
        "type".to_owned(),
        Value::String(
            match value.kind() {
                ExternalSubjectKind::User => "User",
                ExternalSubjectKind::Organization => "Organization",
                ExternalSubjectKind::Team => "Team",
                ExternalSubjectKind::ServiceAccount => "Bot",
            }
            .to_owned(),
        ),
    );
    Value::Object(subject)
}

#[cfg(test)]
mod tests {
    use automata_ci_core::GitObjectId;
    use automata_ci_provider::{
        ExternalChangeId, ExternalRepositoryId, ExternalRepositoryIdentity, ExternalSubjectId,
        MergeQueueTrigger, ProviderGitRef, ProviderGitRefKind, ProviderInstanceId,
        ProviderRepositoryPath, PullRequestTrigger, PushCommitEvidence, PushTrigger,
    };

    use super::*;
    use crate::ProviderEventMetadata;

    fn object(value: char) -> GitObjectId {
        GitObjectId::from_provider_hex(value.to_string().repeat(40)).expect("object")
    }

    fn repository_value(instance: ProviderInstanceId, id: &str, path: &str) -> ProviderRepository {
        ProviderRepository::new(
            ExternalRepositoryIdentity::new(
                instance,
                ExternalRepositoryId::new(id).expect("repository ID"),
            ),
            ExternalSubjectId::new("42").expect("owner ID"),
            ProviderRepositoryPath::new(path).expect("repository path"),
            RepositoryVisibility::Private,
        )
    }

    #[test]
    fn push_document_is_host_independent_and_canonical() {
        let instance = ProviderInstanceId::new();
        let trigger = NormalizedTrigger::Push(
            PushTrigger::new(
                repository_value(instance, "7", "acme/widget"),
                ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("ref"),
                Some(object('a')),
                Some(object('b')),
                PushCommitEvidence::complete([object('b')]).expect("commit evidence"),
                false,
                None,
            )
            .expect("push"),
        );
        let document = ActionsProviderEventDocument::from_normalized_trigger(&trigger)
            .expect("event document");
        assert_eq!(document.event_name(), "push");
        let value: Value = serde_json::from_slice(document.canonical_bytes()).expect("JSON");
        assert_eq!(value["ref"], "refs/heads/main");
        assert_eq!(value["repository"]["full_name"], "acme/widget");
        assert_eq!(value["repository"]["id"], "7");
        assert_eq!(value["repository"]["private"], true);
        assert_eq!(value["sender"], Value::Null);
        assert_eq!(
            document.canonical_bytes(),
            serde_json::to_vec(&value).expect("canonical re-encoding")
        );
    }

    #[test]
    fn pull_request_and_merge_queue_use_actions_activity_names() {
        let instance = ProviderInstanceId::new();
        let pull_request = NormalizedTrigger::PullRequest(Box::new(
            PullRequestTrigger::new(
                ExternalChangeId::new("19").expect("change ID"),
                PullRequestActivity::Synchronized,
                repository_value(instance, "7", "acme/widget"),
                repository_value(instance, "8", "contributor/widget"),
                ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch)
                    .expect("base ref"),
                ProviderGitRef::new("refs/heads/topic", ProviderGitRefKind::Branch)
                    .expect("head ref"),
                ProviderGitRef::new("refs/pull/19/merge", ProviderGitRefKind::Synthetic)
                    .expect("execution ref"),
                object('a'),
                object('b'),
                Some(object('c')),
                false,
                None,
                None,
            )
            .expect("pull request"),
        ));
        let metadata = ProviderEventMetadata::from_normalized_trigger(&pull_request);
        assert!(metadata.matches_normalized_trigger(&pull_request));
        assert!(
            !ProviderEventMetadata::pull_request("edited", "main")
                .matches_normalized_trigger(&pull_request)
        );
        let pull_request = ActionsProviderEventDocument::from_normalized_trigger(&pull_request)
            .expect("pull request document");
        let pull_value: Value =
            serde_json::from_slice(pull_request.canonical_bytes()).expect("JSON");
        assert_eq!(pull_value["action"], "synchronize");
        assert_eq!(
            pull_value["pull_request"]["head"]["sha"],
            object('b').to_string()
        );

        let merge_queue = NormalizedTrigger::MergeQueue(
            MergeQueueTrigger::new(
                automata_ci_provider::ExternalMergeQueueId::new("queue-1").expect("queue ID"),
                MergeQueueActivity::Queued,
                repository_value(instance, "7", "acme/widget"),
                ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch)
                    .expect("target ref"),
                ProviderGitRef::new("refs/heads/merge-queue", ProviderGitRefKind::Branch)
                    .expect("candidate ref"),
                object('a'),
                object('d'),
                None,
            )
            .expect("merge queue"),
        );
        let merge_queue = ActionsProviderEventDocument::from_normalized_trigger(&merge_queue)
            .expect("merge queue document");
        let merge_value: Value =
            serde_json::from_slice(merge_queue.canonical_bytes()).expect("JSON");
        assert_eq!(merge_queue.event_name(), "merge_group");
        assert_eq!(merge_value["action"], "checks_requested");
        assert_eq!(
            merge_value["merge_group"]["head_sha"],
            object('d').to_string()
        );
    }
}
