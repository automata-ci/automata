mod support;

use std::sync::Arc;

use async_trait::async_trait;
use automata_ci_action::{
    ActionBundleLimits, ActionResolveErrorKind, ActionResolver, ActionSubpath,
    ImmutableActionResolver, RepositoryActionRequest,
};
use automata_ci_blob::{ImmutableBlobStore, MemoryBlobStore};
use automata_ci_scm::{
    ArchiveLimits, RepositoryId, RepositorySnapshot, RevisionSpec, ScmError, ScmProvider,
    ScmProviderId, SnapshotRequest,
};
use static_assertions::assert_obj_safe;
use support::{TestEntry, snapshot};

assert_obj_safe!(ActionResolver);

#[derive(Debug)]
struct FixedScm {
    provider: ScmProviderId,
    snapshot: RepositorySnapshot,
}

#[async_trait]
impl ScmProvider for FixedScm {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_snapshot(
        &self,
        _request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        Ok(self.snapshot.clone())
    }
}

#[tokio::test]
async fn resolution_validates_then_publishes_one_content_addressed_archive() {
    let snapshot = snapshot(&[
        TestEntry::File(
            "root/action.yml",
            b"name: example\nruns:\n  using: node24\n  main: dist/index.js\n",
        ),
        TestEntry::File("root/dist/index.js", b"console.log('ok')"),
    ]);
    let scm = Arc::new(FixedScm {
        provider: ScmProviderId::new("github").unwrap(),
        snapshot,
    });
    let blobs = Arc::new(MemoryBlobStore::default());
    let resolver = ImmutableActionResolver::new(scm, blobs.clone());
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new("v1").unwrap();
    let subpath = ActionSubpath::root();
    let request = || {
        RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        )
    };

    let first = resolver.resolve(request()).await.unwrap();
    let replay = resolver.resolve(request()).await.unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.provider().as_str(), "github");
    assert_eq!(first.resolved_revision().as_str(), support::SHA);
    assert_eq!(first.definition().path(), "action.yml");
    assert_eq!(
        first.archive().key().as_str(),
        format!("actions/v1/sha256/{}.tar.gz", first.archive().digest())
    );

    let stored = blobs
        .get_verified(first.archive(), ArchiveLimits::default().maximum_bytes())
        .await
        .unwrap();
    assert_eq!(stored.descriptor(), first.archive());
    assert_eq!(first.archive_bytes(), stored.bytes());
}

#[tokio::test]
async fn a_provider_cannot_substitute_another_repository() {
    let mut substituted = snapshot(&[TestEntry::File("root/action.yml", b"name: wrong")]);
    substituted = RepositorySnapshot::from_bytes(
        substituted.provider().clone(),
        RepositoryId::new("attacker/wrong").unwrap(),
        substituted.requested_revision().clone(),
        substituted.resolved_revision().clone(),
        substituted.format(),
        substituted.into_bytes(),
    );
    let resolver = ImmutableActionResolver::new(
        Arc::new(FixedScm {
            provider: ScmProviderId::new("github").unwrap(),
            snapshot: substituted,
        }),
        Arc::new(MemoryBlobStore::default()),
    );
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new("v1").unwrap();
    let subpath = ActionSubpath::root();
    let error = resolver
        .resolve(RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ActionResolveErrorKind::Internal);
}
