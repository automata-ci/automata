use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use automata_action::{
    ActionReferenceIndex, ActionReferenceIndexErrorKind, ActionSubpath, ImmutableActionReference,
    IndexedActionBundle, PutActionReferenceOutcome,
};
use automata_action_cache_file::{
    ActionReferenceIndexLimits, ActionReferenceIndexRoot, FileActionReferenceIndex,
};
use automata_blob::{BlobKey, BlobPayload, MediaType};
use automata_scm::{RepositoryId, ResolvedRevision, RevisionSpec, ScmProviderId};
use bytes::Bytes;

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn bounded_index_survives_reopen_and_evicts_oldest_reference() {
    let scratch = Scratch::new("bounded-reopen");
    let root = scratch.root();
    let limits = ActionReferenceIndexLimits::new(2, 16 * 1_024).unwrap();
    let index = FileActionReferenceIndex::open(root.clone(), limits).unwrap();
    let first = bundle(1, b"one");
    let second = bundle(2, b"two");
    let third = bundle(3, b"three");
    index.put_if_absent(first.clone()).await.unwrap();
    index.put_if_absent(second.clone()).await.unwrap();
    index.put_if_absent(third.clone()).await.unwrap();
    assert!(index.get(first.reference()).await.unwrap().is_none());
    assert_eq!(index.get(second.reference()).await.unwrap(), Some(second));
    assert_eq!(index.get(third.reference()).await.unwrap(), Some(third));
    drop(index);

    let reopened = FileActionReferenceIndex::open(root, limits).unwrap();
    assert!(reopened.get(first.reference()).await.unwrap().is_none());
}

#[tokio::test]
async fn concurrent_identical_fill_creates_exactly_one_mapping() {
    let scratch = Scratch::new("concurrent-fill");
    let index = Arc::new(
        FileActionReferenceIndex::open(scratch.root(), ActionReferenceIndexLimits::default())
            .unwrap(),
    );
    let expected = bundle(7, b"same immutable archive");
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let index = index.clone();
        let bundle = expected.clone();
        tasks.push(tokio::spawn(async move {
            index.put_if_absent(bundle).await.unwrap()
        }));
    }
    let mut created = 0_usize;
    let mut already_present = 0_usize;
    for task in tasks {
        match task.await.unwrap() {
            PutActionReferenceOutcome::Created => created += 1,
            PutActionReferenceOutcome::AlreadyPresent => already_present += 1,
        }
    }
    assert_eq!(created, 1);
    assert_eq!(already_present, 15);
    assert_eq!(
        index.get(expected.reference()).await.unwrap(),
        Some(expected)
    );
}

#[tokio::test]
async fn conflicting_fill_is_rejected_without_overwriting_authority() {
    let scratch = Scratch::new("conflicting-fill");
    let root = scratch.root();
    let index = FileActionReferenceIndex::open(root.clone(), ActionReferenceIndexLimits::default())
        .unwrap();
    let first = bundle(11, b"first bytes");
    let mut conflict = bundle(12, b"different bytes");
    conflict = IndexedActionBundle::new(
        first.reference().clone(),
        first.resolved_revision().clone(),
        conflict.archive().clone(),
    )
    .unwrap();
    index.put_if_absent(first.clone()).await.unwrap();
    let error = index.put_if_absent(conflict).await.unwrap_err();
    assert_eq!(error.kind(), ActionReferenceIndexErrorKind::Conflict);
    assert_eq!(
        index.get(first.reference()).await.unwrap(),
        Some(first.clone())
    );
    drop(index);

    let reopened =
        FileActionReferenceIndex::open(root, ActionReferenceIndexLimits::default()).unwrap();
    assert_eq!(reopened.get(first.reference()).await.unwrap(), Some(first));
}

#[test]
fn corrupt_or_oversized_state_and_second_owner_fail_closed() {
    let scratch = Scratch::new("fail-closed-open");
    let root = scratch.root();
    let index = FileActionReferenceIndex::open(root.clone(), ActionReferenceIndexLimits::default())
        .unwrap();
    let error = FileActionReferenceIndex::open(root.clone(), ActionReferenceIndexLimits::default())
        .unwrap_err();
    assert_eq!(error.kind(), ActionReferenceIndexErrorKind::AlreadyLocked);
    drop(index);

    fs::write(
        root.as_path().join("action-reference-index-v1.json"),
        b"{\"schema_version\":1,\"generation\":1,\"entries\":[",
    )
    .unwrap();
    let error = FileActionReferenceIndex::open(root.clone(), ActionReferenceIndexLimits::default())
        .unwrap_err();
    assert_eq!(error.kind(), ActionReferenceIndexErrorKind::Corrupt);

    fs::write(
        root.as_path().join("action-reference-index-v1.json"),
        br#"{"schema_version":1,"generation":1,"entries":[{"sequence":1,"provider":"github","repository":"actions/example","revision":"0000000000000000000000000000000000000001","subpath":"packages/action","resolved_revision":"0000000000000000000000000000000000000002","archive":{"key":"actions/v1/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tar.gz","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"media_type":"application/gzip"}}]}"#,
    )
    .unwrap();
    let error = FileActionReferenceIndex::open(root.clone(), ActionReferenceIndexLimits::default())
        .unwrap_err();
    assert_eq!(error.kind(), ActionReferenceIndexErrorKind::Corrupt);

    fs::write(
        root.as_path().join("action-reference-index-v1.json"),
        vec![b'x'; 1_025],
    )
    .unwrap();
    let error =
        FileActionReferenceIndex::open(root, ActionReferenceIndexLimits::new(4, 1_024).unwrap())
            .unwrap_err();
    assert_eq!(
        error.kind(),
        ActionReferenceIndexErrorKind::ResourceExhausted
    );
}

#[test]
fn abandoned_staging_file_is_recovered_inside_state_root() {
    let scratch = Scratch::new("staging-recovery");
    let root = scratch.root();
    let staging = root
        .as_path()
        .join(".action-reference-index.stage-abandoned");
    fs::create_dir_all(root.as_path()).unwrap();
    fs::write(&staging, b"incomplete").unwrap();
    let index =
        FileActionReferenceIndex::open(root, ActionReferenceIndexLimits::default()).unwrap();
    assert!(!staging.exists());
    drop(index);
}

#[test]
fn root_policy_rejects_relative_root_filesystem_and_temporary_hierarchy() {
    for path in [
        PathBuf::from("relative/cache"),
        PathBuf::from("/"),
        PathBuf::from("/var/tmp/automata-cache"),
    ] {
        let error = ActionReferenceIndexRoot::explicit(path).unwrap_err();
        assert_eq!(error.kind(), ActionReferenceIndexErrorKind::Unsupported);
    }
}

fn bundle(sequence: u64, bytes: &[u8]) -> IndexedActionBundle {
    let revision = format!("{sequence:040x}");
    let reference = ImmutableActionReference::new(
        ScmProviderId::new("github").unwrap(),
        RepositoryId::new(format!("actions/example-{sequence}")).unwrap(),
        RevisionSpec::new(revision.clone()).unwrap(),
        ActionSubpath::new("packages/action").unwrap(),
    )
    .unwrap();
    let payload = BlobPayload::from_bytes(
        BlobKey::new("actions/v1/sha256/placeholder.tar.gz").unwrap(),
        MediaType::new("application/gzip").unwrap(),
        Bytes::copy_from_slice(bytes),
    );
    let archive = automata_blob::BlobDescriptor::new(
        BlobKey::new(format!(
            "actions/v1/sha256/{}.tar.gz",
            payload.descriptor().digest()
        ))
        .unwrap(),
        payload.descriptor().digest(),
        payload.descriptor().size(),
        payload.descriptor().media_type().clone(),
    );
    IndexedActionBundle::new(reference, ResolvedRevision::new(revision).unwrap(), archive).unwrap()
}

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate is inside workspace crates directory");
        let path = workspace
            .join("target/agent-scratch/action-reference-index")
            .join(format!("{}-{label}-{sequence}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        Self { path }
    }

    fn root(&self) -> ActionReferenceIndexRoot {
        ActionReferenceIndexRoot::explicit(self.path.clone()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}
