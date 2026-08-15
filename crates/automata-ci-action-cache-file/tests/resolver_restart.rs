use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_action::{
    ActionBundleLimits, ActionResolver, ActionSubpath, ImmutableActionResolver,
    RepositoryActionRequest,
};
use automata_ci_action_cache_file::{
    ActionReferenceIndexLimits, ActionReferenceIndexRoot, FileActionReferenceIndex,
};
use automata_ci_blob::MemoryBlobStore;
use automata_ci_scm::{
    ArchiveFormat, RepositoryId, RepositorySnapshot, ResolvedRevision, RevisionSpec, ScmError,
    ScmErrorKind, ScmProvider, ScmProviderId, SnapshotRequest,
};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, EntryType, Header};

const SHA: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

#[derive(Debug)]
struct OfflineSwitchScm {
    provider: ScmProviderId,
    archive: Bytes,
    offline: AtomicBool,
    calls: AtomicUsize,
}

#[async_trait]
impl ScmProvider for OfflineSwitchScm {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.offline.load(Ordering::SeqCst) {
            return Err(ScmError::new(ScmErrorKind::Unavailable));
        }
        Ok(RepositorySnapshot::from_bytes(
            self.provider.clone(),
            request.repository().clone(),
            request.revision().clone(),
            ResolvedRevision::new(SHA).unwrap(),
            ArchiveFormat::TarGzip,
            self.archive.clone(),
        ))
    }
}

#[tokio::test]
async fn durable_warm_hit_survives_resolver_restart_with_scm_offline() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let limits = ActionReferenceIndexLimits::default();
    let scm = Arc::new(OfflineSwitchScm {
        provider: ScmProviderId::new("github").unwrap(),
        archive: action_archive(),
        offline: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let blobs = Arc::new(MemoryBlobStore::default());
    let repository = RepositoryId::new("actions/checkout").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();
    let subpath = ActionSubpath::root();

    let index = Arc::new(FileActionReferenceIndex::open(root.clone(), limits).unwrap());
    let resolver =
        ImmutableActionResolver::new(scm.clone(), blobs.clone()).with_reference_index(index);
    let first = resolver
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap();
    drop(resolver);

    scm.offline.store(true, Ordering::SeqCst);
    let reopened = Arc::new(FileActionReferenceIndex::open(root, limits).unwrap());
    let resolver = ImmutableActionResolver::new(scm.clone(), blobs).with_reference_index(reopened);
    let replay = resolver
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(scm.calls.load(Ordering::SeqCst), 1);
}

fn request<'a>(
    repository: &'a RepositoryId,
    revision: &'a RevisionSpec,
    subpath: &'a ActionSubpath,
) -> RepositoryActionRequest<'a> {
    RepositoryActionRequest::public(repository, revision, subpath, ActionBundleLimits::default())
}

fn action_archive() -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut encoder);
        let contents = b"name: checkout\nruns:\n  using: node24\n  main: dist/index.js\n";
        let mut header = Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(contents.len()).unwrap());
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        archive
            .append_data(&mut header, "root/action.yml", Cursor::new(contents))
            .unwrap();
        archive.finish().unwrap();
    }
    Bytes::from(encoder.finish().unwrap())
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate is inside workspace crates directory");
        let path = workspace
            .join("target/agent-scratch/action-reference-index")
            .join(format!("{}-resolver-restart", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        Self(path)
    }

    fn root(&self) -> ActionReferenceIndexRoot {
        ActionReferenceIndexRoot::explicit(self.0.clone()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
