mod support;

use std::{fs, sync::Arc};

use automata_runner_spool::{
    ContentKind, ContentProtectionError, DurableContentStore, FileSpool, FileSpoolOptions,
    SpoolError, SpoolInvariantError, SpoolLimits,
};
use static_assertions::assert_obj_safe;
use support::{Scratch, StaticRetainSet, TestProtector, adopt, content_path};

assert_obj_safe!(DurableContentStore);

fn protector() -> Arc<TestProtector> {
    Arc::new(TestProtector::new("test-aead-v1", 0xa7))
}

#[test]
fn protected_content_is_durable_deduplicated_and_reclaimable() {
    let scratch = Scratch::new("durable-content");
    let root = scratch.spool_root();
    let plaintext = b"canonical JobIR bytes that must never be stored in cleartext";
    let spool = FileSpool::open(root.clone(), protector()).expect("open spool");
    let reference = adopt(
        spool
            .persist(ContentKind::JobIr, plaintext)
            .expect("persist content"),
    );
    assert_eq!(spool.load(&reference).expect("load content"), plaintext);
    let usage = spool.usage().expect("usage");
    assert_eq!(usage.0, 1);

    let replay = adopt(
        spool
            .persist(ContentKind::JobIr, plaintext)
            .expect("deduplicate content"),
    );
    assert_eq!(replay, reference);
    assert_eq!(spool.usage().expect("stable usage"), usage);
    let protected = fs::read(content_path(&root, &reference)).expect("protected bytes");
    assert!(
        !protected
            .windows(plaintext.len())
            .any(|part| part == plaintext)
    );
    assert!(!format!("{spool:?}").contains("canonical JobIR"));
    drop(spool);

    let spool = FileSpool::open(root, protector()).expect("reopen spool");
    assert_eq!(spool.load(&reference).expect("recover content"), plaintext);
    assert!(spool.remove(&reference).expect("remove content"));
    assert!(!spool.remove(&reference).expect("idempotent remove"));
    assert!(matches!(
        spool.load(&reference),
        Err(SpoolError::ContentMissing)
    ));
    assert_eq!(spool.usage().expect("empty usage"), (0, 0));
}

#[test]
fn protection_identity_and_authentication_are_enforced_on_reopen() {
    let scratch = Scratch::new("protector-fence");
    let root = scratch.spool_root();
    let spool = FileSpool::open(root.clone(), protector()).expect("open spool");
    let reference = adopt(
        spool
            .persist(ContentKind::TerminalResult, b"exact terminal result")
            .expect("persist result"),
    );
    drop(spool);

    let wrong_identity = Arc::new(TestProtector::new("different-key-id", 0xa7));
    let spool = FileSpool::open(root.clone(), wrong_identity).expect("open with other identity");
    assert!(matches!(
        spool.load(&reference),
        Err(SpoolError::Invariant(SpoolInvariantError::ContentMismatch))
    ));
    drop(spool);

    let wrong_key = Arc::new(TestProtector::new("test-aead-v1", 0x38));
    let spool = FileSpool::open(root, wrong_key).expect("open with rotated key material");
    assert!(matches!(
        spool.load(&reference),
        Err(SpoolError::Protection(
            ContentProtectionError::AuthenticationFailed
        ))
    ));
}

#[test]
fn exclusive_lock_and_coherent_capacity_limits_are_enforced() {
    let scratch = Scratch::new("limits-and-lock");
    let limits = SpoolLimits::new(64, 256, 2, 64).expect("coherent limits");
    let spool = FileSpool::open_with_options(
        scratch.spool_root(),
        protector(),
        FileSpoolOptions::new().with_limits(limits),
    )
    .expect("open bounded spool");
    assert!(matches!(
        FileSpool::open(scratch.spool_root(), protector()),
        Err(SpoolError::AlreadyLocked)
    ));
    assert!(matches!(
        spool.persist(ContentKind::JobIr, &[0; 65]),
        Err(SpoolError::Invariant(SpoolInvariantError::ObjectTooLarge))
    ));
    spool
        .persist(ContentKind::JobIr, b"first")
        .expect("first object")
        .abort();
    spool
        .persist(ContentKind::JobIr, b"second")
        .expect("second object")
        .abort();
    assert!(matches!(
        spool.persist(ContentKind::JobIr, b"third"),
        Err(SpoolError::CapacityExhausted)
    ));
    assert!(SpoolLimits::new(0, 1, 1, 0).is_err());
    assert!(SpoolLimits::new(64, 63, 1, 0).is_err());
}

#[test]
fn complete_journal_reconciliation_reclaims_payload_first_crash_leftovers() {
    let scratch = Scratch::new("reconcile-orphans");
    let root = scratch.spool_root();
    let spool = FileSpool::open(root.clone(), protector()).expect("open spool");
    let retained = adopt(
        spool
            .persist(ContentKind::JobIr, b"journaled JobIR")
            .expect("persist retained object"),
    );
    let crash_leftover = adopt(
        spool
            .persist(
                ContentKind::TerminalResult,
                b"payload committed before a lost journal commit",
            )
            .expect("persist orphan object"),
    );
    let missing = adopt(
        spool
            .persist(ContentKind::LogSpool, b"will be removed")
            .expect("persist missing fixture"),
    );
    spool.remove(&missing).expect("remove missing fixture");

    assert!(matches!(
        spool.reconcile(&StaticRetainSet::new([missing.clone()])),
        Err(SpoolError::ContentMissing)
    ));
    assert_eq!(
        spool.load(&crash_leftover).expect("no partial prune"),
        b"payload committed before a lost journal commit"
    );
    spool
        .reconcile(&StaticRetainSet::new([retained.clone()]))
        .expect("retain complete journal reference set");
    assert_eq!(spool.usage().expect("retained usage").0, 1);
    assert!(matches!(
        spool.load(&crash_leftover),
        Err(SpoolError::ContentMissing)
    ));
    drop(spool);

    let reopened = FileSpool::open(root, protector()).expect("reopen reconciled spool");
    assert_eq!(
        reopened.load(&retained).expect("retained content"),
        b"journaled JobIR"
    );
    assert_eq!(reopened.usage().expect("stable usage").0, 1);
}
