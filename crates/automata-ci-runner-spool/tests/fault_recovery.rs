mod support;

use std::sync::Arc;

use automata_ci_runner_spool::{
    ContentCommitFault, ContentCommitFaultInjector, ContentCommitStage, ContentKind,
    DurableContentStore, FileSpool, FileSpoolOptions, SpoolError,
};
use support::{Scratch, TestProtector, adopt};

#[derive(Debug)]
struct FailAt(ContentCommitStage);

impl ContentCommitFaultInjector for FailAt {
    fn check(&self, stage: ContentCommitStage) -> Result<(), ContentCommitFault> {
        if stage == self.0 {
            Err(ContentCommitFault)
        } else {
            Ok(())
        }
    }
}

fn protector() -> Arc<TestProtector> {
    Arc::new(TestProtector::new("fault-test-aead-v1", 0x51))
}

fn options(stage: ContentCommitStage) -> FileSpoolOptions {
    FileSpoolOptions::new().with_fault_injector(Arc::new(FailAt(stage)))
}

#[test]
fn pre_rename_faults_publish_nothing_and_reopen_cleans_staging() {
    for stage in [
        ContentCommitStage::StagingCreated,
        ContentCommitStage::DataWritten,
        ContentCommitStage::FileSynced,
    ] {
        let scratch = Scratch::new(&format!("content-before-rename-{stage:?}"));
        let root = scratch.spool_root();
        let spool =
            FileSpool::open_with_options(root.clone(), protector(), options(stage)).expect("open");
        assert!(matches!(
            spool.persist(ContentKind::JobIr, b"verified JobIR payload"),
            Err(SpoolError::InjectedFault(received)) if received == stage
        ));
        assert_eq!(spool.usage().expect("unchanged usage"), (0, 0));
        drop(spool);

        let reopened = FileSpool::open(root.clone(), protector()).expect("recover spool");
        assert_eq!(reopened.usage().expect("empty recovery"), (0, 0));
        assert!(
            std::fs::read_dir(root.as_path())
                .expect("read spool root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".runner-spool.stage-"))
        );
        adopt(
            reopened
                .persist(ContentKind::JobIr, b"verified JobIR payload")
                .expect("retry after recovery"),
        );
    }
}

#[test]
fn post_rename_faults_poison_the_handle_and_reopen_recovers_exact_content() {
    for stage in [
        ContentCommitStage::Renamed,
        ContentCommitStage::DirectorySynced,
    ] {
        let scratch = Scratch::new(&format!("content-after-rename-{stage:?}"));
        let root = scratch.spool_root();
        let payload = b"exact result payload";
        let spool =
            FileSpool::open_with_options(root.clone(), protector(), options(stage)).expect("open");
        match spool.persist(ContentKind::TerminalResult, payload) {
            Err(SpoolError::CommitOutcomeUnknown) => {}
            other => panic!("expected unknown commit outcome, received {other:?}"),
        }
        assert!(matches!(spool.usage(), Err(SpoolError::Poisoned)));
        drop(spool);

        let reopened = FileSpool::open(root, protector()).expect("recover spool");
        let reference = adopt(
            reopened
                .persist(ContentKind::TerminalResult, payload)
                .expect("re-persist and verify uncertain content"),
        );
        assert_eq!(
            reopened.load(&reference).expect("recover exact bytes"),
            payload
        );
        assert_eq!(reopened.usage().expect("recovered usage").0, 1);
    }
}
