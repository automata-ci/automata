use crate::support;

use std::sync::{Arc, Mutex, PoisonError};

use automata_ci_runner_spool::{
    ContentKind, DurableContentStore, FileSpool, FileSpoolOptions, SpoolCapacityResource,
    SpoolEvent, SpoolFailureKind, SpoolInvariantError, SpoolLimits, SpoolObserver, SpoolOperation,
    SpoolOperationOutcome, SpoolRoot,
};
use static_assertions::assert_obj_safe;
use support::{Scratch, StaticRetainSet, TestProtector, adopt};

assert_obj_safe!(SpoolObserver);

#[derive(Debug, Default)]
struct CapturingObserver {
    events: Mutex<Vec<SpoolEvent>>,
}

impl CapturingObserver {
    fn events(&self) -> Vec<SpoolEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SpoolObserver for CapturingObserver {
    fn observe(&self, event: SpoolEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }
}

fn protector() -> Arc<TestProtector> {
    Arc::new(TestProtector::new("observability-v1", 0x5a))
}

#[test]
fn operations_protection_reclaim_and_bytes_are_observed_without_identity() {
    let scratch = Scratch::new("observability");
    let observer = Arc::new(CapturingObserver::default());
    let spool = FileSpool::open_with_options(
        scratch.spool_root(),
        protector(),
        FileSpoolOptions::new().with_observer(observer.clone()),
    )
    .expect("open observed spool");
    let secret_payload = b"secret-observer-sentinel";
    let reference = adopt(
        spool
            .persist(ContentKind::JobIr, secret_payload)
            .expect("persist observed content"),
    );
    assert_eq!(
        spool.load(&reference).expect("load observed content"),
        secret_payload
    );
    let orphan = spool
        .persist(ContentKind::TerminalResult, b"orphan")
        .expect("persist payload-first orphan");
    orphan.abort();
    spool
        .reconcile(&StaticRetainSet::new([reference.clone()]))
        .expect("reclaim orphan");
    assert!(spool.remove(&reference).expect("remove retained content"));
    assert!(!spool.remove(&reference).expect("idempotent remove"));

    let events = observer.events();
    let starts = events
        .iter()
        .filter(|event| matches!(event, SpoolEvent::OperationStarted { .. }))
        .count();
    let completions = events
        .iter()
        .filter(|event| matches!(event, SpoolEvent::OperationCompleted { .. }))
        .count();
    assert_eq!(
        starts, completions,
        "every started operation must terminate"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        SpoolEvent::OperationCompleted {
            operation: SpoolOperation::Remove,
            outcome: SpoolOperationOutcome::AlreadyAbsent,
            failure: None,
            ..
        }
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        SpoolEvent::Reclaimed {
            objects: 1,
            protected_bytes
        } if *protected_bytes > 0
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        SpoolEvent::ContentBytes {
            operation: SpoolOperation::Persist,
            content_kind: ContentKind::JobIr,
            bytes
        } if *bytes == secret_payload.len() as u64
    )));
    let debug = format!("{events:?}");
    assert!(!debug.contains("secret-observer-sentinel"));
    assert!(!debug.contains(reference.cache_key().as_str()));
    assert!(!debug.contains("operation_id"));
}

#[test]
fn endpoint_result_observation_reports_only_the_padded_allocation_class() {
    let scratch = Scratch::new("endpoint-result-observability");
    let observer = Arc::new(CapturingObserver::default());
    let spool = FileSpool::open_with_options(
        scratch.spool_root(),
        protector(),
        FileSpoolOptions::new().with_observer(observer.clone()),
    )
    .expect("open observed spool");
    let short = adopt(
        spool
            .reserve_endpoint_result(128)
            .expect("reserve short result")
            .persist(b"x")
            .expect("persist short result"),
    );
    let longer = adopt(
        spool
            .reserve_endpoint_result(128)
            .expect("reserve longer result")
            .persist(&[b'y'; 128])
            .expect("persist longer result"),
    );
    assert_eq!(spool.load(&short).expect("load short result"), b"x");
    assert_eq!(
        spool.load(&longer).expect("load longer result"),
        [b'y'; 128]
    );

    let endpoint_bytes: Vec<_> = observer
        .events()
        .into_iter()
        .filter_map(|event| match event {
            SpoolEvent::ContentBytes {
                content_kind: ContentKind::EndpointResult,
                bytes,
                ..
            } => Some(bytes),
            _ => None,
        })
        .collect();
    assert_eq!(endpoint_bytes, vec![65_536; 4]);
    assert!(!endpoint_bytes.contains(&1));
    assert!(!endpoint_bytes.contains(&128));
}

#[test]
fn capacity_and_typed_failures_are_terminal_and_identifier_free() {
    let scratch = Scratch::new("observability-capacity");
    let observer = Arc::new(CapturingObserver::default());
    let root = SpoolRoot::explicit(scratch.child("bounded")).expect("bounded spool root");
    let limits = SpoolLimits::new(4, 128, 1, 64).expect("coherent tiny limits");
    let spool = FileSpool::open_with_options(
        root,
        protector(),
        FileSpoolOptions::new()
            .with_limits(limits)
            .with_observer(observer.clone()),
    )
    .expect("open bounded observed spool");
    let error = spool
        .persist(ContentKind::LogSpool, b"oversized")
        .expect_err("oversized object must fail");
    assert!(matches!(
        error,
        automata_ci_runner_spool::SpoolError::Invariant(SpoolInvariantError::ObjectTooLarge)
    ));

    let events = observer.events();
    assert!(events.iter().any(|event| matches!(
        event,
        SpoolEvent::CapacityRejected {
            resource: SpoolCapacityResource::ObjectBytes
        }
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        SpoolEvent::OperationCompleted {
            operation: SpoolOperation::Persist,
            outcome: SpoolOperationOutcome::Error,
            failure: Some(SpoolFailureKind::InvalidInput),
            ..
        }
    )));
}
