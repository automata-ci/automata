mod support;

use automata_ci_store::{MAX_ADMISSION_EVENT_BYTES, MAX_ADMISSION_OBJECT_BYTES};
use automata_ci_workflow_service::{WorkflowAdmissionRequest, WorkflowAdmissionRequestError};
use bytes::Bytes;

use support::push_request;

fn json_event(size: usize) -> Bytes {
    const PREFIX: &[u8] = b"{\"padding\":\"";
    const SUFFIX: &[u8] = b"\"}";
    assert!(size >= PREFIX.len() + SUFFIX.len());
    let mut event = Vec::with_capacity(size);
    event.extend_from_slice(PREFIX);
    event.resize(size - SUFFIX.len(), b'x');
    event.extend_from_slice(SUFFIX);
    assert_eq!(event.len(), size);
    Bytes::from(event)
}

fn rebuild(
    original: &WorkflowAdmissionRequest,
    source: Bytes,
    event: Bytes,
) -> Result<WorkflowAdmissionRequest, WorkflowAdmissionRequestError> {
    WorkflowAdmissionRequest::builder(
        original.tenant().clone(),
        original.repository().clone(),
        original.workflow_path(),
        source,
        event,
        original.plan().clone(),
        original.base_context().clone(),
        original.idempotency().clone(),
    )
    .commit_sha(original.commit_sha())
    .git_ref(original.git_ref())
    .workflow_name(original.workflow_name())
    .actor(original.actor().expect("fixture actor"))
    .run_attempt(original.run_attempt().expect("fixture attempt"))
    .build()
}

#[test]
fn provider_event_accepts_exact_twenty_five_mib_and_rejects_one_more_byte() {
    let original = push_request("event-limit-tenant");
    let maximum = usize::try_from(MAX_ADMISSION_EVENT_BYTES).expect("event limit fits usize");
    let accepted = rebuild(&original, original.source().clone(), json_event(maximum))
        .expect("exact provider event limit");
    assert_eq!(accepted.event().len(), maximum);

    assert!(matches!(
        rebuild(
            &original,
            original.source().clone(),
            json_event(maximum + 1),
        ),
        Err(WorkflowAdmissionRequestError::InvalidEvent)
    ));
}

#[test]
fn workflow_source_remains_capped_at_the_standard_object_limit() {
    let original = push_request("source-limit-tenant");
    let oversized = usize::try_from(MAX_ADMISSION_OBJECT_BYTES)
        .expect("source limit fits usize")
        .checked_add(1)
        .expect("source limit increment");

    assert!(matches!(
        rebuild(
            &original,
            Bytes::from(vec![b'x'; oversized]),
            original.event().clone(),
        ),
        Err(WorkflowAdmissionRequestError::OversizedSource)
    ));
}
