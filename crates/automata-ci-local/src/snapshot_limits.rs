use automata_ci_workflow_actions::RepositoryWorkflowDiscoveryLimits;

// Capture retains bounded Git inventories and one expanded file inventory while
// constructing one compressed archive. These local-only ceilings keep the peak
// materially below the shared delivery-scale bounds; the result retains none
// of those buffers after analysis.
const MAX_COMPRESSED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;
const MAX_EXPANDED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENTRY_PATH_BYTES: usize = 4_096;
const MAX_WORKFLOWS: usize = 128;
const MAX_WORKFLOW_BYTES: u64 = 1024 * 1024;

pub(crate) fn local_snapshot_limits() -> RepositoryWorkflowDiscoveryLimits {
    RepositoryWorkflowDiscoveryLimits::new(
        MAX_COMPRESSED_BYTES,
        MAX_DECOMPRESSED_BYTES,
        MAX_ENTRIES,
        MAX_EXPANDED_BYTES,
        MAX_ENTRY_PATH_BYTES,
        MAX_WORKFLOWS,
        MAX_WORKFLOW_BYTES,
    )
    .expect("fixed local snapshot limits must satisfy shared hard bounds")
}
