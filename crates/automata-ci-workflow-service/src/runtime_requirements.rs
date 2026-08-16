//! Pre-scheduling discovery of immutable repository-action runtime requirements.

use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use automata_ci_action::{
    ActionBundleLimits, WindowsActionArchiveReport, validate_windows_materialization_archive,
};
use automata_ci_action_github::JavascriptRuntime;
use automata_ci_core::{
    ActionReference, MAX_WINDOWS_ACTION_GRAPH_ARCHIVES, MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES,
    MAX_WINDOWS_ACTION_GRAPH_EXPANDED_BYTES, MAX_WINDOWS_ACTION_GRAPH_REGULAR_FILES, RunnerFeature,
    Sha256Digest, WindowsActionArchiveFacts, windows_repository_action_key_sha256,
};
use automata_ci_job_executor_github::{
    ActionPreparationErrorKind, ActionPreparationPort, ActionPreparationRequest, PreparedAction,
    PreparedActionExecution, PreparedCompositeStep, PreparedValue, static_shell_requirement,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::AutonomousWorkflowLeaseError;

const MAX_ACTION_NESTING_DEPTH: usize = 10;
const MAX_ACTION_INVOCATIONS: u32 = 10_000;

#[derive(Default)]
struct DiscoveryState {
    active: Vec<String>,
    order: Vec<String>,
    invocations: u32,
    prepared: BTreeMap<String, PreparedAction>,
    reports: BTreeMap<String, WindowsActionArchiveReport>,
    key_digests: BTreeMap<String, Sha256Digest>,
    compressed_bytes: u64,
    expanded_bytes: u64,
    regular_files: u64,
    features: std::collections::BTreeSet<RunnerFeature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiscoveredRepositoryAction {
    key_sha256: Sha256Digest,
    prepared: PreparedAction,
    facts: WindowsActionArchiveFacts,
}

impl DiscoveredRepositoryAction {
    pub(crate) const fn key_sha256(&self) -> Sha256Digest {
        self.key_sha256
    }

    pub(crate) const fn prepared(&self) -> &PreparedAction {
        &self.prepared
    }

    pub(crate) const fn facts(&self) -> WindowsActionArchiveFacts {
        self.facts
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeRequirementDiscovery {
    features: std::collections::BTreeSet<RunnerFeature>,
    actions: Vec<DiscoveredRepositoryAction>,
}

impl RuntimeRequirementDiscovery {
    pub(crate) fn empty() -> Self {
        Self {
            features: std::collections::BTreeSet::new(),
            actions: Vec::new(),
        }
    }

    pub(crate) const fn features(&self) -> &std::collections::BTreeSet<RunnerFeature> {
        &self.features
    }

    pub(crate) fn actions(&self) -> &[DiscoveredRepositoryAction] {
        &self.actions
    }
}

/// Sanitized failure while deriving immutable action requirements before scheduling.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RuntimeRequirementDiscoveryError {
    /// Repository action preparation is not configured for this control plane.
    #[error("repository action requirement discovery is unavailable")]
    Unavailable,
    /// Action resolution or content loading failed and may be retried.
    #[error("repository action requirement discovery dependency failed")]
    Retryable,
    /// Action metadata, graph shape, or execution semantics are invalid.
    #[error("repository action runtime requirements are invalid")]
    Invalid,
    /// The selected workflow operation was cancelled.
    #[error("repository action requirement discovery was cancelled")]
    Cancelled,
    /// The activation lease was no longer authoritative before action I/O.
    #[error("repository action requirement discovery lost its activation lease")]
    Lease(#[from] AutonomousWorkflowLeaseError),
}

pub(crate) async fn discover_runtime_requirements(
    actions: Option<&Arc<dyn ActionPreparationPort>>,
    references: &[ActionReference],
    cancellation: &CancellationToken,
    before_prepare: &mut (dyn FnMut() -> Result<(), AutonomousWorkflowLeaseError> + Send),
) -> Result<RuntimeRequirementDiscovery, RuntimeRequirementDiscoveryError> {
    let mut state = DiscoveryState::default();
    for reference in references {
        match reference {
            ActionReference::Repository { .. } => {
                let actions = actions.ok_or(RuntimeRequirementDiscoveryError::Unavailable)?;
                discover_repository_action(
                    actions.as_ref(),
                    reference,
                    &mut state,
                    cancellation,
                    before_prepare,
                )
                .await?;
            }
            ActionReference::Local { .. } | ActionReference::Container { .. } => {
                return Err(RuntimeRequirementDiscoveryError::Invalid);
            }
        }
    }
    let mut discovered = Vec::with_capacity(state.order.len());
    for key in state.order {
        let prepared = state
            .prepared
            .remove(&key)
            .ok_or(RuntimeRequirementDiscoveryError::Invalid)?;
        let report = state
            .reports
            .remove(&key)
            .ok_or(RuntimeRequirementDiscoveryError::Invalid)?;
        let key_sha256 = state
            .key_digests
            .remove(&key)
            .ok_or(RuntimeRequirementDiscoveryError::Invalid)?;
        let facts = WindowsActionArchiveFacts::new(
            report.entry_count(),
            report.regular_file_count(),
            report.expanded_bytes(),
            report.maximum_regular_file_bytes(),
            report.maximum_depth(),
        )
        .map_err(|_| RuntimeRequirementDiscoveryError::Invalid)?;
        discovered.push(DiscoveredRepositoryAction {
            key_sha256,
            prepared,
            facts,
        });
    }
    Ok(RuntimeRequirementDiscovery {
        features: state.features,
        actions: discovered,
    })
}

#[allow(clippy::too_many_lines)]
fn discover_repository_action<'a>(
    actions: &'a dyn ActionPreparationPort,
    reference: &'a ActionReference,
    state: &'a mut DiscoveryState,
    cancellation: &'a CancellationToken,
    before_prepare: &'a mut (dyn FnMut() -> Result<(), AutonomousWorkflowLeaseError> + Send),
) -> Pin<Box<dyn Future<Output = Result<(), RuntimeRequirementDiscoveryError>> + Send + 'a>> {
    Box::pin(async move {
        if cancellation.is_cancelled() {
            return Err(RuntimeRequirementDiscoveryError::Cancelled);
        }
        if !immutable_repository_reference(reference) {
            return Err(RuntimeRequirementDiscoveryError::Invalid);
        }
        let key = action_reference_key(reference);
        let projected = state
            .invocations
            .checked_add(1)
            .ok_or(RuntimeRequirementDiscoveryError::Invalid)?;
        if state.active.len() >= MAX_ACTION_NESTING_DEPTH
            || projected > MAX_ACTION_INVOCATIONS
            || state.active.iter().any(|active| active == &key)
        {
            return Err(RuntimeRequirementDiscoveryError::Invalid);
        }
        state.invocations = projected;
        state.active.push(key.clone());
        state.features.insert(RunnerFeature::REPOSITORY_ACTIONS);

        let result = async {
            let action = if let Some(prepared) = state.prepared.get(&key) {
                prepared.clone()
            } else {
                before_prepare()?;
                let preparation = actions.prepare(ActionPreparationRequest::new(reference));
                let prepared = tokio::select! {
                    () = cancellation.cancelled() => {
                        return Err(RuntimeRequirementDiscoveryError::Cancelled);
                    }
                    result = preparation => result.map_err(classify_preparation_error)?,
                };
                let report = validate_windows_materialization_archive(
                    prepared.archive(),
                    ActionBundleLimits::default(),
                )
                .map_err(|_| RuntimeRequirementDiscoveryError::Invalid)?;
                let compressed = u64::try_from(prepared.archive().len())
                    .map_err(|_| RuntimeRequirementDiscoveryError::Invalid)?;
                state.compressed_bytes = state
                    .compressed_bytes
                    .checked_add(compressed)
                    .ok_or(RuntimeRequirementDiscoveryError::Invalid)?;
                state.expanded_bytes = state
                    .expanded_bytes
                    .checked_add(report.expanded_bytes())
                    .ok_or(RuntimeRequirementDiscoveryError::Invalid)?;
                state.regular_files = state
                    .regular_files
                    .checked_add(u64::from(report.regular_file_count()))
                    .ok_or(RuntimeRequirementDiscoveryError::Invalid)?;
                if state.order.len() >= MAX_WINDOWS_ACTION_GRAPH_ARCHIVES
                    || state.compressed_bytes > MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES
                    || state.expanded_bytes > MAX_WINDOWS_ACTION_GRAPH_EXPANDED_BYTES
                    || state.regular_files > MAX_WINDOWS_ACTION_GRAPH_REGULAR_FILES
                {
                    return Err(RuntimeRequirementDiscoveryError::Invalid);
                }
                state.order.push(key.clone());
                state.reports.insert(key.clone(), report);
                state.key_digests.insert(
                    key.clone(),
                    windows_repository_action_key_sha256(reference)
                        .map_err(|_| RuntimeRequirementDiscoveryError::Invalid)?,
                );
                state.prepared.insert(key.clone(), prepared.clone());
                prepared
            };
            match action.definition().execution() {
                PreparedActionExecution::Javascript(javascript) => {
                    state.features.insert(RunnerFeature::JAVASCRIPT_ACTIONS);
                    state.features.insert(match javascript.runtime() {
                        JavascriptRuntime::Node12 => RunnerFeature::NODE12_ACTIONS,
                        JavascriptRuntime::Node16 => RunnerFeature::NODE16_ACTIONS,
                        JavascriptRuntime::Node20 => RunnerFeature::NODE20_ACTIONS,
                        JavascriptRuntime::Node24 => RunnerFeature::NODE24_ACTIONS,
                    });
                }
                PreparedActionExecution::Composite(composite) => {
                    state.features.insert(RunnerFeature::COMPOSITE_ACTIONS);
                    for step in composite.steps() {
                        match step {
                            PreparedCompositeStep::Run(run) => {
                                state.features.insert(RunnerFeature::SHELL_STEPS);
                                let PreparedValue::Literal(shell) = run.shell() else {
                                    return Err(RuntimeRequirementDiscoveryError::Invalid);
                                };
                                state.features.insert(
                                    static_shell_requirement(shell)
                                        .map_err(|_| RuntimeRequirementDiscoveryError::Invalid)?,
                                );
                            }
                            PreparedCompositeStep::Uses(uses) => match uses.reference() {
                                ActionReference::Repository { .. } => {
                                    discover_repository_action(
                                        actions,
                                        uses.reference(),
                                        state,
                                        cancellation,
                                        before_prepare,
                                    )
                                    .await?;
                                }
                                ActionReference::Local { .. }
                                | ActionReference::Container { .. } => {
                                    // Repository preparation must bind local syntax to
                                    // the same exact repository revision, while nested
                                    // containers remain unsupported. Neither may cross
                                    // scheduling as an unresolved prepared child.
                                    return Err(RuntimeRequirementDiscoveryError::Invalid);
                                }
                            },
                        }
                    }
                }
            }
            Ok(())
        }
        .await;
        let popped = state.active.pop();
        debug_assert_eq!(popped.as_deref(), Some(key.as_str()));
        result
    })
}

fn classify_preparation_error(
    error: automata_ci_job_executor_github::ActionPreparationError,
) -> RuntimeRequirementDiscoveryError {
    match error.kind() {
        ActionPreparationErrorKind::Resolution
        | ActionPreparationErrorKind::Content
        | ActionPreparationErrorKind::Internal => RuntimeRequirementDiscoveryError::Retryable,
        ActionPreparationErrorKind::UnsupportedReference
        | ActionPreparationErrorKind::Metadata
        | ActionPreparationErrorKind::UnsupportedExecution
        | ActionPreparationErrorKind::RuntimeUnavailable
        | ActionPreparationErrorKind::ResourceExhausted
        | ActionPreparationErrorKind::PermissionDenied => RuntimeRequirementDiscoveryError::Invalid,
    }
}

fn action_reference_key(reference: &ActionReference) -> String {
    match reference {
        ActionReference::Repository {
            repository,
            revision,
            subpath,
        } => format!(
            "repository\0{repository}\0{revision}\0{}",
            subpath.as_deref().unwrap_or_default()
        ),
        ActionReference::Local { path } => format!("local\0{path}"),
        ActionReference::Container { image } => format!("container\0{image}"),
    }
}

fn immutable_repository_reference(reference: &ActionReference) -> bool {
    let ActionReference::Repository { revision, .. } = reference else {
        return false;
    };
    revision.len() == 40
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use automata_ci_action_github::{GithubActionMetadataDecoder, JavascriptRuntime};
    use automata_ci_core::Sha256Digest;
    use automata_ci_job_executor_github::{
        CheckedOutLocalActionPreparer, LocalActionPreparationRequest, PreparedActionDefinition,
        PreparedJavascriptAction,
    };
    use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
    use bytes::Bytes;
    use flate2::{Compression, write::GzEncoder};
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;
    use tar::{Builder, Header};

    use super::*;

    const ROOT_REVISION: &str = "1111111111111111111111111111111111111111";
    const CHILD_REVISION: &str = "2222222222222222222222222222222222222222";

    #[derive(Debug, Default)]
    struct FakeActions {
        prepared: BTreeMap<String, PreparedAction>,
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ActionPreparationPort for FakeActions {
        async fn prepare(
            &self,
            request: ActionPreparationRequest<'_>,
        ) -> Result<PreparedAction, automata_ci_job_executor_github::ActionPreparationError>
        {
            let key = action_reference_key(request.reference());
            self.calls.lock().expect("calls").push(key.clone());
            self.prepared.get(&key).cloned().ok_or_else(|| {
                automata_ci_job_executor_github::ActionPreparationError::new(
                    ActionPreparationErrorKind::Resolution,
                )
            })
        }
    }

    fn repository(repository: &str, revision: &str) -> ActionReference {
        repository_at(repository, revision, None)
    }

    fn repository_at(repository: &str, revision: &str, subpath: Option<&str>) -> ActionReference {
        ActionReference::Repository {
            repository: repository.to_owned(),
            revision: revision.to_owned(),
            subpath: subpath.map(str::to_owned),
        }
    }

    fn action_with_definition(label: &str, definition: PreparedActionDefinition) -> PreparedAction {
        let metadata = format!("name: {label}\nruns:\n  using: node20\n  main: dist/index.js\n");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut archive = Builder::new(&mut encoder);
            for (path, bytes) in [
                ("repository/action.yml", metadata.as_bytes()),
                (
                    "repository/dist/index.js",
                    b"console.log('fixture');".as_slice(),
                ),
            ] {
                let mut header = Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                archive
                    .append_data(&mut header, path, bytes)
                    .expect("append archive entry");
            }
            archive.finish().expect("finish tar");
        }
        encoder.flush().expect("flush gzip");
        let archive = Bytes::from(encoder.finish().expect("finish gzip"));
        let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
        PreparedAction::with_definition(digest, archive, "", definition).expect("prepared action")
    }

    fn javascript(runtime: JavascriptRuntime) -> PreparedAction {
        let compiler = GithubConditionCompiler::default();
        let always = compiler
            .compile_condition(Some("always()"), GithubConditionPhase::Step)
            .expect("condition");
        let javascript = PreparedJavascriptAction::new(
            runtime,
            "dist/index.js",
            None,
            always.clone(),
            None,
            always,
        )
        .expect("JavaScript action");
        action_with_definition(
            "javascript",
            PreparedActionDefinition::new(
                Vec::new(),
                Vec::new(),
                PreparedActionExecution::Javascript(Box::new(javascript)),
            )
            .expect("definition"),
        )
    }

    fn metadata(source: &str, label: &str) -> PreparedAction {
        let local = ActionReference::Local {
            path: format!("./{label}"),
        };
        let prepared = CheckedOutLocalActionPreparer::new(
            Arc::new(GithubActionMetadataDecoder::default()),
            GithubConditionCompiler::default(),
        )
        .prepare(LocalActionPreparationRequest::new(
            &local,
            Some(source.as_bytes()),
            None,
        ))
        .expect("metadata");
        action_with_definition(label, prepared.definition().clone())
    }

    #[tokio::test]
    async fn recursive_repository_graph_carries_nested_exact_node_and_shell_features() {
        let root = repository("synthetic/root", ROOT_REVISION);
        let child = repository("synthetic/child", CHILD_REVISION);
        let nested = repository_at("synthetic/root", ROOT_REVISION, Some("nested"));
        let composite = metadata(
            "runs:\n  using: composite\n  steps:\n    - shell: bash -e {0}\n      run: echo root\n    - uses: synthetic/child@2222222222222222222222222222222222222222\n    - uses: synthetic/root/nested@1111111111111111111111111111111111111111\n",
            "root",
        );
        let actions = Arc::new(FakeActions {
            prepared: BTreeMap::from([
                (action_reference_key(&root), composite),
                (
                    action_reference_key(&child),
                    javascript(JavascriptRuntime::Node24),
                ),
                (
                    action_reference_key(&nested),
                    javascript(JavascriptRuntime::Node20),
                ),
            ]),
            calls: Mutex::new(Vec::new()),
        });
        let actions_port: Arc<dyn ActionPreparationPort> = actions.clone();
        let mut checkpoints = 0_u32;
        let mut before_prepare = || {
            checkpoints += 1;
            Ok(())
        };
        let discovery = discover_runtime_requirements(
            Some(&actions_port),
            &[root],
            &CancellationToken::new(),
            &mut before_prepare,
        )
        .await
        .expect("requirements");
        assert_eq!(
            discovery.features().clone(),
            std::collections::BTreeSet::from([
                RunnerFeature::SHELL_STEPS,
                RunnerFeature::BASH_SHELL,
                RunnerFeature::JAVASCRIPT_ACTIONS,
                RunnerFeature::NODE20_ACTIONS,
                RunnerFeature::NODE24_ACTIONS,
                RunnerFeature::COMPOSITE_ACTIONS,
                RunnerFeature::REPOSITORY_ACTIONS,
            ])
        );
        assert_eq!(discovery.actions().len(), 3);
        assert_eq!(actions.calls.lock().expect("calls").len(), 3);
        assert_eq!(checkpoints, 3);
    }

    #[tokio::test]
    async fn recursive_cycles_and_invalid_static_composite_shells_fail_before_scheduling() {
        for (metadata_source, label) in [
            (
                "runs:\n  using: composite\n  steps:\n    - uses: synthetic/root@1111111111111111111111111111111111111111\n",
                "cycle",
            ),
            (
                "runs:\n  using: composite\n  steps:\n    - shell: fish\n      run: echo invalid\n",
                "shell",
            ),
            (
                "inputs:\n  shell:\n    default: bash\nruns:\n  using: composite\n  steps:\n    - shell: ${{ inputs.shell }}\n      run: echo dynamic\n",
                "dynamic-shell",
            ),
            (
                "runs:\n  using: composite\n  steps:\n    - uses: ./unbound-workspace-action\n",
                "unbound-local",
            ),
        ] {
            let root = repository("synthetic/root", ROOT_REVISION);
            let actions: Arc<dyn ActionPreparationPort> = Arc::new(FakeActions {
                prepared: BTreeMap::from([(
                    action_reference_key(&root),
                    metadata(metadata_source, label),
                )]),
                calls: Mutex::new(Vec::new()),
            });
            let mut before_prepare = || Ok(());
            assert_eq!(
                discover_runtime_requirements(
                    Some(&actions),
                    &[root],
                    &CancellationToken::new(),
                    &mut before_prepare,
                )
                .await,
                Err(RuntimeRequirementDiscoveryError::Invalid)
            );
        }
    }

    #[tokio::test]
    async fn checkout_created_local_metadata_fails_closed_before_scheduling() {
        let local = ActionReference::Local {
            path: "./checked-out".to_owned(),
        };
        let mut before_prepare = || Ok(());
        assert_eq!(
            discover_runtime_requirements(
                None,
                &[local],
                &CancellationToken::new(),
                &mut before_prepare,
            )
            .await,
            Err(RuntimeRequirementDiscoveryError::Invalid)
        );
        let mut before_prepare = || Ok(());
        assert_eq!(
            discover_runtime_requirements(
                None,
                &[repository("synthetic/root", ROOT_REVISION)],
                &CancellationToken::new(),
                &mut before_prepare,
            )
            .await,
            Err(RuntimeRequirementDiscoveryError::Unavailable)
        );
    }

    #[tokio::test]
    async fn mutable_repository_revisions_fail_without_io() {
        let actions_impl = Arc::new(FakeActions::default());
        let actions: Arc<dyn ActionPreparationPort> = actions_impl.clone();
        let mut checkpoints = 0_u32;
        let mut before_prepare = || {
            checkpoints += 1;
            Ok(())
        };
        assert_eq!(
            discover_runtime_requirements(
                Some(&actions),
                &[repository("synthetic/root", "v1")],
                &CancellationToken::new(),
                &mut before_prepare,
            )
            .await,
            Err(RuntimeRequirementDiscoveryError::Invalid)
        );
        assert_eq!(checkpoints, 0);
        assert!(actions_impl.calls.lock().expect("calls").is_empty());
    }

    #[test]
    fn repository_cache_keys_are_unambiguous() {
        let first = ActionReference::Repository {
            repository: "synthetic/root".to_owned(),
            revision: "feature/x".to_owned(),
            subpath: Some("action".to_owned()),
        };
        let second = ActionReference::Repository {
            repository: "synthetic/root".to_owned(),
            revision: "feature".to_owned(),
            subpath: Some("x/action".to_owned()),
        };
        assert_ne!(action_reference_key(&first), action_reference_key(&second));
    }
}
