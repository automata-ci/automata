use std::{collections::BTreeSet, sync::Arc};

use automata_ci_core::{
    InvocationInputDefault, InvocationInputType, PermissionLevel, PlanSourceOrigin, RunId,
    WorkflowEventProvenance,
};
use automata_ci_store::LogicalWorkflowInvocationId;
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    ExpandReusableWorkflowRequest, GithubReusableWorkflowCatalog, RepositoryWorkflowSource,
    ReusableInputBindingSource, ReusableWorkflowExpander, ReusableWorkflowExpansionError,
    ReusableWorkflowLimits, ReusableWorkflowPermissions,
};
use bytes::Bytes;
use uuid::Uuid;

const REPOSITORY: &str = "synthetic/repository";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const ROOT_PATH: &str = ".github/workflows/root.yml";
const CALLEE_PATH: &str = ".github/workflows/reusable.yml";

const CALLEE: &str = r"name: Reusable
on:
  workflow_call:
    inputs:
      enabled:
        required: true
        type: boolean
      attempts:
        type: number
        default: 2
      channel:
        type: string
        default: stable
    secrets:
      token:
        required: true
    outputs:
      digest:
        value: ${{ jobs.build.outputs.digest }}
permissions:
  contents: write
  issues: read
jobs:
  build:
    runs-on: linux
    outputs:
      digest: ${{ steps.result.outputs.digest }}
    steps:
      - id: result
        run: echo digest=synthetic
";

const ROOT: &str = r"name: Root
on: workflow_dispatch
permissions: write-all
jobs:
  invoke:
    permissions:
      contents: read
      issues: write
    uses: ./.github/workflows/reusable.yml
    with:
      enabled: true
    secrets:
      token: ${{ secrets.ROOT_TOKEN }}
  consume:
    needs: invoke
    runs-on: linux
    steps:
      - run: echo ${{ needs.invoke.outputs.digest }}
";

fn compile_root(source: &str) -> automata_ci_core::WorkflowPlan {
    let provenance = SourceProvenance::new(
        SourceId::new(ROOT_PATH),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(ROOT_PATH),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_commit_sha(REVISION)
            .with_git_ref("refs/heads/main"),
    ));
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    compiled.into_parts().0.expect("compiled plan")
}

fn catalog(
    sources: impl IntoIterator<Item = (&'static str, String)>,
) -> GithubReusableWorkflowCatalog {
    GithubReusableWorkflowCatalog::compile(
        REPOSITORY,
        REVISION,
        sources
            .into_iter()
            .map(|(path, source)| RepositoryWorkflowSource::new(path, Bytes::from(source))),
    )
    .expect("valid exact-source catalog")
}

fn ids() -> (RunId, LogicalWorkflowInvocationId) {
    (
        RunId::from_uuid(Uuid::from_u128(0x1100)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(0x2200))
            .expect("root invocation ID"),
    )
}

fn root_permissions() -> ReusableWorkflowPermissions {
    ReusableWorkflowPermissions::new(PermissionLevel::Write, Vec::new())
        .expect("root permission ceiling")
}

fn expand(
    root_source: &str,
    catalog: &GithubReusableWorkflowCatalog,
    limits: Option<ReusableWorkflowLimits>,
) -> Result<automata_ci_workflow_service::ReusableWorkflowExpansion, ReusableWorkflowExpansionError>
{
    let root_plan = compile_root(root_source);
    let (run_id, root_invocation_id) = ids();
    let secrets = BTreeSet::from(["ROOT_TOKEN".to_owned()]);
    let permissions = root_permissions();
    let request = ExpandReusableWorkflowRequest::new(
        run_id,
        root_invocation_id,
        ROOT_PATH,
        root_source.as_bytes(),
        &root_plan,
        catalog,
        &secrets,
        &permissions,
    );
    limits.map_or_else(
        || ReusableWorkflowExpander::new().expand(request),
        |limits| ReusableWorkflowExpander::with_limits(limits).expand(request),
    )
}

#[test]
fn exact_catalog_expands_typed_least_authority_call_deterministically() {
    let catalog = catalog([(CALLEE_PATH, CALLEE.to_owned())]);
    let first = expand(ROOT, &catalog, None).expect("first expansion");
    let replay = expand(ROOT, &catalog, None).expect("exact replay");
    assert_eq!(first, replay);
    assert_eq!(first.invocations().len(), 2);

    let root = &first.invocations()[0];
    let child = &first.invocations()[1];
    assert_eq!(child.parent_id(), Some(root.id()));
    assert_eq!(child.depth(), 1);
    assert_eq!(child.workflow_path(), CALLEE_PATH);
    assert_ne!(child.source_digest(), root.source_digest());
    assert_eq!(child.inputs().len(), 3);
    assert_eq!(child.inputs()[0].target(), "enabled");
    assert_eq!(child.inputs()[0].input_type(), InvocationInputType::Boolean);
    assert!(matches!(
        child.inputs()[0].source(),
        ReusableInputBindingSource::Caller(_)
    ));
    assert!(matches!(
        child.inputs()[1].source(),
        ReusableInputBindingSource::Default(InvocationInputDefault::Number(value)) if value == "2"
    ));
    assert!(matches!(
        child.inputs()[2].source(),
        ReusableInputBindingSource::Default(InvocationInputDefault::String(value)) if value == "stable"
    ));
    assert_eq!(child.secrets().len(), 1);
    assert_eq!(child.secrets()[0].target(), "token");
    assert_eq!(child.secrets()[0].source(), "ROOT_TOKEN");
    assert_eq!(child.outputs()[0].key(), "digest");
    assert_eq!(child.permissions().default_level(), PermissionLevel::None);
    assert_eq!(child.permissions().level("contents"), PermissionLevel::Read);
    assert_eq!(child.permissions().level("issues"), PermissionLevel::Read);
    assert_eq!(child.permissions().level("actions"), PermissionLevel::None);
    assert_eq!(root.jobs().len(), 2);
    assert_eq!(child.jobs().len(), 1);
    assert!(root.jobs()[0].is_reusable());
    assert_eq!(child.caller_job_id(), Some(root.jobs()[0].id()));
}

#[test]
fn exact_source_change_changes_catalog_binding_ids_and_replay_digest() {
    let first_catalog = catalog([(CALLEE_PATH, CALLEE.to_owned())]);
    let changed_source = CALLEE.replace(
        "echo digest=synthetic",
        "echo digest=changed-with-the-same-contract",
    );
    let changed_catalog = catalog([(CALLEE_PATH, changed_source)]);
    let first = expand(ROOT, &first_catalog, None).expect("first expansion");
    let changed = expand(ROOT, &changed_catalog, None).expect("changed expansion");
    assert_ne!(first.digest(), changed.digest());
    assert_ne!(first.invocations()[1].id(), changed.invocations()[1].id());
    assert_ne!(
        first.invocations()[1].source_digest(),
        changed.invocations()[1].source_digest()
    );
}

#[test]
fn canonical_local_path_resolution_rejects_aliases_and_remote_references() {
    for reference in [
        "../.github/workflows/reusable.yml",
        "./.github/workflows/../reusable.yml",
        ".github/workflows/reusable.yml",
        "synthetic/repository/.github/workflows/reusable.yml@main",
    ] {
        let root = ROOT.replace("./.github/workflows/reusable.yml", reference);
        let exact_catalog = catalog([(CALLEE_PATH, CALLEE.to_owned())]);
        assert_eq!(
            expand(&root, &exact_catalog, None),
            Err(ReusableWorkflowExpansionError::NonLocalReference),
            "reference `{reference}` must fail closed"
        );
    }
}

#[test]
fn catalog_requires_a_resolved_lowercase_commit_digest() {
    for revision in [
        "main",
        "0123456789abcdef0123456789abcdef0123456G",
        "0123456789ABCDEF0123456789ABCDEF01234567",
    ] {
        assert_eq!(
            GithubReusableWorkflowCatalog::compile(
                REPOSITORY,
                revision,
                [RepositoryWorkflowSource::new(
                    CALLEE_PATH,
                    Bytes::from_static(CALLEE.as_bytes()),
                )],
            ),
            Err(ReusableWorkflowExpansionError::InvalidRepositoryCoordinate),
            "revision `{revision}` must fail closed",
        );
    }
}

#[test]
fn call_stack_cycle_is_rejected_before_any_runnable_graph_exists() {
    let cyclic = r"on:
  workflow_call:
    inputs:
      enabled:
        required: true
        type: boolean
    secrets:
      token:
        required: true
    outputs:
      digest:
        value: ${{ jobs.produce.outputs.digest }}
jobs:
  produce:
    runs-on: linux
    outputs:
      digest: ${{ steps.result.outputs.digest }}
    steps:
      - id: result
        run: echo digest=cycle
  recurse:
    uses: ./.github/workflows/reusable.yml
";
    let exact_catalog = catalog([(CALLEE_PATH, cyclic.to_owned())]);
    assert_eq!(
        expand(ROOT, &exact_catalog, None),
        Err(ReusableWorkflowExpansionError::Cycle(
            CALLEE_PATH.to_owned()
        ))
    );
}

#[test]
fn literal_input_type_mismatch_and_missing_secret_are_rejected() {
    let exact_catalog = catalog([(CALLEE_PATH, CALLEE.to_owned())]);
    let wrong_type = ROOT.replace("enabled: true", "enabled: stable");
    assert_eq!(
        expand(&wrong_type, &exact_catalog, None),
        Err(ReusableWorkflowExpansionError::InputTypeMismatch(
            "enabled".to_owned()
        ))
    );

    let missing_secret = ROOT.replace("    secrets:\n      token: ${{ secrets.ROOT_TOKEN }}\n", "");
    assert_eq!(
        expand(&missing_secret, &exact_catalog, None),
        Err(ReusableWorkflowExpansionError::MissingRequiredSecret(
            "token".to_owned()
        ))
    );
}

#[test]
fn depth_invocation_and_aggregate_job_limits_are_independent() {
    let leaf_path = ".github/workflows/leaf.yml";
    let middle_path = ".github/workflows/middle.yml";
    let leaf = r"on:
  workflow_call: {}
jobs:
  leaf:
    runs-on: linux
    steps:
      - run: echo leaf
";
    let middle = r"on:
  workflow_call: {}
jobs:
  descend:
    uses: ./.github/workflows/leaf.yml
";
    let top = r"on:
  workflow_call:
    inputs:
      enabled:
        required: true
        type: boolean
    secrets:
      token:
        required: true
    outputs:
      digest:
        value: ${{ jobs.prepare.outputs.digest }}
jobs:
  prepare:
    runs-on: linux
    outputs:
      digest: ${{ steps.result.outputs.digest }}
    steps:
      - id: result
        run: echo digest=top
  descend:
    uses: ./.github/workflows/middle.yml
";
    let exact_catalog = catalog([
        (CALLEE_PATH, top.to_owned()),
        (middle_path, middle.to_owned()),
        (leaf_path, leaf.to_owned()),
    ]);

    let depth = ReusableWorkflowLimits::new(2, 256, 4_096).expect("narrow depth");
    assert_eq!(
        expand(ROOT, &exact_catalog, Some(depth)),
        Err(ReusableWorkflowExpansionError::DepthLimitExceeded)
    );

    let invocations = ReusableWorkflowLimits::new(9, 1, 4_096).expect("one invocation");
    assert_eq!(
        expand(ROOT, &exact_catalog, Some(invocations)),
        Err(ReusableWorkflowExpansionError::InvocationLimitExceeded)
    );

    let jobs = ReusableWorkflowLimits::new(9, 256, 2).expect("two jobs");
    assert_eq!(
        expand(ROOT, &exact_catalog, Some(jobs)),
        Err(ReusableWorkflowExpansionError::JobLimitExceeded)
    );
}

#[test]
fn root_plan_must_recompile_from_the_exact_supplied_source() {
    let exact_catalog = catalog([(CALLEE_PATH, CALLEE.to_owned())]);
    let root_plan = compile_root(ROOT);
    let (run_id, root_invocation_id) = ids();
    let secrets = BTreeSet::from(["ROOT_TOKEN".to_owned()]);
    let permissions = root_permissions();
    let different_source = ROOT.replace("name: Root", "name: Different");
    let error = ReusableWorkflowExpander::new()
        .expand(ExpandReusableWorkflowRequest::new(
            run_id,
            root_invocation_id,
            ROOT_PATH,
            different_source.as_bytes(),
            &root_plan,
            &exact_catalog,
            &secrets,
            &permissions,
        ))
        .expect_err("source and plan mismatch");
    assert_eq!(error, ReusableWorkflowExpansionError::RootPlanMismatch);
}

#[test]
fn catalog_plan_provenance_is_bound_to_one_exact_repository_revision() {
    let exact_catalog = catalog([(CALLEE_PATH, CALLEE.to_owned())]);
    assert_eq!(exact_catalog.repository(), REPOSITORY);
    assert_eq!(exact_catalog.revision(), REVISION);
    let entry = exact_catalog.entries().next().expect("catalog entry");
    assert_eq!(entry.path(), CALLEE_PATH);
    let PlanSourceOrigin::Repository {
        repository,
        revision,
        path,
    } = entry.plan().source().origin()
    else {
        panic!("repository provenance");
    };
    assert_eq!(repository, REPOSITORY);
    assert_eq!(revision, REVISION);
    assert_eq!(path, CALLEE_PATH);
}
