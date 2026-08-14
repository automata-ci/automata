use crate::model::CommandFilePlatform;

const GITHUB_DEFAULT_ENVIRONMENT_NAMES: &[&str] = &[
    "GITHUB_ACTION",
    "GITHUB_ACTION_PATH",
    "GITHUB_ACTION_REF",
    "GITHUB_ACTION_REPOSITORY",
    "GITHUB_ACTIONS",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_API_URL",
    "GITHUB_ARTIFACTS",
    "GITHUB_ARTIFACTS_LIST",
    "GITHUB_BASE_REF",
    "GITHUB_ENV",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_HEAD_REF",
    "GITHUB_JOB",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_PROTECTED",
    "GITHUB_REF_TYPE",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_OWNER_ID",
    "GITHUB_RETENTION_DAYS",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_SERVER_URL",
    "GITHUB_SHA",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_WORKSPACE",
];

const RUNNER_DEFAULT_ENVIRONMENT_NAMES: &[&str] = &[
    "RUNNER_ARCH",
    "RUNNER_DEBUG",
    "RUNNER_ENVIRONMENT",
    "RUNNER_NAME",
    "RUNNER_OS",
    "RUNNER_TEMP",
    "RUNNER_TOOL_CACHE",
];

/// Namespace containing runner-owned default environment variables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservedEnvironmentNamespace {
    /// Protected defaults whose canonical names begin with `GITHUB_`.
    Github,
    /// Protected defaults whose canonical names begin with `RUNNER_`.
    Runner,
}

/// Reason an attempted step environment mutation must be ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentMutationBlockReason {
    /// The name is a runner-owned default in the identified namespace.
    Reserved(ReservedEnvironmentNamespace),
    /// The name is `NODE_OPTIONS`, which GitHub blocks specifically for
    /// `GITHUB_ENV` and legacy `set-env` mutations.
    NodeOptions,
}

/// Classifies an environment mutation using the target platform's name
/// comparison semantics.
///
/// The finite catalog of runner-owned `GITHUB_*` and `RUNNER_*` defaults is
/// matched exactly on Unix and with ASCII case folding on Windows. Other names
/// in those namespaces, including `GITHUB_TOKEN` and `RUNNER_DIGEST`, remain
/// available to workflows. `NODE_OPTIONS` is matched case-insensitively on
/// every platform, preserving upstream runner behavior. `CI` is intentionally
/// mutable and therefore returns `None`.
#[must_use]
pub fn classify_environment_mutation(
    platform: CommandFilePlatform,
    name: &str,
) -> Option<EnvironmentMutationBlockReason> {
    if name.eq_ignore_ascii_case("NODE_OPTIONS") {
        return Some(EnvironmentMutationBlockReason::NodeOptions);
    }

    if catalog_contains(platform, name, GITHUB_DEFAULT_ENVIRONMENT_NAMES) {
        return Some(EnvironmentMutationBlockReason::Reserved(
            ReservedEnvironmentNamespace::Github,
        ));
    }
    if catalog_contains(platform, name, RUNNER_DEFAULT_ENVIRONMENT_NAMES) {
        return Some(EnvironmentMutationBlockReason::Reserved(
            ReservedEnvironmentNamespace::Runner,
        ));
    }
    None
}

fn catalog_contains(platform: CommandFilePlatform, name: &str, catalog: &[&str]) -> bool {
    catalog
        .iter()
        .any(|candidate| names_equal(platform, name, candidate))
}

fn names_equal(platform: CommandFilePlatform, left: &str, right: &str) -> bool {
    match platform {
        CommandFilePlatform::Unix => left == right,
        CommandFilePlatform::Windows => left.eq_ignore_ascii_case(right),
    }
}
