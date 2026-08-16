//! Static credential-reference discovery for one logical job.

use std::collections::BTreeSet;

use automata_ci_core::{
    ExpressionInstruction, ExpressionLiteral, ExpressionProgram, LogicalJobKind,
    LogicalJobTemplate, LogicalWorkflowPlan, ReusableSecretForwarding, Sha256Digest,
};
use automata_ci_store::{
    JobCredentialRequirements, JobEnvironmentRequirement, ProtectedEnvironmentValueError,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const ENVIRONMENT_TEMPLATE_DIGEST_DOMAIN: &[u8] =
    b"automata.workflow.deployment-environment-template.v1\0";

/// Closed built-in credential supplied by provider-bound runtime authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltInCredentialRequirement {
    /// GitHub's job-bound token exposed as `github.token` and `secrets.GITHUB_TOKEN`.
    GithubToken,
}

/// Static external and provider-built-in requirements for one logical job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredJobCredentials {
    external: JobCredentialRequirements,
    built_in: Vec<BuiltInCredentialRequirement>,
}

impl DiscoveredJobCredentials {
    /// Returns secret, variable, and protected-environment requirements that
    /// must be resolved outside provider-built-in runtime authority.
    #[must_use]
    pub const fn external(&self) -> &JobCredentialRequirements {
        &self.external
    }

    /// Returns provider-built-in credentials in stable order.
    #[must_use]
    pub fn built_in(&self) -> &[BuiltInCredentialRequirement] {
        &self.built_in
    }
}

pub(crate) fn built_in_secret_requirement(name: &str) -> Option<BuiltInCredentialRequirement> {
    name.eq_ignore_ascii_case("GITHUB_TOKEN")
        .then_some(BuiltInCredentialRequirement::GithubToken)
}

/// Discovers exact static `secrets.<name>`, `vars.<name>`, and provider
/// built-in credential uses, including name-only caller sources in
/// reusable-workflow secret mappings.
///
/// The complete serialized logical job is walked so new template-bearing fields
/// fail into the same analysis without a second hand-maintained field list.
///
/// # Errors
///
/// Rejects whole-context and dynamic-name access, malformed durable programs,
/// or invalid canonical names.
pub fn discover_job_credentials(
    workflow: &LogicalWorkflowPlan,
    job: &LogicalJobTemplate,
) -> Result<DiscoveredJobCredentials, CredentialDiscoveryError> {
    let value = serde_json::to_value((workflow.environment(), job))
        .map_err(|_| CredentialDiscoveryError::InvalidLogicalPlan)?;
    let mut programs = Vec::new();
    collect_programs(&value, &mut programs)?;
    let mut secrets = BTreeSet::new();
    let mut variables = BTreeSet::new();
    let mut built_in = BTreeSet::new();
    for program in programs {
        scan_program(&program, &mut secrets, &mut variables, &mut built_in)?;
    }
    if let LogicalJobKind::ReusableWorkflow(invocation) = job.execution()
        && let ReusableSecretForwarding::Mapping(bindings) = invocation.secrets()
    {
        for binding in bindings {
            let source = binding.source().value().as_str();
            if let Some(requirement) = built_in_secret_requirement(source) {
                built_in.insert(requirement);
            } else {
                secrets.insert(source.to_owned());
            }
        }
    }
    classify_builtin_secrets(&mut secrets, &mut built_in);
    let environment = match job.deployment() {
        None => JobEnvironmentRequirement::None,
        Some(deployment) => {
            JobEnvironmentRequirement::Environment(template_digest(deployment.name().value())?)
        }
    };
    let external = JobCredentialRequirements::new(environment, secrets, variables)
        .map_err(CredentialDiscoveryError::InvalidRequirements)?;
    Ok(DiscoveredJobCredentials {
        external,
        built_in: built_in.into_iter().collect(),
    })
}

pub(crate) fn discover_external_job_credentials(
    workflow: &LogicalWorkflowPlan,
    job: &LogicalJobTemplate,
) -> Result<JobCredentialRequirements, CredentialDiscoveryError> {
    discover_job_credentials(workflow, job).map(|credentials| credentials.external)
}

fn classify_builtin_secrets(
    secrets: &mut BTreeSet<String>,
    built_in: &mut BTreeSet<BuiltInCredentialRequirement>,
) {
    for name in std::mem::take(secrets) {
        if let Some(requirement) = built_in_secret_requirement(&name) {
            built_in.insert(requirement);
        } else {
            secrets.insert(name);
        }
    }
}

fn template_digest(value: &impl Serialize) -> Result<Sha256Digest, CredentialDiscoveryError> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| CredentialDiscoveryError::InvalidLogicalPlan)?;
    let mut hasher = Sha256::new();
    hasher.update(ENVIRONMENT_TEMPLATE_DIGEST_DOMAIN);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn collect_programs(
    value: &Value,
    programs: &mut Vec<ExpressionProgram>,
) -> Result<(), CredentialDiscoveryError> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_programs(value, programs)?;
            }
        }
        Value::Object(values) => {
            let looks_like_program = ["schema_version", "dialect", "source", "instructions"]
                .iter()
                .all(|key| values.contains_key(*key));
            if looks_like_program {
                programs.push(
                    serde_json::from_value(value.clone())
                        .map_err(|_| CredentialDiscoveryError::InvalidLogicalPlan)?,
                );
            } else {
                for value in values.values() {
                    collect_programs(value, programs)?;
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[derive(Clone)]
enum TraceKind {
    SensitiveRoot(SensitiveContext),
    GithubRoot,
    LiteralString(String),
    Value,
}

#[derive(Clone, Copy)]
enum SensitiveContext {
    Secrets,
    Variables,
}

#[derive(Clone)]
struct Trace {
    kind: TraceKind,
    secrets: BTreeSet<String>,
    variables: BTreeSet<String>,
    built_in: BTreeSet<BuiltInCredentialRequirement>,
}

impl Trace {
    fn value() -> Self {
        Self {
            kind: TraceKind::Value,
            secrets: BTreeSet::new(),
            variables: BTreeSet::new(),
            built_in: BTreeSet::new(),
        }
    }
}

fn scan_program(
    program: &ExpressionProgram,
    secrets: &mut BTreeSet<String>,
    variables: &mut BTreeSet<String>,
    built_in: &mut BTreeSet<BuiltInCredentialRequirement>,
) -> Result<(), CredentialDiscoveryError> {
    let mut stack = Vec::with_capacity(program.instructions().len());
    for instruction in program.instructions() {
        let trace = match instruction {
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String { value },
            } => Trace {
                kind: TraceKind::LiteralString(value.clone()),
                ..Trace::value()
            },
            ExpressionInstruction::Literal { .. } | ExpressionInstruction::Wildcard => {
                Trace::value()
            }
            ExpressionInstruction::NamedValue { name } => Trace {
                kind: match name.as_str() {
                    "secrets" => TraceKind::SensitiveRoot(SensitiveContext::Secrets),
                    "vars" => TraceKind::SensitiveRoot(SensitiveContext::Variables),
                    "github" => TraceKind::GithubRoot,
                    _ => TraceKind::Value,
                },
                ..Trace::value()
            },
            ExpressionInstruction::Index => {
                let index = stack
                    .pop()
                    .ok_or(CredentialDiscoveryError::InvalidLogicalPlan)?;
                let target = stack
                    .pop()
                    .ok_or(CredentialDiscoveryError::InvalidLogicalPlan)?;
                index_sensitive(target, index)?
            }
            ExpressionInstruction::Not => combine(&mut stack, 1)?,
            ExpressionInstruction::Compare { .. } => combine(&mut stack, 2)?,
            ExpressionInstruction::Logical { operand_count, .. } => {
                combine(&mut stack, usize::from(*operand_count))?
            }
            ExpressionInstruction::Call { argument_count, .. } => {
                combine(&mut stack, usize::from(*argument_count))?
            }
        };
        stack.push(trace);
    }
    let [trace] = stack.as_slice() else {
        return Err(CredentialDiscoveryError::InvalidLogicalPlan);
    };
    if matches!(
        trace.kind,
        TraceKind::SensitiveRoot(_) | TraceKind::GithubRoot
    ) {
        return Err(CredentialDiscoveryError::DynamicReference);
    }
    secrets.extend(trace.secrets.iter().cloned());
    variables.extend(trace.variables.iter().cloned());
    built_in.extend(trace.built_in.iter().copied());
    Ok(())
}

fn index_sensitive(mut target: Trace, index: Trace) -> Result<Trace, CredentialDiscoveryError> {
    if matches!(index.kind, TraceKind::SensitiveRoot(_)) {
        return Err(CredentialDiscoveryError::DynamicReference);
    }
    target.secrets.extend(index.secrets);
    target.variables.extend(index.variables);
    target.built_in.extend(index.built_in);
    if let TraceKind::SensitiveRoot(context) = target.kind {
        let TraceKind::LiteralString(name) = index.kind else {
            return Err(CredentialDiscoveryError::DynamicReference);
        };
        match context {
            SensitiveContext::Secrets => {
                target.secrets.insert(name);
            }
            SensitiveContext::Variables => {
                target.variables.insert(name);
            }
        }
    } else if matches!(target.kind, TraceKind::GithubRoot) {
        let TraceKind::LiteralString(name) = index.kind else {
            return Err(CredentialDiscoveryError::DynamicReference);
        };
        if name.eq_ignore_ascii_case("token") {
            target
                .built_in
                .insert(BuiltInCredentialRequirement::GithubToken);
        }
    }
    target.kind = TraceKind::Value;
    Ok(target)
}

fn combine(stack: &mut Vec<Trace>, count: usize) -> Result<Trace, CredentialDiscoveryError> {
    if stack.len() < count {
        return Err(CredentialDiscoveryError::InvalidLogicalPlan);
    }
    let mut output = Trace::value();
    for _ in 0..count {
        let trace = stack
            .pop()
            .ok_or(CredentialDiscoveryError::InvalidLogicalPlan)?;
        if matches!(
            trace.kind,
            TraceKind::SensitiveRoot(_) | TraceKind::GithubRoot
        ) {
            return Err(CredentialDiscoveryError::DynamicReference);
        }
        output.secrets.extend(trace.secrets);
        output.variables.extend(trace.variables);
        output.built_in.extend(trace.built_in);
    }
    Ok(output)
}

/// Unsafe or malformed credential-reference discovery.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialDiscoveryError {
    /// Durable logical data could not be traversed as a current plan.
    #[error("logical job credential analysis failed")]
    InvalidLogicalPlan,
    /// A whole context or dynamic property could expose undeclared names.
    #[error("secret and variable references must use exact static names")]
    DynamicReference,
    /// A discovered name violated the closed context grammar.
    #[error("logical job credential requirements are invalid")]
    InvalidRequirements(ProtectedEnvironmentValueError),
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{ExpressionDialect, ExpressionInstruction, ExpressionLiteral};

    use super::*;

    fn program(instructions: Vec<ExpressionInstruction>) -> ExpressionProgram {
        ExpressionProgram::new(
            ExpressionDialect::new("github", 1).expect("dialect"),
            "test",
            instructions,
        )
        .expect("program")
    }

    fn string(value: &str) -> ExpressionInstruction {
        ExpressionInstruction::Literal {
            value: ExpressionLiteral::String {
                value: value.to_owned(),
            },
        }
    }

    #[test]
    fn exact_static_names_are_collected_and_canonicalized() {
        let expression = program(vec![
            ExpressionInstruction::NamedValue {
                name: "secrets".to_owned(),
            },
            string("token"),
            ExpressionInstruction::Index,
            ExpressionInstruction::NamedValue {
                name: "vars".to_owned(),
            },
            string("region"),
            ExpressionInstruction::Index,
            ExpressionInstruction::Call {
                name: "format".to_owned(),
                argument_count: 2,
            },
        ]);
        let mut secrets = BTreeSet::new();
        let mut variables = BTreeSet::new();
        let mut built_in = BTreeSet::new();
        scan_program(&expression, &mut secrets, &mut variables, &mut built_in)
            .expect("static references");
        let requirements =
            JobCredentialRequirements::new(JobEnvironmentRequirement::None, secrets, variables)
                .expect("requirements");
        assert_eq!(requirements.secret_names(), &["TOKEN"]);
        assert_eq!(requirements.variable_names(), &["REGION"]);
    }

    #[test]
    fn dynamic_and_whole_context_access_fail_closed() {
        for expression in [
            program(vec![ExpressionInstruction::NamedValue {
                name: "secrets".to_owned(),
            }]),
            program(vec![
                ExpressionInstruction::NamedValue {
                    name: "vars".to_owned(),
                },
                ExpressionInstruction::NamedValue {
                    name: "inputs".to_owned(),
                },
                string("name"),
                ExpressionInstruction::Index,
                ExpressionInstruction::Index,
            ]),
        ] {
            assert_eq!(
                scan_program(
                    &expression,
                    &mut BTreeSet::new(),
                    &mut BTreeSet::new(),
                    &mut BTreeSet::new(),
                ),
                Err(CredentialDiscoveryError::DynamicReference)
            );
        }
    }

    #[test]
    fn github_token_spellings_are_closed_builtins() {
        for (root, property) in [("github", "token"), ("secrets", "github_token")] {
            let expression = program(vec![
                ExpressionInstruction::NamedValue {
                    name: root.to_owned(),
                },
                string(property),
                ExpressionInstruction::Index,
            ]);
            let mut secrets = BTreeSet::new();
            let mut variables = BTreeSet::new();
            let mut built_in = BTreeSet::new();
            scan_program(&expression, &mut secrets, &mut variables, &mut built_in)
                .expect("static builtin");
            classify_builtin_secrets(&mut secrets, &mut built_in);
            assert!(secrets.is_empty());
            assert_eq!(
                built_in,
                BTreeSet::from([BuiltInCredentialRequirement::GithubToken])
            );
        }

        let mut duplicate_spellings = BTreeSet::from([
            "GITHUB_TOKEN".to_owned(),
            "github_token".to_owned(),
            "EXTERNAL".to_owned(),
        ]);
        let mut built_in = BTreeSet::new();
        classify_builtin_secrets(&mut duplicate_spellings, &mut built_in);
        assert_eq!(duplicate_spellings, BTreeSet::from(["EXTERNAL".to_owned()]));
        assert_eq!(
            built_in,
            BTreeSet::from([BuiltInCredentialRequirement::GithubToken])
        );
    }
}
