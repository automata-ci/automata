//! Static credential-reference discovery for one logical job.

use std::collections::BTreeSet;

use automata_ci_core::{
    ExpressionInstruction, ExpressionLiteral, ExpressionProgram, LogicalJobTemplate,
    LogicalWorkflowPlan, Sha256Digest,
};
use automata_ci_store::{
    JobCredentialRequirements, JobEnvironmentRequirement, ProtectedEnvironmentValueError,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

// foundation-governance: derived-contract owner=workflow kind=digest-domain
const ENVIRONMENT_TEMPLATE_DIGEST_DOMAIN: &[u8] =
    b"automata.workflow.deployment-environment-template.v1\0";

/// Discovers exact static `secrets.<name>` and `vars.<name>` uses.
///
/// The complete serialized logical job is walked so new template-bearing fields
/// fail into the same analysis without a second hand-maintained field list.
///
/// # Errors
///
/// Rejects whole-context and dynamic-name access, malformed durable programs,
/// or invalid canonical names.
pub fn discover_job_credential_requirements(
    workflow: &LogicalWorkflowPlan,
    job: &LogicalJobTemplate,
) -> Result<JobCredentialRequirements, CredentialDiscoveryError> {
    let value = serde_json::to_value((workflow.environment(), job))
        .map_err(|_| CredentialDiscoveryError::InvalidLogicalPlan)?;
    let mut programs = Vec::new();
    collect_programs(&value, &mut programs)?;
    let mut secrets = BTreeSet::new();
    let mut variables = BTreeSet::new();
    for program in programs {
        scan_program(&program, &mut secrets, &mut variables)?;
    }
    let environment = match job.deployment() {
        None => JobEnvironmentRequirement::None,
        Some(deployment) => {
            JobEnvironmentRequirement::Environment(template_digest(deployment.name().value())?)
        }
    };
    JobCredentialRequirements::new(environment, secrets, variables)
        .map_err(CredentialDiscoveryError::InvalidRequirements)
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
}

impl Trace {
    fn value() -> Self {
        Self {
            kind: TraceKind::Value,
            secrets: BTreeSet::new(),
            variables: BTreeSet::new(),
        }
    }
}

fn scan_program(
    program: &ExpressionProgram,
    secrets: &mut BTreeSet<String>,
    variables: &mut BTreeSet<String>,
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
    if matches!(trace.kind, TraceKind::SensitiveRoot(_)) {
        return Err(CredentialDiscoveryError::DynamicReference);
    }
    secrets.extend(trace.secrets.iter().cloned());
    variables.extend(trace.variables.iter().cloned());
    Ok(())
}

fn index_sensitive(mut target: Trace, index: Trace) -> Result<Trace, CredentialDiscoveryError> {
    if matches!(index.kind, TraceKind::SensitiveRoot(_)) {
        return Err(CredentialDiscoveryError::DynamicReference);
    }
    target.secrets.extend(index.secrets);
    target.variables.extend(index.variables);
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
        if matches!(trace.kind, TraceKind::SensitiveRoot(_)) {
            return Err(CredentialDiscoveryError::DynamicReference);
        }
        output.secrets.extend(trace.secrets);
        output.variables.extend(trace.variables);
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
        scan_program(&expression, &mut secrets, &mut variables).expect("static references");
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
                scan_program(&expression, &mut BTreeSet::new(), &mut BTreeSet::new()),
                Err(CredentialDiscoveryError::DynamicReference)
            );
        }
    }
}
