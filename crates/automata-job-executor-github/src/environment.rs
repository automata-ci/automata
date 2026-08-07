use std::collections::BTreeMap;

use automata_core::{ExpressionProgram, ValueSource};
use automata_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionEnvironment,
};
use automata_expression_github::GithubExpressionEvaluator;
use automata_github_runtime::JobCommandState;

use crate::{
    ExecutorAdapterError, GithubContextSnapshot, PreparedAction, PreparedValue, SecretPort,
    error::{ExecutorAdapterErrorKind, PortErrorKind},
    output::SecretMasker,
};

pub(crate) struct EnvironmentBuilder<'a> {
    evaluator: &'a GithubExpressionEvaluator,
    secrets: &'a dyn SecretPort,
    defaults: &'a ExecutionEnvironment,
}

impl<'a> EnvironmentBuilder<'a> {
    pub(crate) const fn new(
        evaluator: &'a GithubExpressionEvaluator,
        secrets: &'a dyn SecretPort,
        defaults: &'a ExecutionEnvironment,
    ) -> Self {
        Self {
            evaluator,
            secrets,
            defaults,
        }
    }

    pub(crate) fn phase_environment(
        &self,
        context: &GithubContextSnapshot,
        commands: &JobCommandState,
        job: &BTreeMap<String, ValueSource>,
        step: &BTreeMap<String, ValueSource>,
        extra: impl IntoIterator<Item = (String, String)>,
        masker: &mut SecretMasker,
    ) -> Result<ExecutionEnvironment, ExecutorAdapterError> {
        let mut values = self
            .defaults
            .values()
            .iter()
            .map(|variable| {
                (
                    variable.name().as_str().to_owned(),
                    variable.value().expose().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for secret in context.secret_masks() {
            masker.register(secret.expose_secret())?;
        }
        for variable in context.environment() {
            if variable.is_secret() {
                masker.register(variable.expose_value())?;
            }
            values.insert(
                variable.name().to_owned(),
                variable.expose_value().to_owned(),
            );
        }
        self.overlay_sources(&mut values, job, context, masker)?;
        for variable in commands.environment() {
            values.insert(variable.name().to_owned(), variable.value().to_owned());
        }
        self.overlay_sources(&mut values, step, context, masker)?;
        for (name, value) in extra {
            values.insert(name, value);
        }
        prepend_paths(&mut values, commands);
        into_execution_environment(values)
    }

    pub(crate) fn action_inputs(
        &self,
        action: &PreparedAction,
        supplied: &BTreeMap<String, ValueSource>,
        context: &GithubContextSnapshot,
        masker: &mut SecretMasker,
    ) -> Result<Vec<(String, String)>, ExecutorAdapterError> {
        for secret in context.secret_masks() {
            masker.register(secret.expose_secret())?;
        }
        let mut inputs = BTreeMap::<String, (String, String)>::new();
        for input in action.inputs() {
            let Some(default) = input.default() else {
                continue;
            };
            let value = self.resolve_prepared(default, context)?;
            inputs.insert(
                input.name().to_ascii_lowercase(),
                (input.name().to_owned(), value),
            );
        }
        for (name, source) in supplied {
            let value = self.resolve_source(source, context, masker)?;
            inputs.insert(name.to_ascii_lowercase(), (name.clone(), value));
        }
        inputs
            .into_values()
            .map(|(name, value)| action_input_environment(&name).map(|name| (name, value)))
            .collect()
    }

    fn overlay_sources(
        &self,
        destination: &mut BTreeMap<String, String>,
        sources: &BTreeMap<String, ValueSource>,
        context: &GithubContextSnapshot,
        masker: &mut SecretMasker,
    ) -> Result<(), ExecutorAdapterError> {
        for (name, source) in sources {
            destination.insert(name.clone(), self.resolve_source(source, context, masker)?);
        }
        Ok(())
    }

    fn resolve_source(
        &self,
        source: &ValueSource,
        context: &GithubContextSnapshot,
        masker: &mut SecretMasker,
    ) -> Result<String, ExecutorAdapterError> {
        match source {
            ValueSource::Literal(value) => Ok(value.clone()),
            ValueSource::Expression(program) => self.evaluate_string(program, context),
            ValueSource::SecretReference(reference) => {
                let secret = self.secrets.resolve(reference).map_err(|error| {
                    let kind = match error.kind() {
                        PortErrorKind::PermissionDenied => {
                            ExecutorAdapterErrorKind::PermissionDenied
                        }
                        PortErrorKind::Unavailable => ExecutorAdapterErrorKind::Unavailable,
                        PortErrorKind::ResourceExhausted => {
                            ExecutorAdapterErrorKind::ResourceExhausted
                        }
                        PortErrorKind::NotFound
                        | PortErrorKind::InvalidData
                        | PortErrorKind::Unsupported
                        | PortErrorKind::Internal => ExecutorAdapterErrorKind::InvalidJob,
                    };
                    ExecutorAdapterError::new(kind)
                })?;
                masker.register(secret.expose_secret())?;
                Ok(secret.expose_secret().to_owned())
            }
        }
    }

    fn resolve_prepared(
        &self,
        value: &PreparedValue,
        context: &GithubContextSnapshot,
    ) -> Result<String, ExecutorAdapterError> {
        match value {
            PreparedValue::Literal(value) => Ok(value.clone()),
            PreparedValue::Expression(program) => self.evaluate_string(program, context),
        }
    }

    fn evaluate_string(
        &self,
        program: &ExpressionProgram,
        context: &GithubContextSnapshot,
    ) -> Result<String, ExecutorAdapterError> {
        self.evaluator
            .evaluate(program, context.expression())
            .map(|value| value.coerce_to_string())
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
    }
}

fn prepend_paths(values: &mut BTreeMap<String, String>, commands: &JobCommandState) {
    let paths = commands.prepend_path().collect::<Vec<_>>();
    if paths.is_empty() {
        return;
    }
    let mut path = paths.join(":");
    if let Some(existing) = values.get("PATH")
        && !existing.is_empty()
    {
        path.push(':');
        path.push_str(existing);
    }
    values.insert("PATH".to_owned(), path);
}

fn action_input_environment(name: &str) -> Result<String, ExecutorAdapterError> {
    let mut normalized = String::from("INPUT_");
    for character in name.chars() {
        if character == ' ' {
            normalized.push('_');
        } else {
            normalized.extend(character.to_uppercase());
        }
    }
    EnvironmentName::new(normalized.clone())
        .map(|_| normalized)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
}

fn into_execution_environment(
    values: BTreeMap<String, String>,
) -> Result<ExecutionEnvironment, ExecutorAdapterError> {
    let values = values
        .into_iter()
        .map(|(name, value)| {
            let name = EnvironmentName::new(name)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            let value = EnvironmentValue::new(value).map_err(|_| {
                ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted)
            })?;
            Ok(EnvironmentVariable::new(name, value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ExecutionEnvironment::new(values)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))
}
