use std::{collections::BTreeMap, fmt};

use automata_ci_auth::secret::SharedSensitiveString;
use automata_ci_core::{ExpressionProgram, ValueSource, ValueTemplate, ValueTemplateSegment};
use automata_ci_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionEnvironment,
};
use automata_ci_expression_github::{
    GithubEvaluationContext, GithubExpressionEvaluator, GithubExpressionFunctionProvider,
    GithubObject, GithubStatus, GithubValue,
};
use automata_ci_github_runtime::JobCommandState;

use crate::{
    ExecutorAdapterError, GithubContextSnapshot, PreparedActionDefinition, PreparedValue,
    PreparedValueSegment, SecretPort,
    error::{ExecutorAdapterErrorKind, PortErrorKind},
    output::SecretMasker,
};

/// Resolved action inputs retained in canonical case-insensitive order.
///
/// Values can contain secrets, so this type deliberately has no `Debug`
/// implementation.
pub(crate) struct ResolvedActionInputs {
    values: Vec<(String, ResolvedEnvironmentValue)>,
}

impl ResolvedActionInputs {
    pub(crate) fn values(&self) -> &[(String, ResolvedEnvironmentValue)] {
        &self.values
    }

    pub(crate) fn environment(
        &self,
    ) -> Result<Vec<(String, ResolvedEnvironmentValue)>, ExecutorAdapterError> {
        self.values
            .iter()
            .map(|(name, value)| action_input_environment(name).map(|name| (name, value.clone())))
            .collect()
    }
}

/// One resolved environment value with its provider-transport sensitivity.
///
/// Every secret-marked value retains shallow-cloneable, zeroizing custody until
/// the legacy execution-environment boundary. Plain values retain their owned
/// `String` allocation. This type is intentionally not `Debug`: a secret
/// reference or sensitive context variable must never be exposed through
/// derived executor state.
#[derive(Clone)]
pub(crate) enum ResolvedEnvironmentValue {
    Plain(String),
    SharedSecret(SharedSensitiveString),
}

impl ResolvedEnvironmentValue {
    pub(crate) fn plain(value: impl Into<String>) -> Self {
        Self::Plain(value.into())
    }

    pub(crate) fn secret(value: impl Into<String>) -> Self {
        Self::SharedSecret(SharedSensitiveString::from_string(value.into()))
    }

    fn from_shared_secret(value: SharedSensitiveString) -> Self {
        Self::SharedSecret(value)
    }

    pub(crate) fn from_parts(value: impl Into<String>, secret: bool) -> Self {
        let value = value.into();
        if secret {
            Self::secret(value)
        } else {
            Self::plain(value)
        }
    }

    pub(crate) fn expose(&self) -> &str {
        match self {
            Self::Plain(value) => value,
            Self::SharedSecret(value) => value.expose_secret(),
        }
    }

    /// Crosses the remaining owned-string boundary.
    ///
    /// Plain values move their existing allocation. Every secret variant
    /// deliberately makes its first legacy environment-value plaintext copy
    /// here when [`into_execution_environment`] constructs the still-
    /// `String`-backed [`ExecutionEnvironment`]. Secret construction and shared
    /// handle cloning do not copy plaintext; masking and execution transport
    /// retain their existing ordinary plaintext allocations.
    pub(crate) fn into_value(self) -> String {
        match self {
            Self::Plain(value) => value,
            Self::SharedSecret(value) => value.expose_secret().to_owned(),
        }
    }

    pub(crate) const fn is_secret(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            Self::SharedSecret(_) => true,
        }
    }
}

pub(crate) struct EnvironmentBuilder<'a> {
    evaluator: &'a GithubExpressionEvaluator,
    secrets: &'a dyn SecretPort,
    defaults: &'a ExecutionEnvironment,
}

struct ResolvedPhaseValues {
    process: BTreeMap<String, ResolvedEnvironmentValue>,
    expression: BTreeMap<String, ResolvedEnvironmentValue>,
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
        extra: impl IntoIterator<Item = (String, ResolvedEnvironmentValue)>,
        masker: &mut SecretMasker,
    ) -> Result<ExecutionEnvironment, ExecutorAdapterError> {
        let values = self.phase_values(context, commands, job, step, extra, masker)?;
        into_execution_environment(values.process)
    }

    pub(crate) fn phase_expression_values(
        &self,
        context: &GithubContextSnapshot,
        commands: &JobCommandState,
        job: &BTreeMap<String, ValueSource>,
        step: &BTreeMap<String, ValueSource>,
        masker: &mut SecretMasker,
    ) -> Result<Vec<(String, ResolvedEnvironmentValue)>, ExecutorAdapterError> {
        self.phase_values(context, commands, job, step, std::iter::empty(), masker)
            .map(|values| values.expression)
            .map(BTreeMap::into_iter)
            .map(Iterator::collect)
    }

    fn phase_values(
        &self,
        context: &GithubContextSnapshot,
        commands: &JobCommandState,
        job: &BTreeMap<String, ValueSource>,
        step: &BTreeMap<String, ValueSource>,
        extra: impl IntoIterator<Item = (String, ResolvedEnvironmentValue)>,
        masker: &mut SecretMasker,
    ) -> Result<ResolvedPhaseValues, ExecutorAdapterError> {
        let mut values = BTreeMap::new();
        for variable in self.defaults.values() {
            if variable.is_secret() {
                masker.register(variable.value().expose())?;
            }
            values.insert(
                variable.name().as_str().to_owned(),
                resolved_default_value(variable),
            );
        }
        for secret in context.secret_masks() {
            masker.register(secret.expose_secret())?;
        }
        for variable in context.environment() {
            if let Some(secret) = variable.shared_secret_value() {
                masker.register(secret.expose_secret())?;
            }
            values.insert(variable.name().to_owned(), resolved_context_value(variable));
        }
        let mut expression = expression_environment(context.expression())?;
        for (name, source) in job {
            let value = self.resolve_source_value(source, context.expression(), masker)?;
            values.insert(name.clone(), value.clone());
            insert_expression_environment(&mut expression, name.clone(), value);
        }
        for variable in commands.environment() {
            let name = variable.name().to_owned();
            let value = ResolvedEnvironmentValue::plain(variable.value());
            values.insert(name.clone(), value.clone());
            insert_expression_environment(&mut expression, name, value);
        }
        let step_context = EnvironmentEvaluationContext::new(context.expression(), &expression)?;
        for (name, source) in step {
            let value = self.resolve_source_value(source, &step_context, masker)?;
            values.insert(name.clone(), value.clone());
            insert_expression_environment(&mut expression, name.clone(), value);
        }
        for (name, value) in extra {
            values.insert(name, value);
        }
        prepend_paths(&mut values, commands);
        prepend_paths(&mut expression, commands);
        Ok(ResolvedPhaseValues {
            process: values,
            expression,
        })
    }

    pub(crate) fn resolve_action_inputs(
        &self,
        definition: &PreparedActionDefinition,
        supplied: &BTreeMap<String, ResolvedEnvironmentValue>,
        context: &dyn GithubEvaluationContext,
    ) -> Result<ResolvedActionInputs, ExecutorAdapterError> {
        let mut inputs = BTreeMap::<String, (String, ResolvedEnvironmentValue)>::new();
        for input in definition.inputs() {
            let Some(default) = input.default() else {
                continue;
            };
            let value = self.resolve_prepared_value(default, context)?;
            inputs.insert(
                input.name().to_ascii_lowercase(),
                (input.name().to_owned(), value),
            );
        }
        let mut supplied_names = std::collections::BTreeSet::new();
        for (name, value) in supplied {
            let normalized = name.to_ascii_lowercase();
            if !supplied_names.insert(normalized.clone()) {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::InvalidJob,
                ));
            }
            inputs.insert(normalized, (name.clone(), value.clone()));
        }
        Ok(ResolvedActionInputs {
            values: inputs.into_values().collect(),
        })
    }

    /// Resolves only the environment declared for a job/service container.
    /// Runner defaults, workflow environment, command state, and standard
    /// GitHub variables are intentionally not injected into sibling services.
    pub(crate) fn container_environment(
        &self,
        sources: &BTreeMap<String, ValueSource>,
        context: &GithubContextSnapshot,
        masker: &mut SecretMasker,
    ) -> Result<ExecutionEnvironment, ExecutorAdapterError> {
        for secret in context.secret_masks() {
            masker.register(secret.expose_secret())?;
        }
        let mut values = BTreeMap::new();
        self.overlay_sources(&mut values, sources, context.expression(), masker)?;
        into_execution_environment(values)
    }

    fn overlay_sources(
        &self,
        destination: &mut BTreeMap<String, ResolvedEnvironmentValue>,
        sources: &BTreeMap<String, ValueSource>,
        context: &dyn GithubEvaluationContext,
        masker: &mut SecretMasker,
    ) -> Result<(), ExecutorAdapterError> {
        for (name, source) in sources {
            destination.insert(
                name.clone(),
                self.resolve_source_value(source, context, masker)?,
            );
        }
        Ok(())
    }

    pub(crate) fn resolve_source_value(
        &self,
        source: &ValueSource,
        context: &dyn GithubEvaluationContext,
        masker: &mut SecretMasker,
    ) -> Result<ResolvedEnvironmentValue, ExecutorAdapterError> {
        match source {
            ValueSource::Literal(value) => Ok(ResolvedEnvironmentValue::plain(value)),
            ValueSource::Expression(program) => self
                .evaluate_string(program, context)
                .map(ResolvedEnvironmentValue::secret),
            ValueSource::Template(template) => {
                let secret = template
                    .segments()
                    .iter()
                    .any(|segment| matches!(segment, ValueTemplateSegment::Expression { .. }));
                let rendered = self.resolve_value_template(template, context)?;
                Ok(ResolvedEnvironmentValue::from_parts(rendered, secret))
            }
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
                Ok(ResolvedEnvironmentValue::from_shared_secret(secret))
            }
        }
    }

    /// Renders a validated late-bound value template against one immutable
    /// phase context without retaining the evaluated value.
    pub(crate) fn resolve_value_template(
        &self,
        template: &ValueTemplate,
        context: &dyn GithubEvaluationContext,
    ) -> Result<String, ExecutorAdapterError> {
        let mut rendered = String::new();
        for segment in template.segments() {
            let value = match segment {
                ValueTemplateSegment::Literal { value } => value.clone(),
                ValueTemplateSegment::Expression { program } => {
                    self.evaluate_string(program, context)?
                }
            };
            if rendered
                .len()
                .checked_add(value.len())
                .is_none_or(|bytes| bytes > automata_ci_core::MAX_VALUE_TEMPLATE_TEXT_BYTES)
            {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::ResourceExhausted,
                ));
            }
            rendered.push_str(&value);
        }
        Ok(rendered)
    }

    pub(crate) fn resolve_prepared(
        &self,
        value: &PreparedValue,
        context: &dyn GithubEvaluationContext,
    ) -> Result<String, ExecutorAdapterError> {
        self.resolve_prepared_value(value, context)
            .map(ResolvedEnvironmentValue::into_value)
    }

    pub(crate) fn resolve_prepared_value(
        &self,
        value: &PreparedValue,
        context: &dyn GithubEvaluationContext,
    ) -> Result<ResolvedEnvironmentValue, ExecutorAdapterError> {
        match value {
            PreparedValue::Literal(value) => Ok(ResolvedEnvironmentValue::plain(value)),
            PreparedValue::Expression(program) => self
                .evaluate_string(program, context)
                .map(ResolvedEnvironmentValue::secret),
            PreparedValue::Template(segments) => {
                let mut value = String::new();
                let mut secret = false;
                for segment in segments {
                    let segment = match segment {
                        PreparedValueSegment::Literal(segment) => segment.clone(),
                        PreparedValueSegment::Expression(program) => {
                            secret = true;
                            self.evaluate_string(program, context)?
                        }
                    };
                    if value
                        .len()
                        .checked_add(segment.len())
                        .is_none_or(|bytes| bytes > automata_ci_core::MAX_VALUE_TEMPLATE_TEXT_BYTES)
                    {
                        return Err(ExecutorAdapterError::new(
                            ExecutorAdapterErrorKind::ResourceExhausted,
                        ));
                    }
                    value.push_str(&segment);
                }
                Ok(ResolvedEnvironmentValue::from_parts(value, secret))
            }
        }
    }

    fn evaluate_string(
        &self,
        program: &ExpressionProgram,
        context: &dyn GithubEvaluationContext,
    ) -> Result<String, ExecutorAdapterError> {
        self.evaluator
            .evaluate(program, context)
            .map(|value| value.coerce_to_string())
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
    }
}

struct EnvironmentEvaluationContext<'a> {
    base: &'a dyn GithubEvaluationContext,
    environment: GithubValue,
}

impl<'a> EnvironmentEvaluationContext<'a> {
    fn new(
        base: &'a dyn GithubEvaluationContext,
        values: &BTreeMap<String, ResolvedEnvironmentValue>,
    ) -> Result<Self, ExecutorAdapterError> {
        let environment = GithubObject::new(
            values
                .iter()
                .map(|(name, value)| (name.clone(), GithubValue::string(value.expose())))
                .collect(),
        )
        .map(GithubValue::object)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))?;
        Ok(Self { base, environment })
    }
}

impl fmt::Debug for EnvironmentEvaluationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentEvaluationContext")
            .field("environment", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl GithubEvaluationContext for EnvironmentEvaluationContext<'_> {
    fn named_value(&self, name: &str) -> Option<GithubValue> {
        if name.eq_ignore_ascii_case("env") {
            Some(self.environment.clone())
        } else {
            self.base.named_value(name)
        }
    }

    fn status(&self) -> GithubStatus {
        self.base.status()
    }

    fn functions(&self) -> &dyn GithubExpressionFunctionProvider {
        self.base.functions()
    }
}

fn expression_environment(
    context: &dyn GithubEvaluationContext,
) -> Result<BTreeMap<String, ResolvedEnvironmentValue>, ExecutorAdapterError> {
    let Some(value) = context.named_value("env") else {
        return Ok(BTreeMap::new());
    };
    let GithubValue::Object(value) = value else {
        return Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::InvalidJob,
        ));
    };
    let mut environment = BTreeMap::new();
    for (name, value) in value.entries() {
        insert_expression_environment(
            &mut environment,
            name.clone(),
            ResolvedEnvironmentValue::plain(value.coerce_to_string()),
        );
    }
    Ok(environment)
}

fn insert_expression_environment(
    values: &mut BTreeMap<String, ResolvedEnvironmentValue>,
    name: String,
    value: ResolvedEnvironmentValue,
) {
    if let Some(existing) = values
        .keys()
        .find(|existing| existing.eq_ignore_ascii_case(&name))
        .cloned()
    {
        values.remove(&existing);
    }
    values.insert(name, value);
}

fn resolved_default_value(variable: &EnvironmentVariable) -> ResolvedEnvironmentValue {
    ResolvedEnvironmentValue::from_parts(variable.value().expose(), variable.is_secret())
}

fn resolved_context_value(
    variable: &crate::ContextEnvironmentVariable,
) -> ResolvedEnvironmentValue {
    match variable.shared_secret_value() {
        Some(secret) => ResolvedEnvironmentValue::from_shared_secret(secret.clone()),
        None => ResolvedEnvironmentValue::plain(variable.expose_value()),
    }
}

fn prepend_paths(
    values: &mut BTreeMap<String, ResolvedEnvironmentValue>,
    commands: &JobCommandState,
) {
    let paths = commands.prepend_path().collect::<Vec<_>>();
    if paths.is_empty() {
        return;
    }
    let mut path = paths.join(":");
    let secret = values
        .get("PATH")
        .is_some_and(ResolvedEnvironmentValue::is_secret);
    if let Some(existing) = values.get("PATH")
        && !existing.expose().is_empty()
    {
        path.push(':');
        path.push_str(existing.expose());
    }
    values.insert(
        "PATH".to_owned(),
        ResolvedEnvironmentValue::from_parts(path, secret),
    );
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
    values: BTreeMap<String, ResolvedEnvironmentValue>,
) -> Result<ExecutionEnvironment, ExecutorAdapterError> {
    let values = values
        .into_iter()
        .map(|(name, resolved)| {
            let name = EnvironmentName::new(name)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            let secret = resolved.is_secret();
            let value = EnvironmentValue::new(resolved.into_value()).map_err(|_| {
                ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted)
            })?;
            Ok(if secret {
                EnvironmentVariable::secret(name, value)
            } else {
                EnvironmentVariable::new(name, value)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    ExecutionEnvironment::new(values)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use automata_ci_auth::secret::{SecretString, SharedSensitiveString};
    use automata_ci_core::{
        ExpressionDialect, ExpressionInstruction, ExpressionLiteral, ValueTemplate,
    };
    use automata_ci_execution::{EnvironmentName, EnvironmentValue, EnvironmentVariable};
    use automata_ci_expression_github::{GithubObject, GithubStatus, GithubValue, MapContext};
    use automata_ci_github_runtime::{CommandFilePlatform, JobCommandState};
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{ContextEnvironmentVariable, PortError};

    assert_not_impl_any!(ResolvedEnvironmentValue: std::fmt::Debug, std::fmt::Display);

    #[derive(Debug)]
    struct TestSecrets;

    impl SecretPort for TestSecrets {
        fn resolve(&self, reference: &str) -> Result<SharedSensitiveString, PortError> {
            assert_eq!(reference, "runner-secret");
            SecretString::new("resolved-secret")
                .map(|secret| SharedSensitiveString::from_secret(Arc::new(secret)))
                .map_err(|_| PortError::new(crate::error::PortErrorKind::Internal))
        }
    }

    #[derive(Debug)]
    struct RetainedTestSecrets {
        secret: Arc<SecretString>,
    }

    impl SecretPort for RetainedTestSecrets {
        fn resolve(&self, reference: &str) -> Result<SharedSensitiveString, PortError> {
            assert_eq!(reference, "retained-secret");
            Ok(SharedSensitiveString::from_secret(Arc::clone(&self.secret)))
        }
    }

    fn object(entries: impl IntoIterator<Item = (&'static str, GithubValue)>) -> GithubValue {
        GithubValue::object(
            GithubObject::new(
                entries
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value))
                    .collect(),
            )
            .expect("expression object"),
        )
    }

    fn step_output_program(output: &str) -> ExpressionProgram {
        let instructions = vec![
            ExpressionInstruction::NamedValue {
                name: "steps".to_owned(),
            },
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String {
                    value: "producer".to_owned(),
                },
            },
            ExpressionInstruction::Index,
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String {
                    value: "outputs".to_owned(),
                },
            },
            ExpressionInstruction::Index,
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String {
                    value: output.to_owned(),
                },
            },
            ExpressionInstruction::Index,
        ];
        ExpressionProgram::new(
            ExpressionDialect::new("github-actions", 1).expect("dialect"),
            format!("steps.producer.outputs.{output}"),
            instructions,
        )
        .expect("step output expression")
    }

    fn step_output_context(value: &str) -> MapContext {
        MapContext::without_extensions(
            BTreeMap::from([(
                "steps".to_owned(),
                object([(
                    "producer",
                    object([("outputs", object([("value", GithubValue::string(value))]))]),
                )]),
            )]),
            GithubStatus::Success,
        )
        .expect("expression context")
    }

    #[test]
    fn resolved_secret_sources_retain_ephemeral_transport_sensitivity() {
        let defaults = ExecutionEnvironment::new(vec![EnvironmentVariable::secret(
            EnvironmentName::new("DEFAULT_SECRET").expect("environment name"),
            EnvironmentValue::new("default-secret").expect("environment value"),
        )])
        .expect("default environment");
        let expression = MapContext::without_extensions(BTreeMap::new(), GithubStatus::Success)
            .expect("expression context");
        let context = GithubContextSnapshot::new(
            Arc::new(expression),
            vec![ContextEnvironmentVariable::secret(
                "CONTEXT_SECRET",
                SecretString::new("context-secret").expect("context secret"),
            )],
        );
        let mut masker = SecretMasker::new();
        let environment = EnvironmentBuilder::new(
            &GithubExpressionEvaluator::default(),
            &TestSecrets,
            &defaults,
        )
        .phase_environment(
            &context,
            &JobCommandState::new(CommandFilePlatform::Unix),
            &BTreeMap::from([(
                "RESOLVED_SECRET".to_owned(),
                ValueSource::SecretReference("runner-secret".to_owned()),
            )]),
            &BTreeMap::new(),
            std::iter::empty(),
            &mut masker,
        )
        .expect("phase environment");

        for name in ["DEFAULT_SECRET", "CONTEXT_SECRET", "RESOLVED_SECRET"] {
            assert!(
                environment
                    .values()
                    .iter()
                    .find(|variable| variable.name().as_str() == name)
                    .expect("expected secret environment variable")
                    .is_secret(),
                "{name} lost secret sensitivity"
            );
        }
    }

    #[test]
    fn secret_reference_stays_shared_until_execution_environment_conversion() {
        let secret = Arc::new(SecretString::new("shared-secret-value").expect("secret"));
        let original_plaintext = secret.expose_secret().as_ptr();
        let secrets = RetainedTestSecrets {
            secret: Arc::clone(&secret),
        };
        let defaults = ExecutionEnvironment::empty();
        let evaluator = GithubExpressionEvaluator::default();
        let builder = EnvironmentBuilder::new(&evaluator, &secrets, &defaults);
        let context = MapContext::without_extensions(BTreeMap::new(), GithubStatus::Success)
            .expect("expression context");
        let mut masker = SecretMasker::new();

        assert_eq!(Arc::strong_count(&secret), 2);
        let resolved = builder
            .resolve_source_value(
                &ValueSource::SecretReference("retained-secret".to_owned()),
                &context,
                &mut masker,
            )
            .expect("resolve shared secret");

        assert!(matches!(
            &resolved,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert!(resolved.is_secret());
        assert_eq!(resolved.expose(), "shared-secret-value");
        assert_eq!(resolved.expose().as_ptr(), original_plaintext);
        assert_eq!(Arc::strong_count(&secret), 3);

        let inputs = ResolvedActionInputs {
            values: vec![("token".to_owned(), resolved.clone())],
        };
        assert_eq!(Arc::strong_count(&secret), 4);
        let input_environment = inputs.environment().expect("input environment");
        assert_eq!(Arc::strong_count(&secret), 5);
        assert!(matches!(
            &input_environment[0].1,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert_eq!(input_environment[0].1.expose().as_ptr(), original_plaintext);

        // Registered post state uses these same `Vec` and value clone paths.
        let retained_post_environment = input_environment.clone();
        assert_eq!(Arc::strong_count(&secret), 6);
        assert!(matches!(
            &retained_post_environment[0].1,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert_eq!(
            retained_post_environment[0].1.expose().as_ptr(),
            original_plaintext
        );

        drop(retained_post_environment);
        drop(input_environment);
        drop(inputs);
        assert_eq!(Arc::strong_count(&secret), 3);

        let environment =
            into_execution_environment(BTreeMap::from([("TOKEN".to_owned(), resolved)]))
                .expect("execution environment");
        assert_eq!(Arc::strong_count(&secret), 2);
        let variable = &environment.values()[0];
        assert!(variable.is_secret());
        assert_eq!(variable.value().expose(), "shared-secret-value");
        assert_ne!(variable.value().expose().as_ptr(), original_plaintext);
    }

    #[test]
    fn context_secret_and_mask_stay_shared_until_legacy_boundaries() {
        let secret = Arc::new(SecretString::new("context-shared-secret").expect("secret"));
        let original_plaintext = secret.expose_secret().as_ptr();
        let expression = MapContext::without_extensions(BTreeMap::new(), GithubStatus::Success)
            .expect("expression context");
        let context = GithubContextSnapshot::new(
            Arc::new(expression),
            vec![ContextEnvironmentVariable::shared_secret(
                "CONTEXT_SECRET",
                Arc::clone(&secret),
            )],
        )
        .with_secret_masks(vec![Arc::clone(&secret)]);

        assert_eq!(Arc::strong_count(&secret), 3);
        let context_variable = &context.environment()[0];
        let context_secret = context_variable
            .shared_secret_value()
            .expect("shared context secret");
        assert_eq!(context_secret.expose_secret().as_ptr(), original_plaintext);
        assert_eq!(
            context.secret_masks()[0].expose_secret().as_ptr(),
            original_plaintext
        );
        assert_eq!(Arc::strong_count(&secret), 3);

        let resolved = resolved_context_value(context_variable);
        assert_eq!(resolved.expose().as_ptr(), original_plaintext);
        assert_eq!(Arc::strong_count(&secret), 4);

        let environment =
            into_execution_environment(BTreeMap::from([("CONTEXT_SECRET".to_owned(), resolved)]))
                .expect("execution environment");
        assert_eq!(Arc::strong_count(&secret), 3);
        let value = environment.values()[0].value().expose();
        assert_eq!(value, "context-shared-secret");
        assert_ne!(value.as_ptr(), original_plaintext);
    }

    #[test]
    fn owned_secret_values_move_and_clone_without_plaintext_copy() {
        let secret = String::from("derived-secret-value");
        let secret_plaintext = secret.as_ptr();
        let resolved = ResolvedEnvironmentValue::secret(secret);

        assert!(matches!(
            &resolved,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert!(resolved.is_secret());
        assert_eq!(resolved.expose().as_ptr(), secret_plaintext);

        let clone = resolved.clone();
        assert_eq!(clone.expose().as_ptr(), secret_plaintext);
        let legacy = resolved.into_value();
        assert_eq!(legacy, "derived-secret-value");
        assert_ne!(legacy.as_ptr(), secret_plaintext);
        assert_eq!(clone.expose().as_ptr(), secret_plaintext);

        let plain = String::from("plain-value");
        let plain_text = plain.as_ptr();
        let resolved = ResolvedEnvironmentValue::plain(plain);
        assert!(matches!(&resolved, ResolvedEnvironmentValue::Plain(_)));
        assert!(!resolved.is_secret());
        assert_eq!(resolved.expose().as_ptr(), plain_text);
        let plain = resolved.into_value();
        assert_eq!(plain.as_ptr(), plain_text);
    }

    #[test]
    fn secret_defaults_retain_shared_custody() {
        let default = EnvironmentVariable::secret(
            EnvironmentName::new("DEFAULT_SECRET").expect("environment name"),
            EnvironmentValue::new("default-secret").expect("environment value"),
        );
        let resolved_default = resolved_default_value(&default);
        assert!(matches!(
            &resolved_default,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert!(resolved_default.is_secret());
        let default_clone = resolved_default.clone();
        assert_eq!(
            resolved_default.expose().as_ptr(),
            default_clone.expose().as_ptr()
        );
    }

    #[test]
    fn derived_expressions_and_templates_retain_shared_custody() {
        let context = step_output_context("evaluated-secret");
        let defaults = ExecutionEnvironment::empty();
        let evaluator = GithubExpressionEvaluator::default();
        let builder = EnvironmentBuilder::new(&evaluator, &TestSecrets, &defaults);
        let program = step_output_program("value");
        let mut masker = SecretMasker::new();

        let expression = builder
            .resolve_source_value(
                &ValueSource::Expression(program.clone()),
                &context,
                &mut masker,
            )
            .expect("expression value");
        assert!(matches!(
            &expression,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert!(expression.is_secret());

        let empty_expression = builder
            .resolve_source_value(
                &ValueSource::Expression(step_output_program("missing")),
                &context,
                &mut masker,
            )
            .expect("empty expression value");
        assert!(matches!(
            &empty_expression,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert!(empty_expression.is_secret());
        assert!(empty_expression.expose().is_empty());

        let template = ValueTemplate::new(vec![
            ValueTemplateSegment::literal("prefix-"),
            ValueTemplateSegment::expression(program.clone()),
        ])
        .expect("value template");
        let template = builder
            .resolve_source_value(&ValueSource::Template(template), &context, &mut masker)
            .expect("template value");
        assert!(matches!(
            &template,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert!(template.is_secret());
        assert_eq!(template.expose(), "prefix-evaluated-secret");
        let template_clone = template.clone();
        assert_eq!(template.expose().as_ptr(), template_clone.expose().as_ptr());

        let literal_template = builder
            .resolve_source_value(
                &ValueSource::Template(
                    ValueTemplate::literal("literal-template").expect("literal template"),
                ),
                &context,
                &mut masker,
            )
            .expect("literal template value");
        assert!(matches!(
            &literal_template,
            ResolvedEnvironmentValue::Plain(_)
        ));
        assert!(!literal_template.is_secret());

        let literal = builder
            .resolve_source_value(
                &ValueSource::Literal("literal".to_owned()),
                &context,
                &mut masker,
            )
            .expect("literal value");
        assert!(matches!(&literal, ResolvedEnvironmentValue::Plain(_)));
        assert!(!literal.is_secret());
    }

    #[test]
    fn prepared_templates_retain_shared_custody() {
        let context = step_output_context("evaluated-secret");
        let defaults = ExecutionEnvironment::empty();
        let evaluator = GithubExpressionEvaluator::default();
        let builder = EnvironmentBuilder::new(&evaluator, &TestSecrets, &defaults);
        let prepared = builder
            .resolve_prepared_value(
                &PreparedValue::Template(vec![
                    PreparedValueSegment::Literal("prepared-".to_owned()),
                    PreparedValueSegment::Expression(step_output_program("value")),
                ]),
                &context,
            )
            .expect("prepared template");
        assert!(matches!(
            &prepared,
            ResolvedEnvironmentValue::SharedSecret(_)
        ));
        assert!(prepared.is_secret());
        assert_eq!(prepared.expose(), "prepared-evaluated-secret");
    }

    #[test]
    fn final_value_templates_use_the_supplied_steps_snapshot_and_missing_is_empty() {
        let context = MapContext::without_extensions(
            BTreeMap::from([(
                "steps".to_owned(),
                object([(
                    "producer",
                    object([(
                        "outputs",
                        object([("value", GithubValue::string("after-post"))]),
                    )]),
                )]),
            )]),
            GithubStatus::Success,
        )
        .expect("expression context");
        let defaults = ExecutionEnvironment::new(Vec::new()).expect("default environment");
        let evaluator = GithubExpressionEvaluator::default();
        let builder = EnvironmentBuilder::new(&evaluator, &TestSecrets, &defaults);

        let present = ValueTemplate::expression(step_output_program("value")).expect("template");
        assert_eq!(
            builder
                .resolve_value_template(&present, &context)
                .expect("render present output"),
            "after-post"
        );

        let missing = ValueTemplate::expression(step_output_program("missing")).expect("template");
        assert_eq!(
            builder
                .resolve_value_template(&missing, &context)
                .expect("render missing output"),
            ""
        );
    }
}
