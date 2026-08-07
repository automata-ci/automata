use std::fmt::Debug;

use crate::model::{ActionState, SensitiveText, StepOutputState};
use crate::{
    CommandFilePlatform, CompletedStepCommands, JobCommandState, NameValueCommand,
    PhaseApplication, PhaseApplicationError, PhaseApplicationLimits, PhaseApplicationNotice,
    StepPhase, StepScope,
};

/// Object-safe pure port for committing command effects after step completion.
pub trait CompletedStepApplicator: Debug + Send + Sync {
    /// Atomically derives the state visible to later steps.
    ///
    /// The input state is never mutated, including when limits are exceeded.
    ///
    /// # Errors
    ///
    /// Returns an error when the derived job state exceeds a configured count
    /// or aggregate-byte ceiling.
    fn apply_completed_step(
        &self,
        current: &JobCommandState,
        scope: &StepScope,
        commands: &CompletedStepCommands,
    ) -> Result<PhaseApplication, PhaseApplicationError>;
}

/// Upstream-compatible completed-step effect applicator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubCompletedStepApplicator {
    limits: PhaseApplicationLimits,
}

impl GithubCompletedStepApplicator {
    #[must_use]
    pub const fn new(limits: PhaseApplicationLimits) -> Self {
        Self { limits }
    }

    #[must_use]
    pub const fn limits(self) -> PhaseApplicationLimits {
        self.limits
    }
}

impl Default for GithubCompletedStepApplicator {
    fn default() -> Self {
        Self::new(PhaseApplicationLimits::default())
    }
}

impl CompletedStepApplicator for GithubCompletedStepApplicator {
    fn apply_completed_step(
        &self,
        current: &JobCommandState,
        scope: &StepScope,
        commands: &CompletedStepCommands,
    ) -> Result<PhaseApplication, PhaseApplicationError> {
        let mut next = current.clone();
        let mut notices = Vec::new();

        let platform = next.platform;
        for command in commands.environment().commands() {
            if command.name().eq_ignore_ascii_case("NODE_OPTIONS") {
                notices.push(PhaseApplicationNotice::BlockedNodeOptions);
                continue;
            }
            replace_name_value(&mut next.environment, command.clone(), |left, right| {
                environment_names_equal(platform, left, right)
            });
        }

        for path in &commands.path().paths {
            next.prepend_path
                .retain(|existing| existing.as_str() != path.as_str());
            next.prepend_path.push(path.clone());
        }

        let mut outputs = if matches!(scope.phase(), StepPhase::ActionPost(_)) {
            next.outputs
                .iter()
                .find(|entry| entry.step_id == *scope.step_id())
                .map_or_else(Vec::new, |entry| entry.values.clone())
        } else {
            Vec::new()
        };
        for command in commands.output().commands() {
            replace_name_value(&mut outputs, command.clone(), str::eq_ignore_ascii_case);
        }
        next.outputs
            .retain(|entry| entry.step_id != *scope.step_id());
        if !outputs.is_empty() {
            next.outputs.push(StepOutputState {
                step_id: scope.step_id().clone(),
                values: outputs,
            });
        }

        match scope.phase() {
            StepPhase::Run => {
                if !commands.state().is_empty() {
                    notices.push(PhaseApplicationNotice::StateIgnoredForRunStep);
                }
            }
            StepPhase::ActionMain(invocation_id) | StepPhase::ActionPost(invocation_id) => {
                let state_index = next
                    .action_states
                    .iter()
                    .position(|entry| entry.invocation_id == *invocation_id);
                let state = state_index
                    .map_or_else(Vec::new, |index| next.action_states.remove(index).values);
                let mut state = state;
                for command in commands.state().commands() {
                    replace_name_value(&mut state, command.clone(), str::eq_ignore_ascii_case);
                }
                if !state.is_empty() {
                    next.action_states.push(ActionState {
                        invocation_id: invocation_id.clone(),
                        values: state,
                    });
                }
            }
        }

        validate_derived_state(&next, self.limits)?;
        Ok(PhaseApplication {
            next_state: next,
            summary: commands.summary().clone(),
            notices,
        })
    }
}

fn environment_names_equal(platform: CommandFilePlatform, left: &str, right: &str) -> bool {
    match platform {
        CommandFilePlatform::Unix => left == right,
        CommandFilePlatform::Windows => left.eq_ignore_ascii_case(right),
    }
}

fn replace_name_value(
    values: &mut Vec<NameValueCommand>,
    replacement: NameValueCommand,
    equals: impl Fn(&str, &str) -> bool,
) {
    if let Some(index) = values
        .iter()
        .position(|existing| equals(existing.name(), replacement.name()))
    {
        let original_name = values[index].name().to_owned();
        values[index] = NameValueCommand::from_parts(original_name, replacement.value().to_owned());
    } else {
        values.push(replacement);
    }
}

fn validate_derived_state(
    state: &JobCommandState,
    limits: PhaseApplicationLimits,
) -> Result<(), PhaseApplicationError> {
    if state.environment.len() > limits.maximum_environment_entries() {
        return Err(PhaseApplicationError::TooManyEnvironmentEntries {
            maximum: limits.maximum_environment_entries(),
        });
    }
    if state.prepend_path.len() > limits.maximum_path_entries() {
        return Err(PhaseApplicationError::TooManyPathEntries {
            maximum: limits.maximum_path_entries(),
        });
    }
    if state.outputs.len() > limits.maximum_steps() {
        return Err(PhaseApplicationError::TooManySteps {
            maximum: limits.maximum_steps(),
        });
    }
    if state.action_states.len() > limits.maximum_action_states() {
        return Err(PhaseApplicationError::TooManyActionStates {
            maximum: limits.maximum_action_states(),
        });
    }

    let aggregate = state_aggregate_bytes(state).unwrap_or(usize::MAX);
    if aggregate > limits.maximum_aggregate_bytes() {
        return Err(PhaseApplicationError::AggregateTooLarge {
            maximum: limits.maximum_aggregate_bytes(),
        });
    }
    Ok(())
}

fn state_aggregate_bytes(state: &JobCommandState) -> Option<usize> {
    let mut total = 0_usize;
    for value in &state.environment {
        total = add_name_value_bytes(total, value)?;
    }
    for path in &state.prepend_path {
        total = total.checked_add(sensitive_bytes(path))?;
    }
    for output in &state.outputs {
        total = total.checked_add(output.step_id.as_str().len())?;
        for value in &output.values {
            total = add_name_value_bytes(total, value)?;
        }
    }
    for action_state in &state.action_states {
        total = total.checked_add(action_state.invocation_id.as_str().len())?;
        for value in &action_state.values {
            total = add_name_value_bytes(total, value)?;
        }
    }
    Some(total)
}

fn add_name_value_bytes(total: usize, value: &NameValueCommand) -> Option<usize> {
    total
        .checked_add(value.name().len())?
        .checked_add(value.value().len())
}

fn sensitive_bytes(value: &SensitiveText) -> usize {
    value.len()
}
