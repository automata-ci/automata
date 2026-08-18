use thiserror::Error;

const HARD_MAX_FILE_BYTES: usize = 64 * 1_024 * 1_024;
const HARD_MAX_SUMMARY_BYTES: usize = 1_024 * 1_024;
const HARD_MAX_LINE_BYTES: usize = 16 * 1_024 * 1_024;
const HARD_MAX_RECORDS: usize = 1_000_000;
const HARD_MAX_NAME_BYTES: usize = 64 * 1_024;
const HARD_MAX_VALUE_BYTES: usize = 64 * 1_024 * 1_024;
const HARD_MAX_STREAM_BYTES: usize = 512 * 1_024 * 1_024;
const HARD_MAX_STREAM_LINES: usize = 10_000_000;
const HARD_MAX_PROPERTIES: usize = 16_384;
const HARD_MAX_MASKS: usize = 1_000_000;
const HARD_MAX_STATE_ENTRIES: usize = 1_000_000;
const HARD_MAX_STATE_BYTES: usize = 512 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActionsRuntimeHardLimitRejection {
    FileBytes,
    SummaryBytes,
    LineBytes,
    Records,
    NameBytes,
    ValueBytes,
    StreamBytes,
    StreamLines,
    Properties,
    Masks,
    StateEntries,
    StateBytes,
}

const fn hard_max_file_bytes_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_FILE_BYTES {
        return Some(ActionsRuntimeHardLimitRejection::FileBytes);
    }
    None
}

const fn hard_max_summary_bytes_rejection(
    value: usize,
) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_SUMMARY_BYTES {
        return Some(ActionsRuntimeHardLimitRejection::SummaryBytes);
    }
    None
}

const fn hard_max_line_bytes_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_LINE_BYTES {
        return Some(ActionsRuntimeHardLimitRejection::LineBytes);
    }
    None
}

const fn hard_max_records_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_RECORDS {
        return Some(ActionsRuntimeHardLimitRejection::Records);
    }
    None
}

const fn hard_max_name_bytes_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_NAME_BYTES {
        return Some(ActionsRuntimeHardLimitRejection::NameBytes);
    }
    None
}

const fn hard_max_value_bytes_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_VALUE_BYTES {
        return Some(ActionsRuntimeHardLimitRejection::ValueBytes);
    }
    None
}

const fn hard_max_stream_bytes_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_STREAM_BYTES {
        return Some(ActionsRuntimeHardLimitRejection::StreamBytes);
    }
    None
}

const fn hard_max_stream_lines_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_STREAM_LINES {
        return Some(ActionsRuntimeHardLimitRejection::StreamLines);
    }
    None
}

const fn hard_max_properties_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_PROPERTIES {
        return Some(ActionsRuntimeHardLimitRejection::Properties);
    }
    None
}

const fn hard_max_masks_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_MASKS {
        return Some(ActionsRuntimeHardLimitRejection::Masks);
    }
    None
}

const fn hard_max_state_entries_rejection(
    value: usize,
) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_STATE_ENTRIES {
        return Some(ActionsRuntimeHardLimitRejection::StateEntries);
    }
    None
}

const fn hard_max_state_bytes_rejection(value: usize) -> Option<ActionsRuntimeHardLimitRejection> {
    if value > HARD_MAX_STATE_BYTES {
        return Some(ActionsRuntimeHardLimitRejection::StateBytes);
    }
    None
}

/// Independent ceilings for a single GitHub command file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandFileLimits {
    file_bytes: usize,
    summary_bytes: usize,
    line_bytes: usize,
    records: usize,
    name_bytes: usize,
    value_bytes: usize,
}

impl CommandFileLimits {
    /// Creates a command-file limit policy.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit is zero or exceeds its hard ceiling. The
    /// summary ceiling is fixed at the upstream runner's one-MiB attachment
    /// limit or lower.
    pub const fn new(
        maximum_file_bytes: usize,
        maximum_summary_bytes: usize,
        maximum_line_bytes: usize,
        maximum_records: usize,
        maximum_name_bytes: usize,
        maximum_value_bytes: usize,
    ) -> Result<Self, CommandFileLimitsError> {
        if maximum_file_bytes == 0
            || maximum_summary_bytes == 0
            || maximum_line_bytes == 0
            || maximum_records == 0
            || maximum_name_bytes == 0
            || maximum_value_bytes == 0
            || hard_max_file_bytes_rejection(maximum_file_bytes).is_some()
            || hard_max_summary_bytes_rejection(maximum_summary_bytes).is_some()
            || hard_max_line_bytes_rejection(maximum_line_bytes).is_some()
            || hard_max_records_rejection(maximum_records).is_some()
            || hard_max_name_bytes_rejection(maximum_name_bytes).is_some()
            || hard_max_value_bytes_rejection(maximum_value_bytes).is_some()
        {
            return Err(CommandFileLimitsError);
        }
        Ok(Self {
            file_bytes: maximum_file_bytes,
            summary_bytes: maximum_summary_bytes,
            line_bytes: maximum_line_bytes,
            records: maximum_records,
            name_bytes: maximum_name_bytes,
            value_bytes: maximum_value_bytes,
        })
    }

    /// Returns the byte ceiling for any single command file.
    #[must_use]
    pub const fn maximum_file_bytes(self) -> usize {
        self.file_bytes
    }

    /// Returns the additional byte ceiling for `GITHUB_STEP_SUMMARY`.
    #[must_use]
    pub const fn maximum_summary_bytes(self) -> usize {
        self.summary_bytes
    }

    /// Returns the byte ceiling for one logical file line.
    #[must_use]
    pub const fn maximum_line_bytes(self) -> usize {
        self.line_bytes
    }

    /// Returns the maximum number of records, paths, or summary lines.
    #[must_use]
    pub const fn maximum_records(self) -> usize {
        self.records
    }

    /// Returns the byte ceiling for a command name or heredoc delimiter.
    #[must_use]
    pub const fn maximum_name_bytes(self) -> usize {
        self.name_bytes
    }

    /// Returns the byte ceiling for one decoded value or PATH entry.
    #[must_use]
    pub const fn maximum_value_bytes(self) -> usize {
        self.value_bytes
    }
}

impl Default for CommandFileLimits {
    fn default() -> Self {
        Self {
            file_bytes: 16 * 1_024 * 1_024,
            summary_bytes: HARD_MAX_SUMMARY_BYTES,
            line_bytes: 1_024 * 1_024,
            records: 16_384,
            name_bytes: 4_096,
            value_bytes: 16 * 1_024 * 1_024,
        }
    }
}

/// A command-file limit policy contains a zero or unsafe value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub command-file limit is zero or exceeds a hard safety ceiling")]
pub struct CommandFileLimitsError;

/// Aggregate and per-line ceilings for one stdout/stderr command session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowCommandLimits {
    stream_bytes: usize,
    line_bytes: usize,
    stream_lines: usize,
    commands: usize,
    properties: usize,
    name_bytes: usize,
    data_bytes: usize,
    masks: usize,
}

/// Builder for validated [`WorkflowCommandLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct WorkflowCommandLimitsBuilder {
    stream_bytes: usize,
    line_bytes: usize,
    stream_lines: usize,
    commands: usize,
    properties: usize,
    name_bytes: usize,
    data_bytes: usize,
    masks: usize,
}

impl WorkflowCommandLimitsBuilder {
    /// Sets the aggregate byte ceiling across all observed lines.
    pub const fn maximum_stream_bytes(mut self, value: usize) -> Self {
        self.stream_bytes = value;
        self
    }

    /// Sets the byte ceiling for one captured line.
    pub const fn maximum_line_bytes(mut self, value: usize) -> Self {
        self.line_bytes = value;
        self
    }

    /// Sets the maximum number of observed lines in the session.
    pub const fn maximum_stream_lines(mut self, value: usize) -> Self {
        self.stream_lines = value;
        self
    }

    /// Sets the maximum number of recognized commands in the session.
    pub const fn maximum_commands(mut self, value: usize) -> Self {
        self.commands = value;
        self
    }

    /// Sets the maximum number of raw properties on one command.
    pub const fn maximum_properties(mut self, value: usize) -> Self {
        self.properties = value;
        self
    }

    /// Sets the byte ceiling for command and property names.
    pub const fn maximum_name_bytes(mut self, value: usize) -> Self {
        self.name_bytes = value;
        self
    }

    /// Sets the byte ceiling for decoded command data and property values.
    pub const fn maximum_data_bytes(mut self, value: usize) -> Self {
        self.data_bytes = value;
        self
    }

    /// Sets the maximum number of secret masks registered in the session.
    pub const fn maximum_masks(mut self, value: usize) -> Self {
        self.masks = value;
        self
    }

    /// Validates and creates a workflow-command stream policy.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit is zero or exceeds its hard ceiling.
    pub const fn build(self) -> Result<WorkflowCommandLimits, WorkflowCommandLimitsError> {
        if self.stream_bytes == 0
            || self.line_bytes == 0
            || self.stream_lines == 0
            || self.commands == 0
            || self.properties == 0
            || self.name_bytes == 0
            || self.data_bytes == 0
            || self.masks == 0
            || hard_max_stream_bytes_rejection(self.stream_bytes).is_some()
            || hard_max_line_bytes_rejection(self.line_bytes).is_some()
            || hard_max_stream_lines_rejection(self.stream_lines).is_some()
            || hard_max_records_rejection(self.commands).is_some()
            || hard_max_properties_rejection(self.properties).is_some()
            || hard_max_name_bytes_rejection(self.name_bytes).is_some()
            || hard_max_value_bytes_rejection(self.data_bytes).is_some()
            || hard_max_masks_rejection(self.masks).is_some()
        {
            return Err(WorkflowCommandLimitsError);
        }
        Ok(WorkflowCommandLimits {
            stream_bytes: self.stream_bytes,
            line_bytes: self.line_bytes,
            stream_lines: self.stream_lines,
            commands: self.commands,
            properties: self.properties,
            name_bytes: self.name_bytes,
            data_bytes: self.data_bytes,
            masks: self.masks,
        })
    }
}

impl Default for WorkflowCommandLimitsBuilder {
    fn default() -> Self {
        Self {
            stream_bytes: 64 * 1_024 * 1_024,
            line_bytes: 1_024 * 1_024,
            stream_lines: 1_000_000,
            commands: 65_536,
            properties: 256,
            name_bytes: 4_096,
            data_bytes: 16 * 1_024 * 1_024,
            masks: 65_536,
        }
    }
}

impl WorkflowCommandLimits {
    /// Starts with the safe default workflow-command policy.
    pub fn builder() -> WorkflowCommandLimitsBuilder {
        WorkflowCommandLimitsBuilder::default()
    }

    /// Returns the aggregate byte ceiling across all observed lines.
    #[must_use]
    pub const fn maximum_stream_bytes(self) -> usize {
        self.stream_bytes
    }

    /// Returns the byte ceiling for one captured line.
    #[must_use]
    pub const fn maximum_line_bytes(self) -> usize {
        self.line_bytes
    }

    /// Returns the maximum number of observed lines in the session.
    #[must_use]
    pub const fn maximum_stream_lines(self) -> usize {
        self.stream_lines
    }

    /// Returns the maximum number of recognized commands in the session.
    #[must_use]
    pub const fn maximum_commands(self) -> usize {
        self.commands
    }

    /// Returns the maximum number of raw properties on one command.
    #[must_use]
    pub const fn maximum_properties(self) -> usize {
        self.properties
    }

    /// Returns the byte ceiling for command and property names.
    #[must_use]
    pub const fn maximum_name_bytes(self) -> usize {
        self.name_bytes
    }

    /// Returns the byte ceiling for decoded command data and property values.
    #[must_use]
    pub const fn maximum_data_bytes(self) -> usize {
        self.data_bytes
    }

    /// Returns the maximum number of secret masks registered in the session.
    #[must_use]
    pub const fn maximum_masks(self) -> usize {
        self.masks
    }
}

impl Default for WorkflowCommandLimits {
    fn default() -> Self {
        WorkflowCommandLimitsBuilder::default()
            .build()
            .expect("default workflow-command limits are valid")
    }
}

/// A workflow-command limit policy contains a zero or unsafe value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub workflow-command limit is zero or exceeds a hard safety ceiling")]
pub struct WorkflowCommandLimitsError;

/// Ceilings for durable command effects accumulated across one job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseApplicationLimits {
    environment_entries: usize,
    path_entries: usize,
    steps: usize,
    action_states: usize,
    aggregate_bytes: usize,
}

impl PhaseApplicationLimits {
    /// Creates an accumulated-state policy.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit is zero or exceeds its hard ceiling.
    pub const fn new(
        maximum_environment_entries: usize,
        maximum_path_entries: usize,
        maximum_steps: usize,
        maximum_action_states: usize,
        maximum_aggregate_bytes: usize,
    ) -> Result<Self, PhaseApplicationLimitsError> {
        if maximum_environment_entries == 0
            || maximum_path_entries == 0
            || maximum_steps == 0
            || maximum_action_states == 0
            || maximum_aggregate_bytes == 0
            || hard_max_state_entries_rejection(maximum_environment_entries).is_some()
            || hard_max_state_entries_rejection(maximum_path_entries).is_some()
            || hard_max_state_entries_rejection(maximum_steps).is_some()
            || hard_max_state_entries_rejection(maximum_action_states).is_some()
            || hard_max_state_bytes_rejection(maximum_aggregate_bytes).is_some()
        {
            return Err(PhaseApplicationLimitsError);
        }
        Ok(Self {
            environment_entries: maximum_environment_entries,
            path_entries: maximum_path_entries,
            steps: maximum_steps,
            action_states: maximum_action_states,
            aggregate_bytes: maximum_aggregate_bytes,
        })
    }

    /// Returns the maximum number of names in the derived job environment.
    #[must_use]
    pub const fn maximum_environment_entries(self) -> usize {
        self.environment_entries
    }

    /// Returns the maximum number of entries prepended to the derived PATH.
    #[must_use]
    pub const fn maximum_path_entries(self) -> usize {
        self.path_entries
    }

    /// Returns the maximum number of step scopes retaining outputs.
    #[must_use]
    pub const fn maximum_steps(self) -> usize {
        self.steps
    }

    /// Returns the maximum number of action invocations retaining state.
    #[must_use]
    pub const fn maximum_action_states(self) -> usize {
        self.action_states
    }

    /// Returns the byte ceiling for all durable command state combined.
    #[must_use]
    pub const fn maximum_aggregate_bytes(self) -> usize {
        self.aggregate_bytes
    }
}

impl Default for PhaseApplicationLimits {
    fn default() -> Self {
        Self {
            environment_entries: 16_384,
            path_entries: 4_096,
            steps: 16_384,
            action_states: 16_384,
            aggregate_bytes: 64 * 1_024 * 1_024,
        }
    }
}

/// An accumulated-state limit policy contains a zero or unsafe value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub phase-application limit is zero or exceeds a hard safety ceiling")]
pub struct PhaseApplicationLimitsError;

#[cfg(test)]
mod hard_limit_contract_tests {
    use super::{
        ActionsRuntimeHardLimitRejection, HARD_MAX_FILE_BYTES, HARD_MAX_LINE_BYTES, HARD_MAX_MASKS,
        HARD_MAX_NAME_BYTES, HARD_MAX_PROPERTIES, HARD_MAX_RECORDS, HARD_MAX_STATE_BYTES,
        HARD_MAX_STATE_ENTRIES, HARD_MAX_STREAM_BYTES, HARD_MAX_STREAM_LINES,
        HARD_MAX_SUMMARY_BYTES, HARD_MAX_VALUE_BYTES, hard_max_file_bytes_rejection,
        hard_max_line_bytes_rejection, hard_max_masks_rejection, hard_max_name_bytes_rejection,
        hard_max_properties_rejection, hard_max_records_rejection, hard_max_state_bytes_rejection,
        hard_max_state_entries_rejection, hard_max_stream_bytes_rejection,
        hard_max_stream_lines_rejection, hard_max_summary_bytes_rejection,
        hard_max_value_bytes_rejection,
    };

    #[test]
    fn hard_max_file_bytes_has_exact_boundaries() {
        assert_eq!(hard_max_file_bytes_rejection(HARD_MAX_FILE_BYTES - 1), None);
        assert_eq!(hard_max_file_bytes_rejection(HARD_MAX_FILE_BYTES), None);
        assert_eq!(
            hard_max_file_bytes_rejection(HARD_MAX_FILE_BYTES + 1),
            Some(ActionsRuntimeHardLimitRejection::FileBytes)
        );
    }

    #[test]
    fn hard_max_summary_bytes_has_exact_boundaries() {
        assert_eq!(
            hard_max_summary_bytes_rejection(HARD_MAX_SUMMARY_BYTES - 1),
            None
        );
        assert_eq!(
            hard_max_summary_bytes_rejection(HARD_MAX_SUMMARY_BYTES),
            None
        );
        assert_eq!(
            hard_max_summary_bytes_rejection(HARD_MAX_SUMMARY_BYTES + 1),
            Some(ActionsRuntimeHardLimitRejection::SummaryBytes)
        );
    }

    #[test]
    fn hard_max_line_bytes_has_exact_boundaries() {
        assert_eq!(hard_max_line_bytes_rejection(HARD_MAX_LINE_BYTES - 1), None);
        assert_eq!(hard_max_line_bytes_rejection(HARD_MAX_LINE_BYTES), None);
        assert_eq!(
            hard_max_line_bytes_rejection(HARD_MAX_LINE_BYTES + 1),
            Some(ActionsRuntimeHardLimitRejection::LineBytes)
        );
    }

    #[test]
    fn hard_max_records_has_exact_boundaries() {
        assert_eq!(hard_max_records_rejection(HARD_MAX_RECORDS - 1), None);
        assert_eq!(hard_max_records_rejection(HARD_MAX_RECORDS), None);
        assert_eq!(
            hard_max_records_rejection(HARD_MAX_RECORDS + 1),
            Some(ActionsRuntimeHardLimitRejection::Records)
        );
    }

    #[test]
    fn hard_max_name_bytes_has_exact_boundaries() {
        assert_eq!(hard_max_name_bytes_rejection(HARD_MAX_NAME_BYTES - 1), None);
        assert_eq!(hard_max_name_bytes_rejection(HARD_MAX_NAME_BYTES), None);
        assert_eq!(
            hard_max_name_bytes_rejection(HARD_MAX_NAME_BYTES + 1),
            Some(ActionsRuntimeHardLimitRejection::NameBytes)
        );
    }

    #[test]
    fn hard_max_value_bytes_has_exact_boundaries() {
        assert_eq!(
            hard_max_value_bytes_rejection(HARD_MAX_VALUE_BYTES - 1),
            None
        );
        assert_eq!(hard_max_value_bytes_rejection(HARD_MAX_VALUE_BYTES), None);
        assert_eq!(
            hard_max_value_bytes_rejection(HARD_MAX_VALUE_BYTES + 1),
            Some(ActionsRuntimeHardLimitRejection::ValueBytes)
        );
    }

    #[test]
    fn hard_max_stream_bytes_has_exact_boundaries() {
        assert_eq!(
            hard_max_stream_bytes_rejection(HARD_MAX_STREAM_BYTES - 1),
            None
        );
        assert_eq!(hard_max_stream_bytes_rejection(HARD_MAX_STREAM_BYTES), None);
        assert_eq!(
            hard_max_stream_bytes_rejection(HARD_MAX_STREAM_BYTES + 1),
            Some(ActionsRuntimeHardLimitRejection::StreamBytes)
        );
    }

    #[test]
    fn hard_max_stream_lines_has_exact_boundaries() {
        assert_eq!(
            hard_max_stream_lines_rejection(HARD_MAX_STREAM_LINES - 1),
            None
        );
        assert_eq!(hard_max_stream_lines_rejection(HARD_MAX_STREAM_LINES), None);
        assert_eq!(
            hard_max_stream_lines_rejection(HARD_MAX_STREAM_LINES + 1),
            Some(ActionsRuntimeHardLimitRejection::StreamLines)
        );
    }

    #[test]
    fn hard_max_properties_has_exact_boundaries() {
        assert_eq!(hard_max_properties_rejection(HARD_MAX_PROPERTIES - 1), None);
        assert_eq!(hard_max_properties_rejection(HARD_MAX_PROPERTIES), None);
        assert_eq!(
            hard_max_properties_rejection(HARD_MAX_PROPERTIES + 1),
            Some(ActionsRuntimeHardLimitRejection::Properties)
        );
    }

    #[test]
    fn hard_max_masks_has_exact_boundaries() {
        assert_eq!(hard_max_masks_rejection(HARD_MAX_MASKS - 1), None);
        assert_eq!(hard_max_masks_rejection(HARD_MAX_MASKS), None);
        assert_eq!(
            hard_max_masks_rejection(HARD_MAX_MASKS + 1),
            Some(ActionsRuntimeHardLimitRejection::Masks)
        );
    }

    #[test]
    fn hard_max_state_entries_has_exact_boundaries() {
        assert_eq!(
            hard_max_state_entries_rejection(HARD_MAX_STATE_ENTRIES - 1),
            None
        );
        assert_eq!(
            hard_max_state_entries_rejection(HARD_MAX_STATE_ENTRIES),
            None
        );
        assert_eq!(
            hard_max_state_entries_rejection(HARD_MAX_STATE_ENTRIES + 1),
            Some(ActionsRuntimeHardLimitRejection::StateEntries)
        );
    }

    #[test]
    fn hard_max_state_bytes_has_exact_boundaries() {
        assert_eq!(
            hard_max_state_bytes_rejection(HARD_MAX_STATE_BYTES - 1),
            None
        );
        assert_eq!(hard_max_state_bytes_rejection(HARD_MAX_STATE_BYTES), None);
        assert_eq!(
            hard_max_state_bytes_rejection(HARD_MAX_STATE_BYTES + 1),
            Some(ActionsRuntimeHardLimitRejection::StateBytes)
        );
    }
}
