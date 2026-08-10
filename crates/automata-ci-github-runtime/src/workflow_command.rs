use std::fmt::{self, Debug};

use crate::model::SensitiveText;
use crate::{
    Annotation, AnnotationLevel, AnnotationProperty, CommandNotice, DebugMessage, GroupTitle,
    LegacyStepMutation, MaskRegistration, MatcherCommand, MatcherFile, MatcherOwner,
    NameValueCommand, OutputLine, PathEntry, SecretMask, StopCommands, WorkflowCommandError,
    WorkflowCommandEvent, WorkflowCommandLimits, WorkflowCommandPolicy, WorkflowLine,
};

const REGISTERED_COMMANDS: &[&str] = &[
    "add-mask",
    "add-matcher",
    "add-path",
    "debug",
    "echo",
    "endgroup",
    "error",
    "group",
    "notice",
    "remove-matcher",
    "save-state",
    "set-env",
    "set-output",
    "stop-commands",
    "warning",
];

/// Object-safe stateful port for scanning a single step's stdout and stderr.
pub trait WorkflowCommandProcessor: Debug + Send {
    /// Processes one captured line, without a trailing stream newline.
    ///
    /// # Errors
    ///
    /// Rejects non-UTF-8 input, malformed recognized commands, unsafe legacy
    /// mutations, invalid stop tokens, and aggregate or per-line limit
    /// violations. Error values never contain line data or secret values.
    fn process_line(&mut self, source: &[u8]) -> Result<WorkflowLine, WorkflowCommandError>;

    /// Reports whether command echoing is enabled after the latest line.
    #[must_use]
    fn echo_enabled(&self) -> bool;

    /// Reports whether workflow-command recognition is currently suppressed.
    #[must_use]
    fn commands_stopped(&self) -> bool;
}

/// `actions/runner` v2.336.0 compatible workflow-command session.
pub struct GithubWorkflowCommandSession {
    limits: WorkflowCommandLimits,
    policy: WorkflowCommandPolicy,
    observed_bytes: usize,
    observed_lines: usize,
    observed_commands: usize,
    registered_masks: usize,
    stopped_token: Option<String>,
    echo_enabled: bool,
}

impl GithubWorkflowCommandSession {
    /// Starts an empty command session with the supplied limits and policy.
    #[must_use]
    pub const fn new(limits: WorkflowCommandLimits, policy: WorkflowCommandPolicy) -> Self {
        Self {
            limits,
            policy,
            observed_bytes: 0,
            observed_lines: 0,
            observed_commands: 0,
            registered_masks: 0,
            stopped_token: None,
            echo_enabled: false,
        }
    }

    /// Returns the resource limits enforced for this session.
    #[must_use]
    pub const fn limits(&self) -> WorkflowCommandLimits {
        self.limits
    }

    /// Returns the compatibility policy selected for this session.
    #[must_use]
    pub const fn policy(&self) -> WorkflowCommandPolicy {
        self.policy
    }
}

impl Default for GithubWorkflowCommandSession {
    fn default() -> Self {
        Self::new(
            WorkflowCommandLimits::default(),
            WorkflowCommandPolicy::default(),
        )
    }
}

impl fmt::Debug for GithubWorkflowCommandSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowCommandSession")
            .field("limits", &self.limits)
            .field("policy", &self.policy)
            .field("observed_bytes", &self.observed_bytes)
            .field("observed_lines", &self.observed_lines)
            .field("observed_commands", &self.observed_commands)
            .field("registered_masks", &self.registered_masks)
            .field("commands_stopped", &self.stopped_token.is_some())
            .field("echo_enabled", &self.echo_enabled)
            .finish()
    }
}

impl WorkflowCommandProcessor for GithubWorkflowCommandSession {
    fn process_line(&mut self, source: &[u8]) -> Result<WorkflowLine, WorkflowCommandError> {
        self.observe_line(source)?;
        let line = std::str::from_utf8(source).map_err(|_| WorkflowCommandError::NonUtf8)?;

        if let Some(stop_token) = self.stopped_token.clone() {
            let raw = parse_command(line, self.limits, Some(&stop_token))?;
            if let Some(raw) = raw {
                self.observe_command()?;
                if raw.name.eq_ignore_ascii_case(&stop_token) {
                    self.stopped_token = None;
                    return Ok(WorkflowLine::Command(WorkflowCommandEvent::ResumeCommands));
                }
            }
            return Ok(WorkflowLine::Output(OutputLine::new(line.to_owned())));
        }

        let Some(raw) = parse_command(line, self.limits, None)? else {
            return Ok(WorkflowLine::Output(OutputLine::new(line.to_owned())));
        };
        self.observe_command()?;
        self.process_command(raw, line)
    }

    fn echo_enabled(&self) -> bool {
        self.echo_enabled
    }

    fn commands_stopped(&self) -> bool {
        self.stopped_token.is_some()
    }
}

impl GithubWorkflowCommandSession {
    fn observe_line(&mut self, source: &[u8]) -> Result<(), WorkflowCommandError> {
        if source.len() > self.limits.maximum_line_bytes() {
            return Err(WorkflowCommandError::LineTooLong {
                maximum: self.limits.maximum_line_bytes(),
            });
        }
        let bytes = self.observed_bytes.checked_add(source.len()).ok_or(
            WorkflowCommandError::StreamTooLarge {
                maximum: self.limits.maximum_stream_bytes(),
            },
        )?;
        if bytes > self.limits.maximum_stream_bytes() {
            return Err(WorkflowCommandError::StreamTooLarge {
                maximum: self.limits.maximum_stream_bytes(),
            });
        }
        let lines =
            self.observed_lines
                .checked_add(1)
                .ok_or(WorkflowCommandError::TooManyLines {
                    maximum: self.limits.maximum_stream_lines(),
                })?;
        if lines > self.limits.maximum_stream_lines() {
            return Err(WorkflowCommandError::TooManyLines {
                maximum: self.limits.maximum_stream_lines(),
            });
        }
        self.observed_bytes = bytes;
        self.observed_lines = lines;
        Ok(())
    }

    fn observe_command(&mut self) -> Result<(), WorkflowCommandError> {
        let commands =
            self.observed_commands
                .checked_add(1)
                .ok_or(WorkflowCommandError::TooManyCommands {
                    maximum: self.limits.maximum_commands(),
                })?;
        if commands > self.limits.maximum_commands() {
            return Err(WorkflowCommandError::TooManyCommands {
                maximum: self.limits.maximum_commands(),
            });
        }
        self.observed_commands = commands;
        Ok(())
    }

    fn register_mask_count(&mut self, count: usize) -> Result<(), WorkflowCommandError> {
        let masks =
            self.registered_masks
                .checked_add(count)
                .ok_or(WorkflowCommandError::TooManyMasks {
                    maximum: self.limits.maximum_masks(),
                })?;
        if masks > self.limits.maximum_masks() {
            return Err(WorkflowCommandError::TooManyMasks {
                maximum: self.limits.maximum_masks(),
            });
        }
        self.registered_masks = masks;
        Ok(())
    }

    fn process_command(
        &mut self,
        raw: RawCommand,
        original_line: &str,
    ) -> Result<WorkflowLine, WorkflowCommandError> {
        let event = if raw.name.eq_ignore_ascii_case("add-mask") {
            self.add_mask(&raw.data)?
        } else if raw.name.eq_ignore_ascii_case("error") {
            WorkflowCommandEvent::Annotation(annotation(AnnotationLevel::Error, raw))
        } else if raw.name.eq_ignore_ascii_case("warning") {
            WorkflowCommandEvent::Annotation(annotation(AnnotationLevel::Warning, raw))
        } else if raw.name.eq_ignore_ascii_case("notice") {
            if !self.policy.enhanced_annotations() {
                return Ok(WorkflowLine::Output(OutputLine::new(
                    original_line.to_owned(),
                )));
            }
            WorkflowCommandEvent::Annotation(annotation(AnnotationLevel::Notice, raw))
        } else if raw.name.eq_ignore_ascii_case("group") {
            WorkflowCommandEvent::BeginGroup(GroupTitle::new(raw.data))
        } else if raw.name.eq_ignore_ascii_case("endgroup") {
            WorkflowCommandEvent::EndGroup
        } else if raw.name.eq_ignore_ascii_case("debug") {
            WorkflowCommandEvent::Debug(DebugMessage::new(raw.data))
        } else if raw.name.eq_ignore_ascii_case("stop-commands") {
            return self.stop_commands(raw.data);
        } else if raw.name.eq_ignore_ascii_case("add-matcher") {
            if raw.data.is_empty() {
                WorkflowCommandEvent::Notice(CommandNotice::MissingMatcherPath)
            } else {
                WorkflowCommandEvent::Matcher(MatcherCommand::Add(MatcherFile::new(raw.data)))
            }
        } else if raw.name.eq_ignore_ascii_case("remove-matcher") {
            remove_matcher(raw)
        } else if raw.name.eq_ignore_ascii_case("echo") {
            let enabled = match raw.data.trim().to_ascii_uppercase().as_str() {
                "ON" => true,
                "OFF" => false,
                _ => return Err(WorkflowCommandError::InvalidEchoValue),
            };
            self.echo_enabled = enabled;
            WorkflowCommandEvent::EchoChanged(enabled)
        } else if raw.name.eq_ignore_ascii_case("set-output") {
            WorkflowCommandEvent::LegacyMutation(LegacyStepMutation::Output(named_mutation(raw)?))
        } else if raw.name.eq_ignore_ascii_case("save-state") {
            WorkflowCommandEvent::LegacyMutation(LegacyStepMutation::State(named_mutation(raw)?))
        } else if raw.name.eq_ignore_ascii_case("set-env") {
            if !self.policy.allow_insecure_legacy_commands() {
                return Err(WorkflowCommandError::LegacyCommandDisabled);
            }
            let command = named_mutation(raw)?;
            if command.name().eq_ignore_ascii_case("NODE_OPTIONS") {
                WorkflowCommandEvent::Notice(CommandNotice::BlockedNodeOptions)
            } else {
                WorkflowCommandEvent::LegacyMutation(LegacyStepMutation::Environment(command))
            }
        } else if raw.name.eq_ignore_ascii_case("add-path") {
            if !self.policy.allow_insecure_legacy_commands() {
                return Err(WorkflowCommandError::LegacyCommandDisabled);
            }
            if raw.data.is_empty() {
                return Err(WorkflowCommandError::MissingRequiredProperty);
            }
            WorkflowCommandEvent::LegacyMutation(LegacyStepMutation::Path(PathEntry::new(raw.data)))
        } else {
            return Ok(WorkflowLine::Output(OutputLine::new(
                original_line.to_owned(),
            )));
        };
        Ok(WorkflowLine::Command(event))
    }

    fn add_mask(&mut self, value: &str) -> Result<WorkflowCommandEvent, WorkflowCommandError> {
        if value.trim().is_empty() {
            return Ok(WorkflowCommandEvent::Notice(
                CommandNotice::EmptyMaskIgnored,
            ));
        }

        let mut masks = vec![SecretMask::new(value.to_owned())];
        masks.extend(
            value
                .split(['\r', '\n'])
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(|line| SecretMask::new(line.to_owned())),
        );
        self.register_mask_count(masks.len())?;
        Ok(WorkflowCommandEvent::RegisterMask(MaskRegistration::new(
            masks,
        )))
    }

    fn stop_commands(&mut self, token: String) -> Result<WorkflowLine, WorkflowCommandError> {
        if !valid_stop_token(&token, self.limits.maximum_name_bytes()) {
            return Err(WorkflowCommandError::InvalidStopToken);
        }
        let token_mask = if token.len() > 6 {
            self.register_mask_count(1)?;
            Some(SecretMask::new(token.clone()))
        } else {
            None
        };
        self.stopped_token = Some(token);
        Ok(WorkflowLine::Command(WorkflowCommandEvent::StopCommands(
            StopCommands::new(token_mask),
        )))
    }
}

#[derive(Clone)]
struct RawProperty {
    name: String,
    value: String,
}

#[derive(Clone)]
struct RawCommand {
    name: String,
    properties: Vec<RawProperty>,
    data: String,
}

fn parse_command(
    line: &str,
    limits: WorkflowCommandLimits,
    dynamic_command: Option<&str>,
) -> Result<Option<RawCommand>, WorkflowCommandError> {
    if let Some(command) = parse_v2(line, limits, dynamic_command)? {
        return Ok(Some(command));
    }
    parse_legacy(line, limits, dynamic_command)
}

fn parse_v2(
    line: &str,
    limits: WorkflowCommandLimits,
    dynamic_command: Option<&str>,
) -> Result<Option<RawCommand>, WorkflowCommandError> {
    let message = line.trim_start();
    let Some(rest) = message.strip_prefix("::") else {
        return Ok(None);
    };
    let Some(separator) = rest.find("::") else {
        return Ok(None);
    };
    let command_info = &rest[..separator];
    let space = command_info.find(' ');
    let command_name = space.map_or(command_info, |index| &command_info[..index]);
    if !registered(command_name, dynamic_command) {
        return Ok(None);
    }
    validate_command_name(command_name, limits)?;

    let properties = if let Some(space) = space.filter(|space| *space > 0) {
        let raw_properties = command_info[space + 1..].trim();
        parse_properties(raw_properties, ',', PropertyEscaping::V2, limits)?
    } else {
        Vec::new()
    };
    let data = unescape_v2_data(&rest[separator + 2..]);
    validate_data(&data, limits)?;
    Ok(Some(RawCommand {
        name: command_name.to_owned(),
        properties,
        data,
    }))
}

fn parse_legacy(
    line: &str,
    limits: WorkflowCommandLimits,
    dynamic_command: Option<&str>,
) -> Result<Option<RawCommand>, WorkflowCommandError> {
    let Some(prefix) = line.find("##[") else {
        return Ok(None);
    };
    let info_start = prefix + 3;
    let Some(relative_end) = line[info_start..].find(']') else {
        return Ok(None);
    };
    let end = info_start + relative_end;
    let command_info = &line[info_start..end];
    let space = command_info.find(' ');
    let command_name = space.map_or(command_info, |index| &command_info[..index]);
    if !registered(command_name, dynamic_command) {
        return Ok(None);
    }
    validate_command_name(command_name, limits)?;

    let properties = if let Some(space) = space.filter(|space| *space > 0) {
        parse_properties(
            &command_info[space + 1..],
            ';',
            PropertyEscaping::Legacy,
            limits,
        )?
    } else {
        Vec::new()
    };
    let data = unescape_legacy(&line[end + 1..]);
    validate_data(&data, limits)?;
    Ok(Some(RawCommand {
        name: command_name.to_owned(),
        properties,
        data,
    }))
}

#[derive(Clone, Copy)]
enum PropertyEscaping {
    V2,
    Legacy,
}

fn parse_properties(
    source: &str,
    separator: char,
    escaping: PropertyEscaping,
    limits: WorkflowCommandLimits,
) -> Result<Vec<RawProperty>, WorkflowCommandError> {
    let mut properties: Vec<RawProperty> = Vec::new();
    let mut property_count = 0_usize;
    for property in source
        .split(separator)
        .filter(|property| !property.is_empty())
    {
        property_count = property_count.saturating_add(1);
        if property_count > limits.maximum_properties() {
            return Err(WorkflowCommandError::TooManyProperties {
                maximum: limits.maximum_properties(),
            });
        }
        let Some(equals) = property.find('=') else {
            continue;
        };
        let name = &property[..equals];
        let raw_value = &property[equals + 1..];
        if name.is_empty() || raw_value.is_empty() {
            continue;
        }
        if name.len() > limits.maximum_name_bytes() {
            return Err(WorkflowCommandError::NameTooLong {
                maximum: limits.maximum_name_bytes(),
            });
        }
        let value = match escaping {
            PropertyEscaping::V2 => unescape_v2_property(raw_value),
            PropertyEscaping::Legacy => unescape_legacy(raw_value),
        };
        validate_data(&value, limits)?;
        if let Some(existing) = properties
            .iter_mut()
            .find(|existing| existing.name.eq_ignore_ascii_case(name))
        {
            existing.value = value;
        } else {
            properties.push(RawProperty {
                name: name.to_owned(),
                value,
            });
        }
    }
    Ok(properties)
}

fn registered(command: &str, dynamic_command: Option<&str>) -> bool {
    REGISTERED_COMMANDS
        .iter()
        .any(|registered| registered.eq_ignore_ascii_case(command))
        || dynamic_command.is_some_and(|dynamic| dynamic.eq_ignore_ascii_case(command))
}

fn validate_command_name(
    name: &str,
    limits: WorkflowCommandLimits,
) -> Result<(), WorkflowCommandError> {
    if name.len() > limits.maximum_name_bytes() {
        return Err(WorkflowCommandError::NameTooLong {
            maximum: limits.maximum_name_bytes(),
        });
    }
    Ok(())
}

fn validate_data(data: &str, limits: WorkflowCommandLimits) -> Result<(), WorkflowCommandError> {
    if data.len() > limits.maximum_data_bytes() {
        return Err(WorkflowCommandError::DataTooLong {
            maximum: limits.maximum_data_bytes(),
        });
    }
    Ok(())
}

fn unescape_v2_data(value: &str) -> String {
    value
        .replace("%0D", "\r")
        .replace("%0A", "\n")
        .replace("%25", "%")
}

fn unescape_v2_property(value: &str) -> String {
    value
        .replace("%0D", "\r")
        .replace("%0A", "\n")
        .replace("%3A", ":")
        .replace("%2C", ",")
        .replace("%25", "%")
}

fn unescape_legacy(value: &str) -> String {
    value
        .replace("%3B", ";")
        .replace("%0D", "\r")
        .replace("%0A", "\n")
        .replace("%5D", "]")
        .replace("%25", "%")
}

fn raw_property<'a>(command: &'a RawCommand, name: &str) -> Option<&'a str> {
    command
        .properties
        .iter()
        .find(|property| property.name.eq_ignore_ascii_case(name))
        .map(|property| property.value.as_str())
}

fn named_mutation(command: RawCommand) -> Result<NameValueCommand, WorkflowCommandError> {
    let name = raw_property(&command, "name")
        .filter(|name| !name.is_empty())
        .ok_or(WorkflowCommandError::MissingRequiredProperty)?;
    Ok(NameValueCommand::from_parts(name.to_owned(), command.data))
}

fn remove_matcher(command: RawCommand) -> WorkflowCommandEvent {
    let owner = raw_property(&command, "owner").filter(|owner| !owner.is_empty());
    match (owner, command.data.is_empty()) {
        (Some(_), false) | (None, true) => {
            WorkflowCommandEvent::Notice(CommandNotice::InvalidMatcherRemoval)
        }
        (Some(owner), true) => WorkflowCommandEvent::Matcher(MatcherCommand::RemoveOwner(
            MatcherOwner::new(owner.to_owned()),
        )),
        (None, false) => WorkflowCommandEvent::Matcher(MatcherCommand::RemoveFile(
            MatcherFile::new(command.data),
        )),
    }
}

fn annotation(level: AnnotationLevel, mut command: RawCommand) -> Annotation {
    normalize_annotation_locations(&mut command.properties);
    Annotation {
        level,
        message: SensitiveText::new(command.data),
        properties: command
            .properties
            .into_iter()
            .map(|property| AnnotationProperty::new(property.name, property.value))
            .collect(),
    }
}

fn normalize_annotation_locations(properties: &mut Vec<RawProperty>) {
    let mut line = property_value(properties, "line").map(str::to_owned);
    let end_line = property_value(properties, "endLine").map(str::to_owned);
    let column = property_value(properties, "col").map(str::to_owned);
    let end_column = property_value(properties, "endColumn").map(str::to_owned);

    let mut parsed_line = parse_dotnet_i32(line.as_deref());
    let parsed_end_line = parse_dotnet_i32(end_line.as_deref());
    let mut parsed_column = parse_dotnet_i32(column.as_deref());
    let parsed_end_column = parse_dotnet_i32(end_column.as_deref());
    let mut has_line = parsed_line.is_some();
    let has_end_line = parsed_end_line.is_some();
    let mut has_column = parsed_column.is_some();
    let has_end_column = parsed_end_column.is_some();

    if has_end_line && !has_line {
        set_property(properties, "line", end_line.clone().unwrap_or_default());
        line.clone_from(&end_line);
        parsed_line = Some(0);
        has_line = true;
    }
    if has_end_column && !has_column {
        set_property(properties, "col", end_column.clone().unwrap_or_default());
        parsed_column = Some(0);
        has_column = true;
    }
    if !has_line && (has_column || has_end_column) {
        remove_property(properties, "col");
        remove_property(properties, "endColumn");
    }
    if has_end_line && line != end_line && (has_column || has_end_column) {
        remove_property(properties, "col");
        remove_property(properties, "endColumn");
    }
    if parsed_line
        .zip(parsed_end_line)
        .is_some_and(|(start, end)| end < start)
    {
        remove_property(properties, "line");
        remove_property(properties, "endLine");
    }
    if parsed_column
        .zip(parsed_end_column)
        .is_some_and(|(start, end)| end < start)
    {
        remove_property(properties, "col");
        remove_property(properties, "endColumn");
    }
}

fn parse_dotnet_i32(value: Option<&str>) -> Option<i32> {
    value?.trim().parse().ok()
}

fn property_value<'a>(properties: &'a [RawProperty], name: &str) -> Option<&'a str> {
    properties
        .iter()
        .find(|property| property.name.eq_ignore_ascii_case(name))
        .map(|property| property.value.as_str())
}

fn set_property(properties: &mut Vec<RawProperty>, name: &str, value: String) {
    if let Some(property) = properties
        .iter_mut()
        .find(|property| property.name.eq_ignore_ascii_case(name))
    {
        property.value = value;
    } else {
        properties.push(RawProperty {
            name: name.to_owned(),
            value,
        });
    }
}

fn remove_property(properties: &mut Vec<RawProperty>, name: &str) {
    properties.retain(|property| !property.name.eq_ignore_ascii_case(name));
}

fn valid_stop_token(token: &str, maximum_bytes: usize) -> bool {
    !token.is_empty()
        && token.len() <= maximum_bytes
        && !REGISTERED_COMMANDS
            .iter()
            .any(|registered| registered.eq_ignore_ascii_case(token))
        && !token.eq_ignore_ascii_case("pause-logging")
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
