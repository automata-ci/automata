use std::fmt::Debug;

use crate::model::{SensitiveText, artifact_declaration_file_byte_rejection};
use crate::{
    CommandFileError, CommandFileKind, CommandFileLimits, CommandFilePlatform,
    EnvironmentCommandFile, MAX_ARTIFACT_DECLARATION_FILE_BYTES, NameValueCommand,
    OutputCommandFile, ParsedCommandFile, PathCommandFile, StateCommandFile,
    StepSummaryCommandFile, artifact::parse_artifact_declarations,
};

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Object-safe pure port for decoding one captured per-step command file.
pub trait CommandFileDecoder: Debug + Send + Sync {
    /// Decodes a command file without performing filesystem I/O.
    ///
    /// # Errors
    ///
    /// Rejects invalid UTF-8, malformed records and heredocs, NUL bytes, and
    /// any configured size or count limit violation.
    fn decode(
        &self,
        kind: CommandFileKind,
        source: &[u8],
        platform: CommandFilePlatform,
    ) -> Result<ParsedCommandFile, CommandFileError>;
}

/// Parser matching `actions/runner` v2.336.0's command-file grammar, with
/// explicit hard resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubCommandFileDecoder {
    limits: CommandFileLimits,
}

impl GithubCommandFileDecoder {
    /// Creates a decoder constrained by `limits`.
    #[must_use]
    pub const fn new(limits: CommandFileLimits) -> Self {
        Self { limits }
    }

    /// Returns the limits applied to every decode operation.
    #[must_use]
    pub const fn limits(self) -> CommandFileLimits {
        self.limits
    }
}

impl Default for GithubCommandFileDecoder {
    fn default() -> Self {
        Self::new(CommandFileLimits::default())
    }
}

impl CommandFileDecoder for GithubCommandFileDecoder {
    fn decode(
        &self,
        kind: CommandFileKind,
        source: &[u8],
        platform: CommandFilePlatform,
    ) -> Result<ParsedCommandFile, CommandFileError> {
        if kind == CommandFileKind::StepSummary
            && source.len() > self.limits.maximum_summary_bytes()
        {
            return Err(CommandFileError::SummaryTooLarge {
                maximum: self.limits.maximum_summary_bytes(),
                received: source.len(),
            });
        }
        let configured_file_bytes = self.limits.maximum_file_bytes();
        let maximum_file_bytes = if kind == CommandFileKind::Artifacts
            && artifact_declaration_file_byte_rejection(configured_file_bytes).is_some()
        {
            MAX_ARTIFACT_DECLARATION_FILE_BYTES
        } else {
            configured_file_bytes
        };
        if source.len() > maximum_file_bytes {
            return Err(CommandFileError::FileTooLarge {
                kind,
                maximum: maximum_file_bytes,
                received: source.len(),
            });
        }

        let without_bom = source.strip_prefix(UTF8_BOM).unwrap_or(source);
        let text =
            std::str::from_utf8(without_bom).map_err(|_| CommandFileError::NonUtf8 { kind })?;

        if kind != CommandFileKind::StepSummary && text.contains('\0') {
            return Err(CommandFileError::MalformedRecord { kind });
        }

        match kind {
            CommandFileKind::Environment => {
                Ok(ParsedCommandFile::Environment(EnvironmentCommandFile {
                    commands: parse_name_values(kind, text, platform, self.limits)?,
                }))
            }
            CommandFileKind::Output => Ok(ParsedCommandFile::Output(OutputCommandFile {
                commands: parse_name_values(kind, text, platform, self.limits)?,
            })),
            CommandFileKind::State => Ok(ParsedCommandFile::State(StateCommandFile {
                commands: parse_name_values(kind, text, platform, self.limits)?,
            })),
            CommandFileKind::Path => Ok(ParsedCommandFile::Path(PathCommandFile {
                paths: parse_paths(kind, text, self.limits)?,
            })),
            CommandFileKind::StepSummary => {
                validate_summary(text, self.limits)?;
                Ok(ParsedCommandFile::StepSummary(StepSummaryCommandFile {
                    markdown: SensitiveText::new(text.to_owned()),
                }))
            }
            CommandFileKind::Artifacts => Ok(ParsedCommandFile::Artifacts(
                parse_artifact_declarations(text, self.limits)?,
            )),
        }
    }
}

fn validate_summary(text: &str, limits: CommandFileLimits) -> Result<(), CommandFileError> {
    let kind = CommandFileKind::StepSummary;
    let bytes = text.as_bytes();
    let mut start = 0_usize;
    let mut index = 0_usize;
    let mut lines = 0_usize;
    while index < bytes.len() {
        if bytes[index] == b'\r' || bytes[index] == b'\n' {
            validate_line(kind, &text[start..index], limits)?;
            lines = lines.saturating_add(1);
            if lines > limits.maximum_records() {
                return Err(CommandFileError::TooManyRecords {
                    kind,
                    maximum: limits.maximum_records(),
                });
            }
            if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                index += 1;
            }
            start = index + 1;
        }
        index += 1;
    }
    if start < text.len() {
        validate_line(kind, &text[start..], limits)?;
        lines = lines.saturating_add(1);
        if lines > limits.maximum_records() {
            return Err(CommandFileError::TooManyRecords {
                kind,
                maximum: limits.maximum_records(),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ReadLine<'a> {
    text: &'a str,
    newline_bytes: Option<usize>,
}

fn parse_name_values(
    kind: CommandFileKind,
    text: &str,
    platform: CommandFilePlatform,
    limits: CommandFileLimits,
) -> Result<Vec<NameValueCommand>, CommandFileError> {
    let mut commands = Vec::new();
    let mut index = 0;

    while let Some(line) = read_env_line(text, &mut index, platform) {
        validate_line(kind, line.text, limits)?;
        if line.text.is_empty() {
            continue;
        }
        if commands.len() >= limits.maximum_records() {
            return Err(CommandFileError::TooManyRecords {
                kind,
                maximum: limits.maximum_records(),
            });
        }

        let equals = line.text.find('=');
        let heredoc = line.text.find("<<");
        if equals.is_some_and(|equals_index| {
            heredoc.is_none_or(|heredoc_index| equals_index < heredoc_index)
        }) {
            let equals_index = equals.expect("checked as present");
            let name = &line.text[..equals_index];
            let value = &line.text[equals_index + 1..];
            validate_name(kind, name, limits)?;
            validate_value(kind, value, limits)?;
            commands.push(NameValueCommand::from_parts(
                name.to_owned(),
                value.to_owned(),
            ));
            continue;
        }

        if let Some(heredoc_index) = heredoc
            .filter(|heredoc_index| equals.is_none_or(|equals_index| *heredoc_index < equals_index))
        {
            let name = &line.text[..heredoc_index];
            let delimiter = &line.text[heredoc_index + 2..];
            validate_name(kind, name, limits)?;
            if delimiter.is_empty() {
                return Err(CommandFileError::EmptyDelimiter { kind });
            }
            if delimiter.len() > limits.maximum_name_bytes() {
                return Err(CommandFileError::NameTooLong {
                    kind,
                    maximum: limits.maximum_name_bytes(),
                });
            }

            let value_start = index;
            let mut value_end = index;
            loop {
                let Some(value_line) = read_env_line(text, &mut index, platform) else {
                    return Err(CommandFileError::MissingDelimiter { kind });
                };
                validate_line(kind, value_line.text, limits)?;
                if value_line.text == delimiter {
                    break;
                }
                let Some(newline_bytes) = value_line.newline_bytes else {
                    return Err(CommandFileError::HeredocValueMissingNewline { kind });
                };
                value_end = index - newline_bytes;
            }

            let value = if value_end > value_start {
                &text[value_start..value_end]
            } else {
                ""
            };
            validate_value(kind, value, limits)?;
            commands.push(NameValueCommand::from_parts(
                name.to_owned(),
                value.to_owned(),
            ));
            continue;
        }

        return Err(CommandFileError::MalformedRecord { kind });
    }

    Ok(commands)
}

fn read_env_line<'a>(
    text: &'a str,
    index: &mut usize,
    platform: CommandFilePlatform,
) -> Option<ReadLine<'a>> {
    if *index >= text.len() {
        return None;
    }

    let original = *index;
    let relative_lf = text.as_bytes()[original..]
        .iter()
        .position(|byte| *byte == b'\n');
    let Some(relative_lf) = relative_lf else {
        *index = text.len();
        return Some(ReadLine {
            text: &text[original..],
            newline_bytes: None,
        });
    };
    let lf = original + relative_lf;

    if platform == CommandFilePlatform::Windows && lf > original && text.as_bytes()[lf - 1] == b'\r'
    {
        *index = lf + 1;
        return Some(ReadLine {
            text: &text[original..lf - 1],
            newline_bytes: Some(2),
        });
    }

    *index = lf + 1;
    Some(ReadLine {
        text: &text[original..lf],
        newline_bytes: Some(1),
    })
}

fn parse_paths(
    kind: CommandFileKind,
    text: &str,
    limits: CommandFileLimits,
) -> Result<Vec<SensitiveText>, CommandFileError> {
    let mut paths = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'\r' || bytes[index] == b'\n' {
            let line = &text[start..index];
            validate_path_line(kind, line, limits, paths.len())?;
            if !line.is_empty() {
                paths.push(SensitiveText::new(line.to_owned()));
            }
            if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                index += 1;
            }
            start = index + 1;
        }
        index += 1;
    }

    if start < text.len() {
        let line = &text[start..];
        validate_path_line(kind, line, limits, paths.len())?;
        if !line.is_empty() {
            paths.push(SensitiveText::new(line.to_owned()));
        }
    }
    Ok(paths)
}

fn validate_path_line(
    kind: CommandFileKind,
    line: &str,
    limits: CommandFileLimits,
    current_records: usize,
) -> Result<(), CommandFileError> {
    validate_line(kind, line, limits)?;
    if line.len() > limits.maximum_value_bytes() {
        return Err(CommandFileError::ValueTooLong {
            kind,
            maximum: limits.maximum_value_bytes(),
        });
    }
    if !line.is_empty() && current_records >= limits.maximum_records() {
        return Err(CommandFileError::TooManyRecords {
            kind,
            maximum: limits.maximum_records(),
        });
    }
    Ok(())
}

fn validate_line(
    kind: CommandFileKind,
    line: &str,
    limits: CommandFileLimits,
) -> Result<(), CommandFileError> {
    if line.len() > limits.maximum_line_bytes() {
        return Err(CommandFileError::LineTooLong {
            kind,
            maximum: limits.maximum_line_bytes(),
        });
    }
    Ok(())
}

fn validate_name(
    kind: CommandFileKind,
    name: &str,
    limits: CommandFileLimits,
) -> Result<(), CommandFileError> {
    if name.is_empty() {
        return Err(CommandFileError::EmptyName { kind });
    }
    if name.len() > limits.maximum_name_bytes() {
        return Err(CommandFileError::NameTooLong {
            kind,
            maximum: limits.maximum_name_bytes(),
        });
    }
    Ok(())
}

fn validate_value(
    kind: CommandFileKind,
    value: &str,
    limits: CommandFileLimits,
) -> Result<(), CommandFileError> {
    if value.len() > limits.maximum_value_bytes() {
        return Err(CommandFileError::ValueTooLong {
            kind,
            maximum: limits.maximum_value_bytes(),
        });
    }
    Ok(())
}
