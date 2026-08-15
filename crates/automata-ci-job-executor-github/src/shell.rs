use std::borrow::Cow;

use automata_ci_core::{RunnerFeature, ShellTemplate, ValueTemplate};
use automata_ci_execution::{TargetPath, TargetPlatform};
use thiserror::Error;

use crate::{
    environment::ResolvedEnvironmentValue,
    error::{ExecutorAdapterError, ExecutorAdapterErrorKind},
    port::GithubToolchain,
};

pub(crate) enum ResolvedShell {
    Default,
    Named(ShellKind),
    CommandTemplate(SafeCommandTemplate),
}

impl ResolvedShell {
    pub(crate) fn script_extension(&self, platform: TargetPlatform) -> &'static str {
        match self {
            Self::Named(shell) | Self::CommandTemplate(SafeCommandTemplate { shell, .. }) => {
                shell.script_extension()
            }
            Self::Default if platform == TargetPlatform::Windows => ".ps1",
            Self::Default => ".sh",
        }
    }

    pub(crate) fn fix_up_script<'command>(
        &self,
        platform: TargetPlatform,
        command: &'command str,
    ) -> Cow<'command, str> {
        let shell = match self {
            Self::Default if platform == TargetPlatform::Windows => Some(ShellKind::Pwsh),
            Self::Named(shell) | Self::CommandTemplate(SafeCommandTemplate { shell, .. }) => {
                Some(*shell)
            }
            Self::Default => None,
        };
        let fixed = match shell {
            Some(ShellKind::Pwsh | ShellKind::PowerShell) => Cow::Owned(format!(
                "$ErrorActionPreference = 'stop'\n{command}\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) {{ exit $LASTEXITCODE }}"
            )),
            Some(ShellKind::Cmd) => Cow::Owned(format!("@echo off\n{command}")),
            _ => Cow::Borrowed(command),
        };
        if platform == TargetPlatform::Windows {
            Cow::Owned(fixed.replace("\r\n", "\n").replace('\n', "\r\n"))
        } else {
            fixed
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ShellKind {
    Bash,
    Sh,
    Python,
    Pwsh,
    PowerShell,
    Cmd,
}

impl ShellKind {
    fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("bash") {
            Some(Self::Bash)
        } else if value.eq_ignore_ascii_case("sh") {
            Some(Self::Sh)
        } else if value.eq_ignore_ascii_case("python") {
            Some(Self::Python)
        } else if value.eq_ignore_ascii_case("pwsh") {
            Some(Self::Pwsh)
        } else if value.eq_ignore_ascii_case("powershell") {
            Some(Self::PowerShell)
        } else if value.eq_ignore_ascii_case("cmd") {
            Some(Self::Cmd)
        } else {
            None
        }
    }

    const fn script_extension(self) -> &'static str {
        match self {
            Self::Bash | Self::Sh => ".sh",
            Self::Python => ".py",
            Self::Pwsh | Self::PowerShell => ".ps1",
            Self::Cmd => ".cmd",
        }
    }

    const fn runner_feature(self) -> RunnerFeature {
        match self {
            Self::Bash => RunnerFeature::BASH_SHELL,
            Self::Sh => RunnerFeature::SH_SHELL,
            Self::Python => RunnerFeature::PYTHON_SHELL,
            Self::Pwsh => RunnerFeature::PWSH_SHELL,
            Self::PowerShell => RunnerFeature::WINDOWS_POWERSHELL_SHELL,
            Self::Cmd => RunnerFeature::CMD_SHELL,
        }
    }
}

/// A literal GitHub shell value cannot be represented by the closed runner contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("literal GitHub shell is unsupported")]
pub struct StaticShellRequirementError;

/// Returns the exact runner capability required by one literal GitHub shell value.
///
/// Named shells and safe custom templates use the same parser as executor
/// admission, preventing the scheduling and execution boundaries from
/// interpreting the value differently.
///
/// # Errors
///
/// Rejects unknown named shells and custom templates outside the published
/// fixed-argument grammar.
pub fn static_shell_requirement(value: &str) -> Result<RunnerFeature, StaticShellRequirementError> {
    let resolved = if value.contains("{0}") {
        command_template(value)
    } else {
        named_shell(value)
    }
    .map_err(|_| StaticShellRequirementError)?;
    match resolved {
        ResolvedShell::Named(shell)
        | ResolvedShell::CommandTemplate(SafeCommandTemplate { shell, .. }) => {
            Ok(shell.runner_feature())
        }
        ResolvedShell::Default => unreachable!("literal shell parsing never returns default"),
    }
}

pub(crate) struct SafeCommandTemplate {
    shell: ShellKind,
    arguments: Vec<String>,
}

impl SafeCommandTemplate {
    fn parse(value: &str) -> Result<Self, ExecutorAdapterError> {
        if value.is_empty()
            || value.trim() != value
            || value.chars().any(char::is_control)
            || value.contains("  ")
        {
            return Err(unsupported());
        }
        let parts = value.split(' ').collect::<Vec<_>>();
        if parts.len() < 2
            || parts.iter().filter(|part| **part == "{0}").count() != 1
            || parts.last() != Some(&"{0}")
            || parts[..parts.len() - 1]
                .iter()
                .any(|part| part.contains(['{', '}']))
        {
            return Err(unsupported());
        }
        let shell = ShellKind::parse(parts[0]).ok_or_else(unsupported)?;
        let arguments = &parts[1..parts.len() - 1];
        if !safe_template_arguments(shell, arguments) {
            return Err(unsupported());
        }
        Ok(Self {
            shell,
            arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
        })
    }
}

fn safe_template_arguments(shell: ShellKind, arguments: &[&str]) -> bool {
    match shell {
        ShellKind::Bash => matches!(
            arguments,
            [] | ["-e"]
                | ["--noprofile", "--norc", "-e", "-o", "pipefail"]
                | ["--noprofile", "--norc", "-eo", "pipefail"]
        ),
        ShellKind::Sh => matches!(arguments, [] | ["-e"]),
        ShellKind::Python => matches!(arguments, [] | ["-u"]),
        ShellKind::Pwsh | ShellKind::PowerShell => {
            matches!(arguments, [argument] if argument.eq_ignore_ascii_case("-file"))
        }
        ShellKind::Cmd => false,
    }
}

pub(crate) fn resolve_shell_template(
    shell: &ShellTemplate,
    mut resolve_value: impl FnMut(
        &ValueTemplate,
    ) -> Result<ResolvedEnvironmentValue, ExecutorAdapterError>,
) -> Result<ResolvedShell, ExecutorAdapterError> {
    match shell {
        ShellTemplate::Default => Ok(ResolvedShell::Default),
        ShellTemplate::Named { value } => {
            resolve_value(value).and_then(|value| named_shell(value.expose()))
        }
        ShellTemplate::CommandTemplate { value } => {
            resolve_value(value).and_then(|value| command_template(value.expose()))
        }
        ShellTemplate::Dynamic { value } => {
            let value = resolve_value(value)?;
            composite_shell(value.expose())
        }
    }
}

pub(crate) fn shell_argv(
    toolchain: &dyn GithubToolchain,
    shell: &ResolvedShell,
    script: &TargetPath,
) -> Result<(TargetPath, Vec<String>), ExecutorAdapterError> {
    if script.platform() != toolchain.platform() {
        return Err(invalid_job());
    }
    let script_path = script;
    let script = script.as_str().to_owned();
    match (toolchain.platform(), shell) {
        (TargetPlatform::Posix, ResolvedShell::Default) => Ok((
            toolchain
                .bash()
                .or_else(|| toolchain.sh())
                .cloned()
                .ok_or_else(unsupported)?,
            vec!["-e".into(), script],
        )),
        (TargetPlatform::Windows, ResolvedShell::Default) => Ok((
            toolchain
                .pwsh()
                .or_else(|| toolchain.powershell())
                .cloned()
                .ok_or_else(unsupported)?,
            windows_script_arguments(WindowsScriptShell::PowerShell, script_path)
                .ok_or_else(invalid_job)?,
        )),
        (TargetPlatform::Posix, ResolvedShell::Named(ShellKind::Bash)) => Ok((
            configured_tool(toolchain, ShellKind::Bash)?,
            vec![
                "--noprofile".into(),
                "--norc".into(),
                "-e".into(),
                "-o".into(),
                "pipefail".into(),
                script,
            ],
        )),
        (TargetPlatform::Posix, ResolvedShell::Named(ShellKind::Sh)) => Ok((
            configured_tool(toolchain, ShellKind::Sh)?,
            vec!["-e".into(), script],
        )),
        (TargetPlatform::Windows, ResolvedShell::Named(ShellKind::Python)) => Ok((
            configured_tool(toolchain, ShellKind::Python)?,
            windows_script_arguments(WindowsScriptShell::Python, script_path)
                .ok_or_else(invalid_job)?,
        )),
        (TargetPlatform::Posix, ResolvedShell::Named(ShellKind::Python)) => {
            Ok((configured_tool(toolchain, ShellKind::Python)?, vec![script]))
        }
        (TargetPlatform::Posix, ResolvedShell::Named(ShellKind::Pwsh)) => Ok((
            configured_tool(toolchain, ShellKind::Pwsh)?,
            powershell_arguments(&script),
        )),
        (TargetPlatform::Windows, ResolvedShell::Named(ShellKind::Pwsh)) => Ok((
            configured_tool(toolchain, ShellKind::Pwsh)?,
            windows_script_arguments(WindowsScriptShell::PowerShell, script_path)
                .ok_or_else(invalid_job)?,
        )),
        (TargetPlatform::Windows, ResolvedShell::Named(ShellKind::PowerShell)) => Ok((
            configured_tool(toolchain, ShellKind::PowerShell)?,
            windows_script_arguments(WindowsScriptShell::PowerShell, script_path)
                .ok_or_else(invalid_job)?,
        )),
        (TargetPlatform::Windows, ResolvedShell::Named(ShellKind::Cmd)) => Ok((
            configured_tool(toolchain, ShellKind::Cmd)?,
            windows_script_arguments(WindowsScriptShell::Cmd, script_path)
                .ok_or_else(invalid_job)?,
        )),
        (_, ResolvedShell::CommandTemplate(template))
            if shell_supported(toolchain.platform(), template.shell) =>
        {
            let program = configured_tool(toolchain, template.shell)?;
            let mut arguments = template.arguments.clone();
            arguments.push(script);
            Ok((program, arguments))
        }
        (_, ResolvedShell::Named(_) | ResolvedShell::CommandTemplate(_)) => Err(unsupported()),
    }
}

pub(crate) fn composite_shell(value: &str) -> Result<ResolvedShell, ExecutorAdapterError> {
    named_shell(value).or_else(|_| command_template(value))
}

fn named_shell(value: &str) -> Result<ResolvedShell, ExecutorAdapterError> {
    ShellKind::parse(value)
        .map(ResolvedShell::Named)
        .ok_or_else(unsupported)
}

fn command_template(value: &str) -> Result<ResolvedShell, ExecutorAdapterError> {
    SafeCommandTemplate::parse(value).map(ResolvedShell::CommandTemplate)
}

fn shell_supported(platform: TargetPlatform, shell: ShellKind) -> bool {
    matches!(
        (platform, shell),
        (
            TargetPlatform::Posix,
            ShellKind::Bash | ShellKind::Sh | ShellKind::Python | ShellKind::Pwsh
        ) | (
            TargetPlatform::Windows,
            ShellKind::Python | ShellKind::Pwsh | ShellKind::PowerShell | ShellKind::Cmd
        )
    )
}

fn configured_tool(
    toolchain: &dyn GithubToolchain,
    shell: ShellKind,
) -> Result<TargetPath, ExecutorAdapterError> {
    let path = match shell {
        ShellKind::Bash => toolchain.bash(),
        ShellKind::Sh => toolchain.sh(),
        ShellKind::Python => toolchain.python(),
        ShellKind::Pwsh => toolchain.pwsh(),
        ShellKind::PowerShell => toolchain.powershell(),
        ShellKind::Cmd => toolchain.cmd(),
    };
    path.cloned().ok_or_else(unsupported)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ShellAdmissionRejection {
    Invalid,
    MissingTool,
}

pub(crate) fn admit_shell_template(
    toolchain: &dyn GithubToolchain,
    shell: &ShellTemplate,
) -> Result<(), ShellAdmissionRejection> {
    let resolved = match shell {
        ShellTemplate::Default => ResolvedShell::Default,
        ShellTemplate::Named { value } => {
            let Some(value) = literal_template_value(value) else {
                return Ok(());
            };
            named_shell(value).map_err(|_| ShellAdmissionRejection::Invalid)?
        }
        ShellTemplate::CommandTemplate { value } => {
            let Some(value) = literal_template_value(value) else {
                return Ok(());
            };
            command_template(value).map_err(|_| ShellAdmissionRejection::Invalid)?
        }
        ShellTemplate::Dynamic { value } => {
            let Some(value) = literal_template_value(value) else {
                return Ok(());
            };
            composite_shell(value).map_err(|_| ShellAdmissionRejection::Invalid)?
        }
    };
    match resolved {
        ResolvedShell::Default => {
            let available = match toolchain.platform() {
                TargetPlatform::Posix => toolchain.bash().or_else(|| toolchain.sh()),
                TargetPlatform::Windows => toolchain.pwsh().or_else(|| toolchain.powershell()),
            };
            available
                .map(|_| ())
                .ok_or(ShellAdmissionRejection::MissingTool)
        }
        ResolvedShell::Named(shell)
        | ResolvedShell::CommandTemplate(SafeCommandTemplate { shell, .. }) => {
            if !shell_supported(toolchain.platform(), shell) {
                return Err(ShellAdmissionRejection::Invalid);
            }
            configured_tool(toolchain, shell)
                .map(|_| ())
                .map_err(|_| ShellAdmissionRejection::MissingTool)
        }
    }
}

fn literal_template_value(value: &ValueTemplate) -> Option<&str> {
    let [segment] = value.segments() else {
        return None;
    };
    segment.literal_value()
}

const fn unsupported() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::Unsupported)
}

const fn invalid_job() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)
}

fn powershell_arguments(script: &str) -> Vec<String> {
    let script = script.replace('\'', "''");
    vec!["-command".into(), format!(". '{script}'")]
}

/// Supported Windows script-interpreter argument contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsScriptShell {
    /// PowerShell Core or Windows PowerShell dot-sourcing a `.ps1` file.
    PowerShell,
    /// `cmd.exe` executing a `.cmd` file with expansion policy fixed explicitly.
    Cmd,
    /// Python executing a `.py` file by its exact absolute target path.
    Python,
}

/// Builds the exact argument vector used to execute one Windows script file.
///
/// Returns `None` for a non-Windows target or when a `cmd.exe` script path
/// contains quote, percent-expansion, or active command-metacharacter syntax
/// that the command interpreter could reinterpret before opening the intended
/// file. `!` remains literal because the argument contract forces `/V:OFF`.
#[must_use]
pub fn windows_script_arguments(
    shell: WindowsScriptShell,
    script: &TargetPath,
) -> Option<Vec<String>> {
    if script.platform() != TargetPlatform::Windows {
        return None;
    }
    let script = script.as_str();
    match shell {
        WindowsScriptShell::PowerShell => Some(powershell_arguments(script)),
        WindowsScriptShell::Cmd
            if !script.contains(['"', '%', '&', '|', '<', '>', '^', '(', ')']) =>
        {
            Some(vec![
                "/D".into(),
                "/E:ON".into(),
                "/V:OFF".into(),
                "/C".into(),
                script.to_owned(),
            ])
        }
        WindowsScriptShell::Cmd => None,
        WindowsScriptShell::Python => Some(vec![script.to_owned()]),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use automata_ci_action_github::JavascriptRuntime;
    use automata_ci_core::{ShellTemplate, ValueTemplate};
    use automata_ci_execution::{ExecutionArgv, TargetPath, TargetPlatform};
    use static_assertions::assert_not_impl_any;

    use crate::{
        adapter::StaticGithubToolchain,
        environment::ResolvedEnvironmentValue,
        error::{ExecutorAdapterError, ExecutorAdapterErrorKind},
        port::GithubToolchain,
    };

    use super::{
        ResolvedShell, ShellAdmissionRejection, ShellKind, WindowsScriptShell,
        admit_shell_template, command_template, composite_shell, named_shell,
        resolve_shell_template, shell_argv, windows_script_arguments,
    };

    assert_not_impl_any!(ResolvedShell: std::fmt::Debug, std::fmt::Display);

    #[test]
    fn shell_resolution_uses_the_bounded_value_callback() {
        let mut default_callback_called = false;
        let default = resolve_shell_template(&ShellTemplate::Default, |_| {
            default_callback_called = true;
            Ok(ResolvedEnvironmentValue::plain("unused"))
        })
        .expect("default shell");
        assert!(matches!(default, ResolvedShell::Default));
        assert!(!default_callback_called);

        let named = resolve_shell_template(
            &ShellTemplate::named(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::secret("BASH")),
        )
        .expect("named shell");
        assert!(matches!(named, ResolvedShell::Named(ShellKind::Bash)));

        let command = resolve_shell_template(
            &ShellTemplate::command_template(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::plain("bash -e {0}")),
        )
        .expect("command template");
        assert!(matches!(
            command,
            ResolvedShell::CommandTemplate(template)
                if template.shell == ShellKind::Bash
                    && template.arguments == ["-e"]
        ));

        let dynamic = resolve_shell_template(
            &ShellTemplate::dynamic(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::secret("PwSh")),
        )
        .expect("dynamic built-in");
        assert!(matches!(dynamic, ResolvedShell::Named(ShellKind::Pwsh)));

        let dynamic_template = resolve_shell_template(
            &ShellTemplate::dynamic(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::plain("sh -e {0}")),
        )
        .expect("dynamic command template");
        assert!(matches!(
            dynamic_template,
            ResolvedShell::CommandTemplate(template)
                if template.shell == ShellKind::Sh
                    && template.arguments == ["-e"]
        ));

        let unsupported = resolve_shell_template(
            &ShellTemplate::dynamic(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::secret("perl {0}")),
        )
        .err()
        .expect("unsupported dynamic shell");
        assert_eq!(unsupported.kind(), ExecutorAdapterErrorKind::Unsupported);

        let resolver_error = resolve_shell_template(
            &ShellTemplate::named(ValueTemplate::literal("ignored").expect("template")),
            |_| {
                Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Unavailable,
                ))
            },
        )
        .err()
        .expect("resolver failure");
        assert_eq!(resolver_error.kind(), ExecutorAdapterErrorKind::Unavailable);
    }

    #[test]
    fn script_extensions_cover_platform_defaults_and_named_shells() {
        let cases = [
            (ResolvedShell::Default, TargetPlatform::Posix, ".sh"),
            (ResolvedShell::Default, TargetPlatform::Windows, ".ps1"),
            (named("PYTHON"), TargetPlatform::Posix, ".py"),
            (named("pwsh"), TargetPlatform::Windows, ".ps1"),
            (named("PowerShell"), TargetPlatform::Posix, ".ps1"),
            (named("CMD"), TargetPlatform::Windows, ".cmd"),
            (named("bash"), TargetPlatform::Windows, ".sh"),
            (custom("bash -e {0}"), TargetPlatform::Posix, ".sh"),
        ];

        for (shell, platform, expected) in cases {
            assert_eq!(shell.script_extension(platform), expected);
        }
    }

    #[test]
    fn script_fixups_preserve_exact_powershell_cmd_and_passthrough_contracts() {
        let command = "printf '%s\\n' ok";
        let unchanged = ResolvedShell::Default.fix_up_script(TargetPlatform::Posix, command);
        assert!(matches!(unchanged, Cow::Borrowed(_)));
        assert_eq!(unchanged, command);

        let powershell = ResolvedShell::Default
            .fix_up_script(TargetPlatform::Windows, "Write-Host ok")
            .into_owned();
        assert_eq!(
            powershell,
            "$ErrorActionPreference = 'stop'\r\nWrite-Host ok\r\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
        );

        let named_powershell = named("PwSh")
            .fix_up_script(TargetPlatform::Posix, "exit 7")
            .into_owned();
        assert_eq!(
            named_powershell,
            "$ErrorActionPreference = 'stop'\nexit 7\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
        );

        let cmd = named("cmd")
            .fix_up_script(TargetPlatform::Windows, "one\r\ntwo\rthree\nfour")
            .into_owned();
        assert_eq!(cmd, "@echo off\r\none\r\ntwo\rthree\r\nfour");

        let python = named("python")
            .fix_up_script(TargetPlatform::Windows, "one\ntwo\r\nthree")
            .into_owned();
        assert_eq!(python, "one\r\ntwo\r\nthree");
    }

    #[test]
    fn posix_shell_argv_uses_only_configured_tools_and_exact_arguments() {
        let toolchain = posix_toolchain();
        let script = TargetPath::posix("/work root/[literal]$script;.sh").expect("script");
        let cases = vec![
            (
                ResolvedShell::Default,
                "/bin/bash",
                vec!["-e", "/work root/[literal]$script;.sh"],
            ),
            (
                named("BASH"),
                "/bin/bash",
                vec![
                    "--noprofile",
                    "--norc",
                    "-e",
                    "-o",
                    "pipefail",
                    "/work root/[literal]$script;.sh",
                ],
            ),
            (
                named("sh"),
                "/bin/sh",
                vec!["-e", "/work root/[literal]$script;.sh"],
            ),
            (
                named("python"),
                "/usr/bin/python3",
                vec!["/work root/[literal]$script;.sh"],
            ),
            (
                named("pwsh"),
                "/usr/bin/pwsh",
                vec!["-command", ". '/work root/[literal]$script;.sh'"],
            ),
            (
                custom("bash -e {0}"),
                "/bin/bash",
                vec!["-e", "/work root/[literal]$script;.sh"],
            ),
            (
                custom("bash --noprofile --norc -eo pipefail {0}"),
                "/bin/bash",
                vec![
                    "--noprofile",
                    "--norc",
                    "-eo",
                    "pipefail",
                    "/work root/[literal]$script;.sh",
                ],
            ),
            (
                custom("sh -e {0}"),
                "/bin/sh",
                vec!["-e", "/work root/[literal]$script;.sh"],
            ),
            (
                custom("python -u {0}"),
                "/usr/bin/python3",
                vec!["-u", "/work root/[literal]$script;.sh"],
            ),
            (
                custom("pwsh -File {0}"),
                "/usr/bin/pwsh",
                vec!["-File", "/work root/[literal]$script;.sh"],
            ),
        ];

        for (shell, expected_program, expected_arguments) in cases {
            let (program, arguments) =
                shell_argv(&toolchain, &shell, &script).expect("supported shell");
            assert_eq!(program.as_str(), expected_program);
            assert_eq!(
                arguments.iter().map(String::as_str).collect::<Vec<_>>(),
                expected_arguments
            );
        }
    }

    #[test]
    fn windows_shell_argv_uses_exact_interpreter_contracts() {
        let toolchain = windows_toolchain();
        let script =
            TargetPath::windows(r"C:\work root\it's [literal] ! script.ps1").expect("script");
        let cases = vec![
            (
                ResolvedShell::Default,
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                vec![
                    "-command",
                    ". 'C:\\work root\\it''s [literal] ! script.ps1'",
                ],
            ),
            (
                named("pwsh"),
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                vec![
                    "-command",
                    ". 'C:\\work root\\it''s [literal] ! script.ps1'",
                ],
            ),
            (
                named("PowerShell"),
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                vec![
                    "-command",
                    ". 'C:\\work root\\it''s [literal] ! script.ps1'",
                ],
            ),
            (
                named("python"),
                r"C:\Python\python.exe",
                vec![r"C:\work root\it's [literal] ! script.ps1"],
            ),
            (
                custom("python -u {0}"),
                r"C:\Python\python.exe",
                vec!["-u", r"C:\work root\it's [literal] ! script.ps1"],
            ),
            (
                custom("pwsh -File {0}"),
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                vec!["-File", r"C:\work root\it's [literal] ! script.ps1"],
            ),
        ];

        for (shell, expected_program, expected_arguments) in cases {
            let (program, arguments) =
                shell_argv(&toolchain, &shell, &script).expect("supported shell");
            assert_eq!(program.as_str(), expected_program);
            assert_eq!(
                arguments.iter().map(String::as_str).collect::<Vec<_>>(),
                expected_arguments
            );
        }

        let cmd_script = TargetPath::windows(r"C:\work root\literal! script.cmd").expect("script");
        let (program, arguments) =
            shell_argv(&toolchain, &named("cmd"), &cmd_script).expect("cmd shell");
        assert_eq!(program.as_str(), r"C:\Windows\System32\cmd.exe");
        assert_eq!(
            arguments,
            [
                "/D",
                "/E:ON",
                "/V:OFF",
                "/C",
                r"C:\work root\literal! script.cmd"
            ]
        );
    }

    #[test]
    fn default_shells_fall_back_only_to_the_pinned_platform_interpreter() {
        let posix = TestToolchain {
            platform: TargetPlatform::Posix,
            sh: Some(TargetPath::posix("/bin/sh").expect("sh")),
            ..TestToolchain::empty(TargetPlatform::Posix)
        };
        let posix_script = TargetPath::posix("/work/default.sh").expect("script");
        let (program, arguments) =
            shell_argv(&posix, &ResolvedShell::Default, &posix_script).expect("sh fallback");
        assert_eq!(program.as_str(), "/bin/sh");
        assert_eq!(arguments, ["-e", "/work/default.sh"]);

        let windows = TestToolchain {
            platform: TargetPlatform::Windows,
            powershell: Some(
                TargetPath::windows(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                    .expect("PowerShell"),
            ),
            ..TestToolchain::empty(TargetPlatform::Windows)
        };
        let windows_script = TargetPath::windows(r"C:\work\default.ps1").expect("script");
        let (program, arguments) = shell_argv(&windows, &ResolvedShell::Default, &windows_script)
            .expect("Windows PowerShell fallback");
        assert_eq!(
            program.as_str(),
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        assert_eq!(arguments, ["-command", ". 'C:\\work\\default.ps1'"]);
    }

    #[test]
    fn configured_executable_and_script_paths_remain_literal_argv_values() {
        let toolchain = TestToolchain {
            platform: TargetPlatform::Posix,
            bash: Some(
                TargetPath::posix("/opt/runner tools/bash$literal").expect("literal Bash path"),
            ),
            ..TestToolchain::empty(TargetPlatform::Posix)
        };
        let script =
            TargetPath::posix("/work root/$(not-executed);script.sh").expect("literal script path");
        let (program, arguments) = shell_argv(&toolchain, &named("bash"), &script)
            .expect("configured literal paths are valid");

        assert_eq!(program.as_str(), "/opt/runner tools/bash$literal");
        assert_eq!(
            arguments,
            [
                "--noprofile",
                "--norc",
                "-e",
                "-o",
                "pipefail",
                "/work root/$(not-executed);script.sh",
            ]
        );
    }

    #[test]
    fn shell_argv_fails_closed_for_missing_tools_and_unsupported_contracts() {
        let minimal = StaticGithubToolchain::new(
            TargetPath::posix("/bin/bash").expect("bash"),
            TargetPath::posix("/bin/sh").expect("sh"),
            TargetPath::posix("/usr/bin/install").expect("install"),
            TargetPath::posix("/bin/tar").expect("tar"),
            TargetPath::posix("/usr/bin/sha256sum").expect("sha256sum"),
        )
        .expect("toolchain");
        let posix_script = TargetPath::posix("/work/script.sh").expect("script");
        let missing =
            shell_argv(&minimal, &named("python"), &posix_script).expect_err("missing Python");
        assert_eq!(missing.kind(), ExecutorAdapterErrorKind::Unsupported);

        for shell in [named("powershell"), named("cmd")] {
            let error = shell_argv(&minimal, &shell, &posix_script)
                .expect_err("unsupported POSIX shell contract");
            assert_eq!(error.kind(), ExecutorAdapterErrorKind::Unsupported);
        }

        let windows = windows_toolchain();
        let windows_script = TargetPath::windows(r"C:\work\script.ps1").expect("script");
        let command_template = shell_argv(&windows, &custom("bash -e {0}"), &windows_script)
            .expect_err("Windows command templates are unsupported");
        assert_eq!(
            command_template.kind(),
            ExecutorAdapterErrorKind::Unsupported
        );

        let unsafe_cmd = TargetPath::windows(r"C:\work%PATH%\script.cmd").expect("valid path");
        let unsafe_path = shell_argv(&windows, &named("cmd"), &unsafe_cmd)
            .expect_err("cmd metacharacters must fail closed");
        assert_eq!(unsafe_path.kind(), ExecutorAdapterErrorKind::InvalidJob);
    }

    #[test]
    fn windows_script_arguments_preserve_exact_production_quoting_and_cmd_flags() {
        let powershell_script =
            TargetPath::windows(r"C:\runner root\it's probe.ps1").expect("PowerShell script");
        assert_eq!(
            windows_script_arguments(WindowsScriptShell::PowerShell, &powershell_script),
            Some(vec![
                "-command".to_owned(),
                ". 'C:\\runner root\\it''s probe.ps1'".to_owned(),
            ])
        );

        let cmd_script =
            TargetPath::windows(r"C:\runner root\probe script.cmd").expect("cmd script");
        assert_eq!(
            windows_script_arguments(WindowsScriptShell::Cmd, &cmd_script),
            Some(vec![
                "/D".to_owned(),
                "/E:ON".to_owned(),
                "/V:OFF".to_owned(),
                "/C".to_owned(),
                r"C:\runner root\probe script.cmd".to_owned(),
            ])
        );
        let python_script =
            TargetPath::windows(r"C:\runner root\probe script.py").expect("Python script");
        assert_eq!(
            windows_script_arguments(WindowsScriptShell::Python, &python_script),
            Some(vec![r"C:\runner root\probe script.py".to_owned()])
        );

        for metacharacter in ['%', '&', '^', '(', ')'] {
            let unsafe_script = TargetPath::windows(format!(r"C:\runner{metacharacter}\probe.cmd"))
                .expect("filesystem-valid Windows path");
            assert_eq!(
                windows_script_arguments(WindowsScriptShell::Cmd, &unsafe_script),
                None,
                "cmd metacharacter {metacharacter:?} must fail closed"
            );
        }
        for metacharacter in ['"', '|', '<', '>'] {
            assert!(
                TargetPath::windows(format!(r"C:\runner{metacharacter}\probe.cmd")).is_err(),
                "filesystem-invalid Windows metacharacter {metacharacter:?} must fail closed"
            );
        }
        let literal_bang =
            TargetPath::windows(r"C:\runner!literal\probe.cmd").expect("literal bang path");
        assert_eq!(
            windows_script_arguments(WindowsScriptShell::Cmd, &literal_bang),
            Some(vec![
                "/D".to_owned(),
                "/E:ON".to_owned(),
                "/V:OFF".to_owned(),
                "/C".to_owned(),
                r"C:\runner!literal\probe.cmd".to_owned(),
            ])
        );
        let posix = TargetPath::posix("/runner/probe.ps1").expect("POSIX path");
        assert_eq!(
            windows_script_arguments(WindowsScriptShell::PowerShell, &posix),
            None
        );
    }

    #[test]
    fn composite_shell_accepts_builtin_names_and_the_closed_template_grammar() {
        for (input, expected) in [
            ("BASH", ShellKind::Bash),
            ("sh", ShellKind::Sh),
            ("Python", ShellKind::Python),
            ("pwsh", ShellKind::Pwsh),
            ("PowerShell", ShellKind::PowerShell),
            ("CMD", ShellKind::Cmd),
        ] {
            let shell = composite_shell(input).expect("built-in shell");
            assert!(matches!(shell, ResolvedShell::Named(kind) if kind == expected));
        }
        for template in [
            "bash {0}",
            "bash -e {0}",
            "bash --noprofile --norc -e -o pipefail {0}",
            "bash --noprofile --norc -eo pipefail {0}",
            "sh {0}",
            "sh -e {0}",
            "python {0}",
            "python -u {0}",
            "pwsh -File {0}",
            "powershell -file {0}",
        ] {
            let shell = composite_shell(template).expect("configured command template");
            assert!(matches!(shell, ResolvedShell::CommandTemplate(_)));
        }
    }

    #[test]
    fn composite_shell_rejects_ambiguous_or_injectable_templates() {
        for unsupported in [
            "",
            " BASH ",
            "perl {0}",
            "bash -e",
            "bash {0} {0}",
            "bash prefix{0}",
            "bash '{0}'",
            "bash \"{0}\"",
            "bash -c {0}",
            "python -c {0}",
            "pwsh -Command {0}",
            "cmd /C {0}",
            "bash -e {0};touch",
            "bash  -e {0}",
            "bash\t-e {0}",
            "bash\n-e {0}",
            "bash -e {1}",
            "C:\\Program Files\\Git\\bin\\bash.exe {0}",
        ] {
            let error = composite_shell(unsupported)
                .err()
                .expect("unsupported composite shell");
            assert_eq!(error.kind(), ExecutorAdapterErrorKind::Unsupported);
        }
    }

    #[test]
    fn static_shell_admission_distinguishes_invalid_contracts_and_missing_tools() {
        let posix = TestToolchain::empty(TargetPlatform::Posix);
        assert!(matches!(
            admit_shell_template(&posix, &ShellTemplate::Default),
            Err(ShellAdmissionRejection::MissingTool)
        ));
        assert!(matches!(
            admit_shell_template(
                &posix,
                &ShellTemplate::named(ValueTemplate::literal("python").expect("template")),
            ),
            Err(ShellAdmissionRejection::MissingTool)
        ));
        assert!(matches!(
            admit_shell_template(
                &posix,
                &ShellTemplate::named(ValueTemplate::literal("cmd").expect("template")),
            ),
            Err(ShellAdmissionRejection::Invalid)
        ));
        assert!(matches!(
            admit_shell_template(
                &posix,
                &ShellTemplate::command_template(
                    ValueTemplate::literal("bash -c {0}").expect("template"),
                ),
            ),
            Err(ShellAdmissionRejection::Invalid)
        ));

        let sh_only = TestToolchain {
            platform: TargetPlatform::Posix,
            sh: Some(TargetPath::posix("/bin/sh").expect("sh")),
            ..TestToolchain::empty(TargetPlatform::Posix)
        };
        assert!(admit_shell_template(&sh_only, &ShellTemplate::Default).is_ok());
    }

    fn named(value: &str) -> ResolvedShell {
        named_shell(value).expect("known named shell")
    }

    fn custom(value: &str) -> ResolvedShell {
        command_template(value).expect("safe command template")
    }

    fn posix_toolchain() -> StaticGithubToolchain {
        StaticGithubToolchain::new(
            TargetPath::posix("/bin/bash").expect("bash"),
            TargetPath::posix("/bin/sh").expect("sh"),
            TargetPath::posix("/usr/bin/install").expect("install"),
            TargetPath::posix("/bin/tar").expect("tar"),
            TargetPath::posix("/usr/bin/sha256sum").expect("sha256sum"),
        )
        .expect("toolchain")
        .with_python(TargetPath::posix("/usr/bin/python3").expect("python"))
        .expect("Python")
        .with_pwsh(TargetPath::posix("/usr/bin/pwsh").expect("pwsh"))
        .expect("PowerShell Core")
    }

    fn windows_toolchain() -> StaticGithubToolchain {
        StaticGithubToolchain::windows(
            TargetPath::windows(r"C:\Program Files\PowerShell\7\pwsh.exe").expect("pwsh"),
            TargetPath::windows(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                .expect("PowerShell"),
            TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("cmd"),
        )
        .expect("toolchain")
        .with_python(TargetPath::windows(r"C:\Python\python.exe").expect("python"))
        .expect("Python")
    }

    #[derive(Debug)]
    struct TestToolchain {
        platform: TargetPlatform,
        bash: Option<TargetPath>,
        sh: Option<TargetPath>,
        python: Option<TargetPath>,
        pwsh: Option<TargetPath>,
        powershell: Option<TargetPath>,
        cmd: Option<TargetPath>,
    }

    impl TestToolchain {
        const fn empty(platform: TargetPlatform) -> Self {
            Self {
                platform,
                bash: None,
                sh: None,
                python: None,
                pwsh: None,
                powershell: None,
                cmd: None,
            }
        }
    }

    impl GithubToolchain for TestToolchain {
        fn platform(&self) -> TargetPlatform {
            self.platform
        }

        fn bash(&self) -> Option<&TargetPath> {
            self.bash.as_ref()
        }

        fn sh(&self) -> Option<&TargetPath> {
            self.sh.as_ref()
        }

        fn python(&self) -> Option<&TargetPath> {
            self.python.as_ref()
        }

        fn pwsh(&self) -> Option<&TargetPath> {
            self.pwsh.as_ref()
        }

        fn powershell(&self) -> Option<&TargetPath> {
            self.powershell.as_ref()
        }

        fn cmd(&self) -> Option<&TargetPath> {
            self.cmd.as_ref()
        }

        fn install(&self) -> Option<&TargetPath> {
            None
        }

        fn tar(&self) -> Option<&TargetPath> {
            None
        }

        fn sha256(&self) -> Option<&ExecutionArgv> {
            None
        }

        fn node(&self, _runtime: JavascriptRuntime) -> Option<&TargetPath> {
            None
        }
    }
}
