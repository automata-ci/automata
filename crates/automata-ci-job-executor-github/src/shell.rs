use std::borrow::Cow;

use automata_ci_core::{ShellTemplate, ValueTemplate};
use automata_ci_execution::{TargetPath, TargetPlatform};

use crate::{
    environment::ResolvedEnvironmentValue,
    error::{ExecutorAdapterError, ExecutorAdapterErrorKind},
    port::GithubToolchain,
};

pub(crate) enum ResolvedShell {
    Default,
    Named(String),
    CommandTemplate(String),
}

impl ResolvedShell {
    pub(crate) fn script_extension(&self, platform: TargetPlatform) -> &'static str {
        match self {
            Self::Named(name) if name.eq_ignore_ascii_case("python") => ".py",
            Self::Named(name)
                if name.eq_ignore_ascii_case("pwsh") || name.eq_ignore_ascii_case("powershell") =>
            {
                ".ps1"
            }
            Self::Named(name) if name.eq_ignore_ascii_case("cmd") => ".cmd",
            Self::Default if platform == TargetPlatform::Windows => ".ps1",
            Self::Default | Self::Named(_) | Self::CommandTemplate(_) => ".sh",
        }
    }

    pub(crate) fn fix_up_script<'command>(
        &self,
        platform: TargetPlatform,
        command: &'command str,
    ) -> Cow<'command, str> {
        let is_powershell = matches!(self, Self::Named(name) if name.eq_ignore_ascii_case("pwsh") || name.eq_ignore_ascii_case("powershell"))
            || matches!(self, Self::Default if platform == TargetPlatform::Windows);
        if is_powershell {
            Cow::Owned(format!(
                "$ErrorActionPreference = 'stop'\n{command}\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) {{ exit $LASTEXITCODE }}"
            ))
        } else if platform == TargetPlatform::Windows
            && matches!(self, Self::Named(name) if name.eq_ignore_ascii_case("cmd"))
        {
            let mut normalized = command
                .replace("\r\n", "\n")
                .replace('\r', "\n")
                .replace('\n', "\r\n");
            if !normalized.ends_with("\r\n") {
                normalized.push_str("\r\n");
            }
            Cow::Owned(normalized)
        } else {
            Cow::Borrowed(command)
        }
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
            resolve_value(value).map(|value| ResolvedShell::Named(value.into_value()))
        }
        ShellTemplate::CommandTemplate { value } => {
            resolve_value(value).map(|value| ResolvedShell::CommandTemplate(value.into_value()))
        }
        ShellTemplate::Dynamic { value } => {
            let value = resolve_value(value)?;
            composite_shell(value.expose())
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn shell_argv(
    toolchain: &dyn GithubToolchain,
    shell: &ResolvedShell,
    script: &TargetPath,
) -> Result<(TargetPath, Vec<String>), ExecutorAdapterError> {
    let script_path = script;
    let script = script.as_str().to_owned();
    match (toolchain.platform(), shell) {
        (TargetPlatform::Posix, ResolvedShell::Default) => {
            Ok((required_tool(toolchain.bash())?, vec!["-e".into(), script]))
        }
        (TargetPlatform::Posix, ResolvedShell::Named(name))
            if name.eq_ignore_ascii_case("bash") =>
        {
            Ok((
                required_tool(toolchain.bash())?,
                vec![
                    "--noprofile".into(),
                    "--norc".into(),
                    "-e".into(),
                    "-o".into(),
                    "pipefail".into(),
                    script,
                ],
            ))
        }
        (TargetPlatform::Posix, ResolvedShell::Named(name)) if name.eq_ignore_ascii_case("sh") => {
            Ok((required_tool(toolchain.sh())?, vec!["-e".into(), script]))
        }
        (TargetPlatform::Windows, ResolvedShell::Named(name))
            if name.eq_ignore_ascii_case("python") =>
        {
            Ok((
                required_tool(toolchain.python())?,
                windows_script_arguments(WindowsScriptShell::Python, script_path)
                    .ok_or_else(invalid_job)?,
            ))
        }
        (TargetPlatform::Posix, ResolvedShell::Named(name))
            if name.eq_ignore_ascii_case("python") =>
        {
            Ok((required_tool(toolchain.python())?, vec![script]))
        }
        (TargetPlatform::Posix, ResolvedShell::Named(name))
            if name.eq_ignore_ascii_case("pwsh") =>
        {
            Ok((
                required_tool(toolchain.pwsh())?,
                powershell_arguments(&script),
            ))
        }
        (TargetPlatform::Windows, ResolvedShell::Default) => Ok((
            required_tool(toolchain.pwsh())?,
            windows_script_arguments(WindowsScriptShell::PowerShell, script_path)
                .ok_or_else(invalid_job)?,
        )),
        (TargetPlatform::Windows, ResolvedShell::Named(name))
            if name.eq_ignore_ascii_case("pwsh") =>
        {
            Ok((
                required_tool(toolchain.pwsh())?,
                windows_script_arguments(WindowsScriptShell::PowerShell, script_path)
                    .ok_or_else(invalid_job)?,
            ))
        }
        (TargetPlatform::Windows, ResolvedShell::Named(name))
            if name.eq_ignore_ascii_case("powershell") =>
        {
            Ok((
                required_tool(toolchain.powershell())?,
                windows_script_arguments(WindowsScriptShell::PowerShell, script_path)
                    .ok_or_else(invalid_job)?,
            ))
        }
        (TargetPlatform::Windows, ResolvedShell::Named(name))
            if name.eq_ignore_ascii_case("cmd") =>
        {
            Ok((
                required_tool(toolchain.cmd())?,
                windows_script_arguments(WindowsScriptShell::Cmd, script_path)
                    .ok_or_else(invalid_job)?,
            ))
        }
        (TargetPlatform::Posix, ResolvedShell::CommandTemplate(template))
            if template == "bash -e {0}" =>
        {
            Ok((required_tool(toolchain.bash())?, vec!["-e".into(), script]))
        }
        (TargetPlatform::Posix, ResolvedShell::CommandTemplate(template))
            if template == "bash --noprofile --norc -eo pipefail {0}" =>
        {
            Ok((
                required_tool(toolchain.bash())?,
                vec![
                    "--noprofile".into(),
                    "--norc".into(),
                    "-eo".into(),
                    "pipefail".into(),
                    script,
                ],
            ))
        }
        (TargetPlatform::Posix, ResolvedShell::CommandTemplate(template))
            if template == "sh -e {0}" =>
        {
            Ok((required_tool(toolchain.sh())?, vec!["-e".into(), script]))
        }
        (_, ResolvedShell::Named(_) | ResolvedShell::CommandTemplate(_)) => Err(
            ExecutorAdapterError::new(ExecutorAdapterErrorKind::Unsupported),
        ),
    }
}

pub(crate) fn composite_shell(value: &str) -> Result<ResolvedShell, ExecutorAdapterError> {
    let value = value.trim();
    if ["bash", "sh", "python", "pwsh", "powershell", "cmd"]
        .into_iter()
        .any(|name| value.eq_ignore_ascii_case(name))
    {
        return Ok(ResolvedShell::Named(value.to_ascii_lowercase()));
    }
    match value {
        "bash -e {0}" | "bash --noprofile --norc -eo pipefail {0}" | "sh -e {0}" => {
            Ok(ResolvedShell::CommandTemplate(value.to_owned()))
        }
        _ => Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::Unsupported,
        )),
    }
}

fn required_tool(path: Option<&TargetPath>) -> Result<TargetPath, ExecutorAdapterError> {
    path.cloned()
        .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Unsupported))
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

    use automata_ci_core::{ShellTemplate, ValueTemplate};
    use automata_ci_execution::{TargetPath, TargetPlatform};
    use static_assertions::assert_not_impl_any;

    use crate::{
        adapter::StaticGithubToolchain,
        environment::ResolvedEnvironmentValue,
        error::{ExecutorAdapterError, ExecutorAdapterErrorKind},
    };

    use super::{
        ResolvedShell, WindowsScriptShell, composite_shell, resolve_shell_template, shell_argv,
        windows_script_arguments,
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
        assert!(matches!(named, ResolvedShell::Named(name) if name == "BASH"));

        let command = resolve_shell_template(
            &ShellTemplate::command_template(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::plain("bash -e {0}")),
        )
        .expect("command template");
        assert!(matches!(
            command,
            ResolvedShell::CommandTemplate(template) if template == "bash -e {0}"
        ));

        let dynamic = resolve_shell_template(
            &ShellTemplate::dynamic(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::secret("  PwSh  ")),
        )
        .expect("dynamic built-in");
        assert!(matches!(dynamic, ResolvedShell::Named(name) if name == "pwsh"));

        let dynamic_template = resolve_shell_template(
            &ShellTemplate::dynamic(ValueTemplate::literal("ignored").expect("template")),
            |_| Ok(ResolvedEnvironmentValue::plain("sh -e {0}")),
        )
        .expect("dynamic command template");
        assert!(matches!(
            dynamic_template,
            ResolvedShell::CommandTemplate(template) if template == "sh -e {0}"
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
            (
                ResolvedShell::Named("PYTHON".to_owned()),
                TargetPlatform::Posix,
                ".py",
            ),
            (
                ResolvedShell::Named("pwsh".to_owned()),
                TargetPlatform::Windows,
                ".ps1",
            ),
            (
                ResolvedShell::Named("PowerShell".to_owned()),
                TargetPlatform::Posix,
                ".ps1",
            ),
            (
                ResolvedShell::Named("CMD".to_owned()),
                TargetPlatform::Windows,
                ".cmd",
            ),
            (
                ResolvedShell::Named("bash".to_owned()),
                TargetPlatform::Windows,
                ".sh",
            ),
            (
                ResolvedShell::CommandTemplate("bash -e {0}".to_owned()),
                TargetPlatform::Posix,
                ".sh",
            ),
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
            "$ErrorActionPreference = 'stop'\nWrite-Host ok\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
        );

        let named_powershell = ResolvedShell::Named("PwSh".to_owned())
            .fix_up_script(TargetPlatform::Posix, "exit 7")
            .into_owned();
        assert_eq!(
            named_powershell,
            "$ErrorActionPreference = 'stop'\nexit 7\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
        );

        let cmd = ResolvedShell::Named("cmd".to_owned())
            .fix_up_script(TargetPlatform::Windows, "one\r\ntwo\rthree\nfour")
            .into_owned();
        assert_eq!(cmd, "one\r\ntwo\r\nthree\r\nfour\r\n");
    }

    #[test]
    fn posix_shell_argv_uses_only_configured_tools_and_exact_arguments() {
        let toolchain = posix_toolchain();
        let script = TargetPath::posix("/work/script.sh").expect("script");
        let cases = vec![
            (
                ResolvedShell::Default,
                "/bin/bash",
                vec!["-e", "/work/script.sh"],
            ),
            (
                ResolvedShell::Named("BASH".to_owned()),
                "/bin/bash",
                vec![
                    "--noprofile",
                    "--norc",
                    "-e",
                    "-o",
                    "pipefail",
                    "/work/script.sh",
                ],
            ),
            (
                ResolvedShell::Named("sh".to_owned()),
                "/bin/sh",
                vec!["-e", "/work/script.sh"],
            ),
            (
                ResolvedShell::Named("python".to_owned()),
                "/usr/bin/python3",
                vec!["/work/script.sh"],
            ),
            (
                ResolvedShell::Named("pwsh".to_owned()),
                "/usr/bin/pwsh",
                vec!["-command", ". '/work/script.sh'"],
            ),
            (
                ResolvedShell::CommandTemplate("bash -e {0}".to_owned()),
                "/bin/bash",
                vec!["-e", "/work/script.sh"],
            ),
            (
                ResolvedShell::CommandTemplate(
                    "bash --noprofile --norc -eo pipefail {0}".to_owned(),
                ),
                "/bin/bash",
                vec![
                    "--noprofile",
                    "--norc",
                    "-eo",
                    "pipefail",
                    "/work/script.sh",
                ],
            ),
            (
                ResolvedShell::CommandTemplate("sh -e {0}".to_owned()),
                "/bin/sh",
                vec!["-e", "/work/script.sh"],
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
        let script = TargetPath::windows(r"C:\work root\script.ps1").expect("script");
        let cases = vec![
            (
                ResolvedShell::Default,
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                vec!["-command", ". 'C:\\work root\\script.ps1'"],
            ),
            (
                ResolvedShell::Named("pwsh".to_owned()),
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                vec!["-command", ". 'C:\\work root\\script.ps1'"],
            ),
            (
                ResolvedShell::Named("PowerShell".to_owned()),
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                vec!["-command", ". 'C:\\work root\\script.ps1'"],
            ),
            (
                ResolvedShell::Named("cmd".to_owned()),
                r"C:\Windows\System32\cmd.exe",
                vec!["/D", "/E:ON", "/V:OFF", "/C", r"C:\work root\script.ps1"],
            ),
            (
                ResolvedShell::Named("python".to_owned()),
                r"C:\Python\python.exe",
                vec![r"C:\work root\script.ps1"],
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
        let missing = shell_argv(
            &minimal,
            &ResolvedShell::Named("python".to_owned()),
            &posix_script,
        )
        .expect_err("missing Python");
        assert_eq!(missing.kind(), ExecutorAdapterErrorKind::Unsupported);

        for shell in [
            ResolvedShell::Named("powershell".to_owned()),
            ResolvedShell::Named("cmd".to_owned()),
            ResolvedShell::CommandTemplate("bash {0}".to_owned()),
        ] {
            let error = shell_argv(&minimal, &shell, &posix_script)
                .expect_err("unsupported POSIX shell contract");
            assert_eq!(error.kind(), ExecutorAdapterErrorKind::Unsupported);
        }

        let windows = windows_toolchain();
        let windows_script = TargetPath::windows(r"C:\work\script.ps1").expect("script");
        let command_template = shell_argv(
            &windows,
            &ResolvedShell::CommandTemplate("bash -e {0}".to_owned()),
            &windows_script,
        )
        .expect_err("Windows command templates are unsupported");
        assert_eq!(
            command_template.kind(),
            ExecutorAdapterErrorKind::Unsupported
        );

        let unsafe_cmd = TargetPath::windows(r"C:\work%PATH%\script.cmd").expect("valid path");
        let unsafe_path = shell_argv(
            &windows,
            &ResolvedShell::Named("cmd".to_owned()),
            &unsafe_cmd,
        )
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
    fn composite_shell_accepts_only_configured_builtin_names_and_existing_templates() {
        for (input, expected) in [
            (" BASH ", "bash"),
            ("sh", "sh"),
            ("Python", "python"),
            ("pwsh", "pwsh"),
            ("PowerShell", "powershell"),
            ("CMD", "cmd"),
        ] {
            let shell = composite_shell(input).expect("built-in shell");
            assert!(matches!(shell, ResolvedShell::Named(name) if name == expected));
        }
        for template in [
            "bash -e {0}",
            "bash --noprofile --norc -eo pipefail {0}",
            "sh -e {0}",
        ] {
            let shell = composite_shell(template).expect("configured command template");
            assert!(matches!(
                shell,
                ResolvedShell::CommandTemplate(value) if value == template
            ));
        }
        for unsupported in ["perl {0}", "bash {0}", "pwsh -File {0}", ""] {
            let error = composite_shell(unsupported)
                .err()
                .expect("unsupported composite shell");
            assert_eq!(error.kind(), ExecutorAdapterErrorKind::Unsupported);
        }
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
}
