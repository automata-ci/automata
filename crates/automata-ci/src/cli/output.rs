use clap::ValueEnum;

/// Stable presentation modes supported by operator CLI commands.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Human-readable tables and summaries.
    #[default]
    Table,
    /// One complete JSON document.
    Json,
    /// One JSON document per line, suitable for streaming watches.
    JsonLines,
}
