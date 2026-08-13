use std::{
    env,
    fs::OpenOptions,
    io::Write as _,
    path::PathBuf,
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{TIMING_INVOCATION_ENVIRONMENT, TIMING_RUN_ENVIRONMENT, TIMINGS_DIRECTORY_ENVIRONMENT};

static TIMING_WRITE_LOCK: Mutex<()> = Mutex::new(());
const TIMING_RECORD_SCHEMA: &str = "automata-postgres-test-timing/v1";
// foundation-governance: operational-limit
const MAX_TIMING_INVOCATION_LENGTH: usize = 64;

#[derive(Clone, Copy)]
pub(crate) enum TimingOperation {
    TemplatePrepare,
    TemplateReuse,
    Clone,
    TestBody,
    Cleanup,
    NamespaceCleanup,
}

impl TimingOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TemplatePrepare => "template_prepare",
            Self::TemplateReuse => "template_reuse",
            Self::Clone => "clone",
            Self::TestBody => "test_body",
            Self::Cleanup => "cleanup",
            Self::NamespaceCleanup => "namespace_cleanup",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TimingDetail {
    PreparedTemplate,
    EmptyTemplateZero,
    TestDatabase,
    ExactTemplate,
    CompleteNamespace,
}

impl TimingDetail {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PreparedTemplate => "prepared_template",
            Self::EmptyTemplateZero => "empty_template0",
            Self::TestDatabase => "test_database",
            Self::ExactTemplate => "exact_template",
            Self::CompleteNamespace => "complete_namespace",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TimingOutcome {
    Success,
    Completed,
    Error,
    Panic,
    Cancelled,
    Incomplete,
}

impl TimingOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Completed => "completed",
            Self::Error => "error",
            Self::Panic => "panic",
            Self::Cancelled => "cancelled",
            Self::Incomplete => "incomplete",
        }
    }
}

pub(crate) struct TimingSpan {
    started_at: Instant,
    started_unix_ns: Option<u128>,
    context: Option<TimingContext>,
    operation: TimingOperation,
    detail: TimingDetail,
    finished: bool,
}

impl TimingSpan {
    pub(crate) fn start(operation: TimingOperation, detail: TimingDetail) -> Self {
        let started_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_nanos());
        Self {
            started_at: Instant::now(),
            started_unix_ns,
            context: TimingContext::from_environment(),
            operation,
            detail,
            finished: false,
        }
    }

    pub(crate) fn finish(mut self, outcome: TimingOutcome) {
        self.record(self.operation, outcome);
        self.finished = true;
    }

    pub(crate) fn finish_as(mut self, operation: TimingOperation, outcome: TimingOutcome) {
        self.record(operation, outcome);
        self.finished = true;
    }

    fn record(&self, operation: TimingOperation, outcome: TimingOutcome) {
        let Some(started_unix_ns) = self.started_unix_ns else {
            return;
        };
        let Some(context) = &self.context else {
            return;
        };
        append_timing_record(
            context,
            operation,
            self.detail,
            outcome,
            started_unix_ns,
            self.started_at.elapsed().as_nanos(),
        );
    }
}

impl Drop for TimingSpan {
    fn drop(&mut self) {
        if !self.finished {
            self.record(self.operation, TimingOutcome::Incomplete);
        }
    }
}

struct TimingContext {
    directory: PathBuf,
    invocation: String,
    run: u32,
}

impl TimingContext {
    fn from_environment() -> Option<Self> {
        let directory = env::var_os(TIMINGS_DIRECTORY_ENVIRONMENT)?;
        if directory.is_empty() {
            return None;
        }
        let invocation = env::var(TIMING_INVOCATION_ENVIRONMENT).ok()?;
        if invocation.is_empty()
            || invocation.len() > MAX_TIMING_INVOCATION_LENGTH
            || !invocation
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return None;
        }
        let run = env::var(TIMING_RUN_ENVIRONMENT).ok()?;
        if run.is_empty() || (run.len() > 1 && run.starts_with('0')) {
            return None;
        }
        Some(Self {
            directory: PathBuf::from(directory),
            invocation,
            run: run.parse().ok()?,
        })
    }
}

fn append_timing_record(
    context: &TimingContext,
    operation: TimingOperation,
    detail: TimingDetail,
    outcome: TimingOutcome,
    started_unix_ns: u128,
    elapsed_ns: u128,
) {
    let process_id = std::process::id();
    let path = context
        .directory
        .join(format!("postgres-test-timings-{process_id}.jsonl"));
    let record = format!(
        concat!(
            "{{\"schema\":\"{timing_record_schema}\",",
            "\"pid\":{process_id},",
            "\"invocation\":\"{invocation}\",",
            "\"run\":{run},",
            "\"operation\":\"{operation}\",",
            "\"detail\":\"{detail}\",",
            "\"outcome\":\"{outcome}\",",
            "\"started_unix_ns\":{started_unix_ns},",
            "\"elapsed_ns\":{elapsed_ns}}}\n"
        ),
        process_id = process_id,
        timing_record_schema = TIMING_RECORD_SCHEMA,
        invocation = context.invocation.as_str(),
        run = context.run,
        operation = operation.as_str(),
        detail = detail.as_str(),
        outcome = outcome.as_str(),
        started_unix_ns = started_unix_ns,
        elapsed_ns = elapsed_ns,
    );

    // The output is diagnostic only. Serialize writers within this process,
    // open in append mode for every complete record, and deliberately ignore
    // poison, open, write, and flush failures so instrumentation cannot change
    // test behavior. Distinct processes use distinct PID-qualified files.
    let Ok(_guard) = TIMING_WRITE_LOCK.lock() else {
        return;
    };
    let Ok(mut output) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    if output.write_all(record.as_bytes()).is_ok() {
        let _ = output.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::TIMING_RECORD_SCHEMA;

    #[test]
    fn timing_record_schema_is_exact_v1() {
        assert_eq!(TIMING_RECORD_SCHEMA, "automata-postgres-test-timing/v1");
    }
}
