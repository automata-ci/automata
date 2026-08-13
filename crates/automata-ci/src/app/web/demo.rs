use std::{
    fmt,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use automata_ci_auth::human::TenantId;
use automata_ci_core::{JobId, RunId, UnixMillis, WorkflowId};

use super::data::{
    ArtifactDownload, ArtifactSummary, CollectionVisibility, JobLogPage, JobLogRequest,
    JobNavigationItem, JobSummary, LogChannel, LogLine, Repository, RepositoryDirectoryItem,
    RepositoryDirectoryPage, RepositoryDirectoryRequest, RepositoryPath, RepositorySettingsPage,
    RequestContext, RunDetailPage, RunDetailRequest, RunListPage, RunListRequest, RunSummary,
    Status, VisibleCollection, WebData, WebDataError, Workflow, WorkflowDefinition,
};

const OWNER: &str = "local";
const REPOSITORY: &str = "evaluation";

#[derive(Debug)]
struct DemoState {
    run_status: Status,
    job_status: Status,
    started_at: Option<UnixMillis>,
    finished_at: Option<UnixMillis>,
    lines: Vec<LogLine>,
    next_sequence: u64,
}

/// Mutable, process-local projection of one native demo run into the ordinary UI.
pub(crate) struct DemoWebData {
    workflow_id: WorkflowId,
    run_id: RunId,
    job_id: JobId,
    workflow_name: String,
    workflow_path: String,
    state: Mutex<DemoState>,
}

impl fmt::Debug for DemoWebData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DemoWebData")
            .finish_non_exhaustive()
    }
}

impl DemoWebData {
    pub(crate) fn new(workflow_name: String, workflow_path: String) -> Self {
        Self {
            workflow_id: WorkflowId::new(),
            run_id: RunId::new(),
            job_id: JobId::new(),
            workflow_name,
            workflow_path,
            state: Mutex::new(DemoState {
                run_status: Status::Queued,
                job_status: Status::Queued,
                started_at: None,
                finished_at: None,
                lines: Vec::new(),
                next_sequence: 1,
            }),
        }
    }

    pub(crate) fn context() -> RequestContext {
        RequestContext::anonymous(TenantId::new("demo").expect("built-in demo tenant"))
    }

    pub(crate) fn run_url(&self) -> String {
        format!("/{OWNER}/{REPOSITORY}/actions/runs/{}", self.run_id)
    }

    pub(crate) fn start(&self) {
        let mut state = self.state.lock().expect("demo state mutex");
        let now = now();
        state.run_status = Status::InProgress;
        state.job_status = Status::InProgress;
        state.started_at = Some(now);
        push_line(
            &mut state,
            LogChannel::System,
            "Native Windows demo started",
        );
    }

    pub(crate) fn step_started(&self, number: usize, name: &str) {
        let mut state = self.state.lock().expect("demo state mutex");
        push_line(
            &mut state,
            LogChannel::System,
            &format!("Starting step {number}: {name}"),
        );
    }

    pub(crate) fn stdout(&self, bytes: &[u8]) {
        self.step_output(LogChannel::Stdout, bytes);
    }

    pub(crate) fn stderr(&self, bytes: &[u8]) {
        self.step_output(LogChannel::Stderr, bytes);
    }

    fn step_output(&self, channel: LogChannel, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        let mut state = self.state.lock().expect("demo state mutex");
        for line in text.lines() {
            push_line(&mut state, channel, line);
        }
    }

    pub(crate) fn finish(&self, succeeded: bool, message: &str) {
        let mut state = self.state.lock().expect("demo state mutex");
        state.run_status = if succeeded {
            Status::Succeeded
        } else {
            Status::Failed
        };
        state.job_status = state.run_status;
        state.finished_at = Some(now());
        push_line(&mut state, LogChannel::System, message);
    }

    fn repository() -> Repository {
        Repository {
            id: "00000000-0000-4000-8000-000000000001".to_owned(),
            scm_provider: "github".to_owned(),
            owner: OWNER.to_owned(),
            name: REPOSITORY.to_owned(),
            settings_visible: false,
        }
    }

    fn workflow(&self) -> Workflow {
        Workflow {
            id: self.workflow_id,
            name: self.workflow_name.clone(),
            path: self.workflow_path.clone(),
        }
    }

    fn snapshot(&self) -> (RunSummary, JobSummary, Vec<LogLine>) {
        let state = self.state.lock().expect("demo state mutex");
        let created_at = state.started_at.unwrap_or_else(now);
        (
            RunSummary {
                id: self.run_id,
                number: 1,
                attempt: 1,
                title: Some("Native Windows local evaluation".to_owned()),
                workflow: self.workflow(),
                status: state.run_status,
                git_ref: Some("refs/heads/local-evaluation".to_owned()),
                event: "workflow_dispatch".to_owned(),
                actor: Some("local Windows user".to_owned()),
                head_sha: "0000000000000000000000000000000000000000".to_owned(),
                commit_subject: Some("Disposable local evaluation".to_owned()),
                created_at,
                finished_at: state.finished_at,
            },
            JobSummary {
                id: self.job_id,
                name: "Native Windows job".to_owned(),
                attempt: Some(1),
                runner_label: Some("windows-native".to_owned()),
                status: state.job_status,
                started_at: state.started_at,
                finished_at: state.finished_at,
                logs_available: true,
            },
            state.lines.clone(),
        )
    }
}

fn now() -> UnixMillis {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    UnixMillis::new(i64::try_from(millis).unwrap_or(i64::MAX))
}

fn push_line(state: &mut DemoState, channel: LogChannel, text: &str) {
    state.lines.push(LogLine {
        sequence: state.next_sequence,
        fragment: None,
        emitted_at: now(),
        channel,
        text: text.to_owned(),
    });
    state.next_sequence = state.next_sequence.saturating_add(1);
}

fn matches_repository(repository: &RepositoryPath) -> bool {
    repository.owner == OWNER && repository.name == REPOSITORY
}

#[async_trait]
impl WebData for DemoWebData {
    async fn repository_page(
        &self,
        _context: &RequestContext,
        _request: &RepositoryDirectoryRequest,
    ) -> Result<RepositoryDirectoryPage, WebDataError> {
        Ok(RepositoryDirectoryPage {
            repositories: vec![RepositoryDirectoryItem {
                repository: Self::repository(),
                actions_visible: true,
                settings_destination: None,
            }],
            next_cursor: None,
        })
    }

    async fn list_runs(
        &self,
        _context: &RequestContext,
        repository: &RepositoryPath,
        _request: &RunListRequest,
    ) -> Result<Option<RunListPage>, WebDataError> {
        if !matches_repository(repository) {
            return Ok(None);
        }
        let (run, _, _) = self.snapshot();
        let workflow = WorkflowDefinition {
            id: self.workflow_id,
            name: self.workflow_name.clone(),
            enabled: true,
        };
        Ok(Some(RunListPage {
            repository: Self::repository(),
            workflows: vec![workflow.clone()],
            selected_workflow: None,
            workflow_previous_cursor: None,
            workflow_next_cursor: None,
            runs: vec![run],
            previous_cursor: None,
            next_cursor: None,
        }))
    }

    async fn run_detail(
        &self,
        _context: &RequestContext,
        repository: &RepositoryPath,
        run_id: RunId,
        _request: &RunDetailRequest,
    ) -> Result<Option<RunDetailPage>, WebDataError> {
        if !matches_repository(repository) || run_id != self.run_id {
            return Ok(None);
        }
        let (run, job, _) = self.snapshot();
        Ok(Some(RunDetailPage {
            repository: Self::repository(),
            run,
            jobs: VisibleCollection {
                visibility: CollectionVisibility::Full,
                items: vec![job],
            },
            job_previous_cursor: None,
            job_next_cursor: None,
            artifacts: VisibleCollection {
                visibility: CollectionVisibility::Full,
                items: Vec::<ArtifactSummary>::new(),
            },
        }))
    }

    async fn repository_settings(
        &self,
        _context: &RequestContext,
        _repository: &RepositoryPath,
    ) -> Result<Option<RepositorySettingsPage>, WebDataError> {
        Ok(None)
    }

    async fn job_log(
        &self,
        _context: &RequestContext,
        repository: &RepositoryPath,
        run_id: RunId,
        job_id: JobId,
        _request: &JobLogRequest,
    ) -> Result<Option<JobLogPage>, WebDataError> {
        if !matches_repository(repository) || run_id != self.run_id || job_id != self.job_id {
            return Ok(None);
        }
        let (run, job, lines) = self.snapshot();
        Ok(Some(JobLogPage {
            repository: Self::repository(),
            run,
            jobs: vec![JobNavigationItem {
                id: self.job_id,
                name: job.name.clone(),
                status: job.status,
                logs_available: true,
            }],
            previous_navigation_job_id: None,
            next_navigation_job_id: None,
            job,
            lines,
            previous_cursor: None,
            next_cursor: None,
        }))
    }

    async fn artifact(
        &self,
        _context: &RequestContext,
        _repository: &RepositoryPath,
        _run_id: RunId,
        _artifact_id: i64,
    ) -> Result<Option<ArtifactDownload>, WebDataError> {
        Ok(None)
    }
}
