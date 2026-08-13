use std::{
    fmt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use automata_ci_auth::human::TenantId;
use automata_ci_core::{JobId, RunId, UnixMillis, WorkflowId};
use axum::{
    Router,
    extract::State,
    http::{HeaderValue, header::CACHE_CONTROL},
    response::{IntoResponse as _, Redirect, Response},
    routing::get,
};

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
    steps: Vec<DemoStepState>,
}

#[derive(Clone, Debug)]
struct DemoStepState {
    number: usize,
    name: String,
    shell: String,
    status: Status,
    started_at: Option<UnixMillis>,
    finished_at: Option<UnixMillis>,
    exit_code: Option<i32>,
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
                steps: Vec::new(),
            }),
        }
    }

    pub(crate) fn context() -> RequestContext {
        RequestContext::anonymous(TenantId::new("demo").expect("built-in demo tenant"))
    }

    pub(crate) fn run_url(&self) -> String {
        format!("/{OWNER}/{REPOSITORY}/actions/runs/{}", self.run_id)
    }

    pub(crate) fn log_url(&self) -> String {
        format!("{}/jobs/{}", self.run_url(), self.job_id)
    }

    pub(crate) const fn entry_url() -> &'static str {
        "/__demo"
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.state
            .lock()
            .expect("demo state mutex")
            .finished_at
            .is_some()
    }

    pub(crate) fn set_steps(&self, steps: &[(usize, String, String)]) {
        let mut state = self.state.lock().expect("demo state mutex");
        state.steps = steps
            .iter()
            .map(|(number, name, shell)| DemoStepState {
                number: *number,
                name: name.clone(),
                shell: shell.clone(),
                status: Status::Queued,
                started_at: None,
                finished_at: None,
                exit_code: None,
            })
            .collect();
        push_line(
            &mut state,
            LogChannel::System,
            &format!(
                "Plan accepted: {} trusted run step(s); unsupported workflow features fail before execution",
                steps.len()
            ),
        );
    }

    pub(crate) fn start(&self) {
        let mut state = self.state.lock().expect("demo state mutex");
        let observed = now();
        state.run_status = Status::InProgress;
        state.job_status = Status::InProgress;
        state.started_at = Some(observed);
        push_line(
            &mut state,
            LogChannel::System,
            "Evaluation started: commands run through a Windows Job Object as the current Windows user",
        );
        push_line(
            &mut state,
            LogChannel::System,
            &format!("Workflow: {}", self.workflow_path),
        );
    }

    pub(crate) fn system(&self, message: &str) {
        let mut state = self.state.lock().expect("demo state mutex");
        push_line(&mut state, LogChannel::System, message);
    }

    pub(crate) fn step_started(&self, number: usize, name: &str) {
        let mut state = self.state.lock().expect("demo state mutex");
        let total = state.steps.len();
        let shell = state
            .steps
            .iter_mut()
            .find(|step| step.number == number)
            .map_or_else(
                || "unknown shell".to_owned(),
                |step| {
                    step.status = Status::InProgress;
                    step.started_at = Some(now());
                    step.shell.clone()
                },
            );
        push_line(
            &mut state,
            LogChannel::System,
            &format!("Step {number}/{total} running: {name} [{shell}]"),
        );
    }

    pub(crate) fn step_finished(&self, number: usize, exit_code: i32) {
        let mut state = self.state.lock().expect("demo state mutex");
        let finished_at = now();
        let summary = state
            .steps
            .iter_mut()
            .find(|step| step.number == number)
            .map(|step| {
                step.status = if exit_code == 0 {
                    Status::Succeeded
                } else {
                    Status::Failed
                };
                step.finished_at = Some(finished_at);
                step.exit_code = Some(exit_code);
                format!(
                    "Step {number} {}: {} — exit {exit_code} — {}",
                    if exit_code == 0 {
                        "succeeded"
                    } else {
                        "failed"
                    },
                    step.name,
                    elapsed(step.started_at, step.finished_at)
                )
            });
        if let Some(summary) = summary {
            push_line(&mut state, LogChannel::System, &summary);
        }
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
        if !succeeded {
            let finished_at = state.finished_at;
            if let Some(step) = state
                .steps
                .iter_mut()
                .find(|step| step.status == Status::InProgress)
            {
                step.status = Status::Failed;
                step.finished_at = finished_at;
            }
        }
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
                title: Some(format!("Run {} locally", self.workflow_path)),
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
                name: "Trusted Windows host execution".to_owned(),
                attempt: Some(1),
                runner_label: Some("Windows Job Object · current user".to_owned()),
                status: state.job_status,
                started_at: state.started_at,
                finished_at: state.finished_at,
                logs_available: true,
            },
            state.lines.clone(),
        )
    }
}

pub(crate) fn demo_router(data: Arc<DemoWebData>) -> Router {
    Router::new()
        .route("/__demo", get(demo_entry))
        .with_state(data)
}

async fn demo_entry(State(data): State<Arc<DemoWebData>>) -> Response {
    let mut response = Redirect::temporary(&data.log_url()).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn now() -> UnixMillis {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    UnixMillis::new(i64::try_from(millis).unwrap_or(i64::MAX))
}

fn elapsed(started: Option<UnixMillis>, finished: Option<UnixMillis>) -> String {
    let Some(started) = started else {
        return "Not started".to_owned();
    };
    let end = finished.unwrap_or_else(now);
    let millis = end.get().saturating_sub(started.get()).max(0);
    let seconds = millis / 1_000;
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m {}s", seconds / 60, seconds % 60)
    }
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
            workflows: vec![workflow],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_tracks_exact_step_transitions_and_explains_them_in_logs() {
        let data = DemoWebData::new("Local demo".to_owned(), ".ci/workflows/demo.yml".to_owned());
        data.set_steps(&[
            (1, "Build".to_owned(), "powershell".to_owned()),
            (2, "Test".to_owned(), "cmd".to_owned()),
        ]);
        data.start();
        data.step_started(1, "Build");

        {
            let running = data.state.lock().expect("demo state");
            assert_eq!(running.run_status, Status::InProgress);
            assert_eq!(running.steps[0].status, Status::InProgress);
            assert_eq!(running.steps[1].status, Status::Queued);
        }

        data.step_finished(1, 0);
        data.step_started(2, "Test");
        data.step_finished(2, 7);
        data.finish(false, "test failed");

        let failed = data.state.lock().expect("demo state");
        assert_eq!(failed.run_status, Status::Failed);
        assert_eq!(failed.steps[0].status, Status::Succeeded);
        assert_eq!(failed.steps[0].exit_code, Some(0));
        assert_eq!(failed.steps[1].status, Status::Failed);
        assert_eq!(failed.steps[1].exit_code, Some(7));
        let log = failed
            .lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(log.contains("Plan accepted: 2 trusted run step(s)"));
        assert!(log.contains("Step 1/2 running: Build [powershell]"));
        assert!(log.contains("Step 2 failed: Test — exit 7"));
    }

    #[tokio::test]
    async fn demo_entry_redirects_to_the_standard_job_log_page() {
        use axum::{
            body::Body,
            http::{Request, header::LOCATION},
        };
        use tower::ServiceExt as _;

        let data = Arc::new(DemoWebData::new(
            "Local demo".to_owned(),
            "demo.yml".to_owned(),
        ));
        let expected = data.log_url();
        let response = demo_router(data)
            .oneshot(
                Request::builder()
                    .uri("/__demo")
                    .body(Body::empty())
                    .expect("entry request"),
            )
            .await
            .expect("state response");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::TEMPORARY_REDIRECT
        );
        assert_eq!(response.headers()[LOCATION], expected);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }
}
