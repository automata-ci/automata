use anyhow::{Result, bail};
use automata_ci_local::{
    ComposeFrontend, DoctorReport, DoctorRequest, Engine, EngineArchitecture, EngineEndpoint,
    EngineRequest, LocalCheckReport, LocalCheckRequest, check_workflow, inspect,
};
use automata_ci_workflow_github::LocalWorkflowDispatchInputs;

use crate::cli::{LocalArgs, LocalCheckArgs, LocalCommand, LocalContainerEngine, LocalDoctorArgs};

pub(crate) async fn execute(args: &LocalArgs) -> Result<()> {
    match &args.command {
        LocalCommand::Doctor(args) => Box::pin(doctor(args)).await,
        LocalCommand::Check(args) => Box::pin(check(args)).await,
    }
}

async fn check(args: &LocalCheckArgs) -> Result<()> {
    let inputs = LocalWorkflowDispatchInputs::try_new(
        args.inputs
            .iter()
            .map(|input| (input.name().to_owned(), input.value().to_owned())),
    )?;
    let directory = std::env::current_dir()?;
    let request = LocalCheckRequest::new(directory, args.workflow.clone(), inputs);
    let mut checking = Box::pin(check_workflow(request));
    let report = tokio::select! {
        biased;
        () = crate::shutdown::wait_without_logging() => {
            drop(checking);
            bail!("local workflow check interrupted by a process shutdown signal")
        }
        report = &mut checking => report,
    };
    if args.json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
        println!();
    } else {
        print_human_check_report(&report);
    }
    if !report.valid() {
        bail!("local workflow check failed; resolve the source issues above")
    }
    Ok(())
}

async fn doctor(args: &LocalDoctorArgs) -> Result<()> {
    let request = DoctorRequest::new(engine_request(args.engine));
    let mut inspection = Box::pin(inspect(request));
    let report = tokio::select! {
        biased;
        () = crate::shutdown::wait_without_logging() => {
            drop(inspection);
            bail!("local preflight interrupted by a process shutdown signal")
        }
        report = &mut inspection => report,
    };
    if args.json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
        println!();
    } else {
        print_human_report(&report);
    }

    if !report.ready() {
        bail!("local preflight failed; resolve the unavailable checks above")
    }
    Ok(())
}

const fn engine_request(engine: LocalContainerEngine) -> EngineRequest {
    match engine {
        LocalContainerEngine::Auto => EngineRequest::Auto,
        LocalContainerEngine::Docker => EngineRequest::Docker,
    }
}

fn print_human_report(report: &DoctorReport) {
    println!(
        "Automata local preflight: {}",
        if report.ready() { "ready" } else { "not ready" }
    );
    println!(
        "Platform: {}/{}",
        report.operating_system(),
        report.architecture()
    );
    match report.selected_engine() {
        Some(selection) => println!(
            "Container engine: {} {} (API {})",
            engine_name(selection.engine()),
            selection.server_version(),
            selection.api_version()
        ),
        None => println!("Container engine: unavailable"),
    }
    if let Some(selection) = report.selected_engine() {
        println!("Docker context: {}", selection.context_name());
        println!("Engine endpoint: {}", endpoint_name(selection.endpoint()));
        println!("Engine identity: {}", selection.engine_id());
        println!(
            "Execution platform: linux/{}",
            architecture_name(selection.architecture())
        );
        println!(
            "Compose frontend: {} {}",
            compose_name(selection.compose()),
            selection.compose_version()
        );
    }
    for issue in report.issues() {
        println!(
            "Problem ({:?}/{:?}): {}",
            issue.probe(),
            issue.code(),
            issue.message()
        );
    }
}

fn print_human_check_report(report: &LocalCheckReport) {
    println!(
        "Automata local workflow check: {}",
        if report.valid() { "valid" } else { "invalid" }
    );
    if let Some(source) = report.source() {
        println!(
            "Snapshot: {} ({})",
            source.snapshot_digest(),
            if source.dirty() {
                "dirty worktree"
            } else {
                "clean worktree"
            }
        );
        if let Some(path) = source.workflow_path() {
            println!("Workflow: {path}");
        }
    }
    if !report.required_root_secrets().is_empty() {
        println!(
            "Required root secrets: {}",
            report.required_root_secrets().join(", ")
        );
    }
    for workflow in report.workflows() {
        println!(
            "{}: {}",
            if workflow.reusable() {
                "Reusable workflow"
            } else {
                "Root workflow"
            },
            workflow.path()
        );
        for job in workflow.jobs() {
            println!("  Job: {} ({})", job.id(), job.kind());
            if job.environment_required() {
                println!("    Deployment environment: required");
            }
            if !job.secrets().is_empty() {
                println!("    Secrets: {}", job.secrets().join(", "));
            }
            if !job.variables().is_empty() {
                println!("    Variables: {}", job.variables().join(", "));
            }
        }
    }
    for diagnostic in report.diagnostics() {
        println!(
            "Diagnostic ({}): {}",
            diagnostic.code(),
            diagnostic.message()
        );
    }
    if let Some(issue) = report.issue() {
        println!("Problem ({}): {}", issue.code().as_str(), issue.message());
    }
}

const fn engine_name(engine: Engine) -> &'static str {
    match engine {
        Engine::Docker => "docker",
    }
}

const fn compose_name(frontend: ComposeFrontend) -> &'static str {
    match frontend {
        ComposeFrontend::DockerPlugin => "docker compose",
    }
}

const fn endpoint_name(endpoint: EngineEndpoint) -> &'static str {
    match endpoint {
        EngineEndpoint::UnixSocket => "local Unix socket",
        EngineEndpoint::WindowsNamedPipe => "local Windows named pipe",
    }
}

const fn architecture_name(architecture: EngineArchitecture) -> &'static str {
    match architecture {
        EngineArchitecture::Amd64 => "amd64",
        EngineArchitecture::Arm64 => "arm64",
    }
}
