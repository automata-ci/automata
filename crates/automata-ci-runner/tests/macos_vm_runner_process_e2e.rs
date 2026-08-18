#![cfg(target_os = "macos")]
#![deny(warnings)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_auth::{
    machine::{
        AuthenticatedMachine, ExternalRunnerIdentity, MachineAuthenticationError,
        MachineAuthenticationEvidence, MachineAuthenticationFuture, MachineIdentityVerifier,
    },
    time::UnixTimestamp,
};
use automata_ci_core::{
    AttemptId, ContextValue, EnvironmentProfile, EnvironmentProfileId, FencingToken,
    JobAuthorityProfile, JobConclusion, JobContentReference, JobExecutionContext, JobId,
    JobInstanceIdentity, JobIr, JobIrEnvelope, JobPermissionRequest, JobResourceAllocation,
    JobRuntimeContext, JobSource, Lease, LeaseId, LogAck, OperatingSystem, OperationId,
    ResourceCapacity, RunId, RunValueTemplates, RunnerFeature, RunnerId, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    StrategyContext, UnixMillis, ValueTemplate, WorkflowId,
};
#[cfg(target_os = "macos")]
use automata_ci_core::{ExpressionProgram, ValueSource};
use automata_ci_protocol::{
    CommandAck, CommandCursor, CommandSequence, JobResultMessage, JobRuntimeAuthorities,
    LeaseDisposition, LeaseOffer, LeaseRenewal, LeaseRequest, LogAckMessage, LogBatch,
    MessageHeader, NegotiatedSession, NoWork, OperationAck, ProtocolLimits, RunnerSlotOrdinal,
    RunnerToServer, RuntimeAuthorityAck, RuntimeAuthorityGrant, RuntimeAuthorityRequest,
    SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerHello, ServerTiming, ServerToRunner,
    SessionDisposition,
};
use automata_ci_protocol_protobuf::{encode_job_runtime_context, encode_runtime_authorities};
use automata_ci_runner::product::RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION;
use automata_ci_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerRequest, HandlerFuture,
    RunnerControlHandler, RunnerControlServer, ServerTlsConfig, TransportLimits,
};
#[cfg(target_os = "macos")]
use automata_ci_workflow_actions::{GithubConditionCompiler, GithubConditionPhase};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    net::{TcpListener, TcpStream},
    process::Command,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt as _;

const JOB_RUNTIME_CONTEXT_MEDIA_TYPE: &str =
    "application/vnd.automata.job-runtime-context.protobuf";
const PROFILE_ID: &str = "automata.dev/macos-15-arm64-vm-v1";
const S3_BUCKET: &str = "automata-process-e2e";
const S3_PREFIX: &str = "process-e2e";
const SENTINEL: &str = "AUTOMATA_MACOS_RUNNER_PROCESS_E2E";
#[cfg(target_os = "macos")]
const VM_HELPER_ENV: &str = "AUTOMATA_MACOS_VM_HELPER";
#[cfg(target_os = "macos")]
const VM_HELPER_SHA256_ENV: &str = "AUTOMATA_MACOS_VM_HELPER_SHA256";
#[cfg(target_os = "macos")]
const VM_HELPER_REQUIREMENT_ENV: &str = "AUTOMATA_MACOS_VM_HELPER_REQUIREMENT";
#[cfg(target_os = "macos")]
const VM_TEMPLATE_MANIFEST_ENV: &str = "AUTOMATA_MACOS_VM_TEMPLATE_MANIFEST";
#[cfg(target_os = "macos")]
const VM_TEMPLATE_SHA256_ENV: &str = "AUTOMATA_MACOS_VM_TEMPLATE_SHA256";
#[cfg(target_os = "macos")]
const VM_STORAGE_ROOT_ENV: &str = "AUTOMATA_MACOS_VM_STORAGE_ROOT";
#[cfg(target_os = "macos")]
const VM_STORAGE_VOLUME_UUID_ENV: &str = "AUTOMATA_MACOS_VM_STORAGE_VOLUME_UUID";
#[cfg(target_os = "macos")]
const VM_STORAGE_QUOTA_BYTES_ENV: &str = "AUTOMATA_MACOS_VM_STORAGE_QUOTA_BYTES";
#[cfg(target_os = "macos")]
const DIFFERENTIAL_REFERENCE: &str = "differential.bash=ok\nisolation.cpu=4\nisolation.memory=8589934592\nisolation.process_limit=512\nisolation.no_host_helper=true\nisolation.no_ethernet=true\nactions.node20=ok\nactions.node24=ok\ndifferential.sh=ok\ndifferential.environment=command-file\ndifferential.output=vm-output\ndifferential.workspace=true\ndifferential.conclusion=success\n";
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires a sealed VM template on a physical Apple Silicon runner"
)]
#[allow(clippy::too_many_lines)]
async fn shipped_runner_process_executes_a_claimed_isolated_job_with_action_runtimes() {
    let root = TemporaryRoot::new();
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let pki = TestPki::new();
    let (job, event, runtime_context) = process_job();
    let expected_s3_paths = [
        event.fixture_path(),
        runtime_context.fixture_path(),
        runtime_context.fixture_path(),
    ];
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(1).expect("fencing token"),
        UnixMillis::new(unix_millis().saturating_sub(1_000)),
        UnixMillis::new(unix_millis().saturating_add(i64::from(process_control_timeout_millis()))),
    )
    .expect("process test lease");
    let authorities =
        JobRuntimeAuthorities::new(Vec::new(), &job, &lease).expect("credential-free authorities");
    let handler = Arc::new(ProcessFlowHandler::new(
        runner_id,
        session_id,
        lease,
        job,
        authorities,
    ));

    let s3 = S3Fixture::spawn([event, runtime_context]).await;
    let control = RunningControlServer::spawn(&pki, handler.clone()).await;
    let config_path = write_runner_config(root.path(), runner_id, control.address, s3.address);

    let mut child = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .env("AUTOMATA_PROCESS_E2E_SERVER_ROOTS_PEM", pki.root_pem())
        .env(
            "AUTOMATA_PROCESS_E2E_CERTIFICATE_CHAIN_PEM",
            pki.client.certificate_chain_pem(),
        )
        .env(
            "AUTOMATA_PROCESS_E2E_PRIVATE_KEY_PEM",
            pki.client.private_key_pem(),
        )
        .env("AUTOMATA_PROCESS_E2E_SPOOL_KEY_HEX", "11".repeat(32))
        .env("AUTOMATA_PROCESS_E2E_S3_ACCESS_KEY", "process-access")
        .env("AUTOMATA_PROCESS_E2E_S3_SECRET_KEY", "process-secret")
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("launch shipped automata-runner binary");
    let mut stdout_task = Some(tokio::spawn(drain_output(
        child.stdout.take().expect("runner stdout pipe"),
    )));
    let mut stderr_task = Some(tokio::spawn(drain_output(
        child.stderr.take().expect("runner stderr pipe"),
    )));

    wait_for_terminal_result(
        &handler,
        &mut child,
        &mut stdout_task,
        &mut stderr_task,
        process_result_timeout(),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(10), handler.wait_for_completed_poll())
        .await
        .expect("runner finalizes the completed job and polls its released slot");
    #[cfg(target_os = "macos")]
    assert!(
        fs::read_dir(
            PathBuf::from(required_macos_vm_environment(VM_STORAGE_ROOT_ENV)).join("attempts")
        )
        .map_or(true, |mut entries| entries.next().is_none()),
        "virtualization provider left a VM clone behind"
    );

    stop_runner(&mut child).await;
    let stdout = collect_output(stdout_task.take().expect("stdout task"), "stdout").await;
    let stderr = collect_output(stderr_task.take().expect("stderr task"), "stderr").await;
    let s3_requests = s3.requests();
    control.stop().await;
    s3.stop().await;

    let observation = handler.observation();
    assert_eq!(observation.hello_runner_id, Some(runner_id));
    assert_eq!(
        observation.hello_operating_system,
        Some(platform_operating_system())
    );
    for feature in [
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::NODE20_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
    ] {
        assert!(
            observation.hello_features.contains(&feature),
            "physical macOS runner omitted configured action feature {feature:?}"
        );
    }
    assert!(
        observation.accepted,
        "runner did not accept the offered lease"
    );
    assert_eq!(
        observation.command_cursor,
        Some(handler.offer_cursor()),
        "runner did not durably acknowledge the offered command cursor"
    );
    assert!(
        observation.runtime_authority_progress != RuntimeAuthorityProgress::NotRequested,
        "runner did not request the post-accept runtime-authority bundle"
    );
    assert_eq!(
        observation.runtime_authority_progress,
        RuntimeAuthorityProgress::Acknowledged,
        "runner did not acknowledge durable adoption of the runtime-authority bundle"
    );
    assert_eq!(observation.conclusion, Some(JobConclusion::Success));
    let logs = String::from_utf8_lossy(&observation.logs);
    assert!(
        logs.contains(SENTINEL),
        "real isolated-shell output did not reach the control plane; logs={logs:?}; stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    #[cfg(target_os = "macos")]
    assert_macos_differential_fixture(&logs);
    assert!(
        observation.completed_poll,
        "runner reported the result but did not finalize the slot and poll again; stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert_s3_requests(&s3_requests, &expected_s3_paths);
}

async fn drain_output<R>(mut reader: R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

async fn stop_runner(child: &mut tokio::process::Child) {
    if child
        .try_wait()
        .expect("query runner before shutdown")
        .is_none()
    {
        child.start_kill().expect("signal runner process shutdown");
    }
    tokio::time::timeout(TEARDOWN_TIMEOUT, child.wait())
        .await
        .expect("runner process exits within teardown timeout")
        .expect("wait for runner process");
}

async fn collect_output(task: JoinHandle<io::Result<Vec<u8>>>, stream: &'static str) -> Vec<u8> {
    tokio::time::timeout(TEARDOWN_TIMEOUT, task)
        .await
        .unwrap_or_else(|_| panic!("runner {stream} drain exceeded teardown timeout"))
        .unwrap_or_else(|error| panic!("runner {stream} drain task failed: {error}"))
        .unwrap_or_else(|error| panic!("runner {stream} drain failed: {error}"))
}

async fn wait_for_terminal_result(
    handler: &ProcessFlowHandler,
    child: &mut tokio::process::Child,
    stdout_task: &mut Option<JoinHandle<io::Result<Vec<u8>>>>,
    stderr_task: &mut Option<JoinHandle<io::Result<Vec<u8>>>>,
    limit: Duration,
) {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if handler.observation().conclusion.is_some() {
            return;
        }
        if let Some(status) = child.try_wait().expect("query runner process") {
            let stdout = collect_output(stdout_task.take().expect("stdout task"), "stdout").await;
            let stderr = collect_output(stderr_task.take().expect("stderr task"), "stderr").await;
            panic!(
                "automata-runner exited before reporting a job result: {status}; observation={:?}; stdout={:?}; stderr={:?}",
                handler.observation(),
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            );
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "automata-runner did not complete the claimed job within {limit:?}; observation={:?}",
            handler.observation(),
        );
        let _ = tokio::time::timeout(Duration::from_millis(200), handler.wait_for_result()).await;
    }
}

fn process_job() -> (JobIrEnvelope, S3Object, S3Object) {
    let event_bytes = b"{}".to_vec();
    let event_reference =
        content_reference("events/process-e2e.json", "application/json", &event_bytes);
    let runtime_context = JobRuntimeContext::new(
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        StrategyContext::new(true, 0, 1, 1).expect("strategy context"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("empty runtime context");
    let runtime_bytes = encode_job_runtime_context(&runtime_context, &ProtocolLimits::default())
        .expect("encode runtime context");
    let runtime_reference = content_reference(
        "contexts/process-e2e.pb",
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
        &runtime_bytes,
    );
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new(PROFILE_ID).expect("profile ID"),
        process_profile_digest(),
    );
    let capacity = process_resource_capacity();
    let allocation =
        JobResourceAllocation::new(capacity, capacity).expect("isolated process allocation");
    let requirements = RunnerRequirements::default()
        .with_environment_profile(profile)
        .with_resource_allocation(allocation);
    let steps = macos_steps();
    let job = JobIr::new(
        JobId::new(),
        RunId::new(),
        "process-e2e",
        requirements,
        JobInstanceIdentity::new("process-e2e", 0, 1, Sha256Digest::from_bytes([0x44; 32]))
            .expect("job instance"),
        false,
        steps,
    )
    .with_authority_profile(JobAuthorityProfile::CredentialFree)
    .with_permission_request(JobPermissionRequest::Mapping(Vec::new()));
    let envelope = JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "automata-ci/automata",
            automata_ci_core::GitObjectId::from_provider_hex(
                "0123456789abcdef0123456789abcdef01234567",
            )
            .expect("revision"),
            ".ci/workflows/macos-vm-process-e2e.yml",
            "workflow_dispatch",
        ),
        JobExecutionContext::new(
            "CI",
            "refs/heads/macos-vm-process-e2e",
            "/__w/automata/automata",
            event_reference.clone(),
            runtime_reference.clone(),
        ),
        job,
    );
    (
        envelope,
        S3Object::new(&event_reference, event_bytes),
        S3Object::new(&runtime_reference, runtime_bytes),
    )
}

#[cfg(target_os = "macos")]
fn macos_steps() -> Vec<StepIr> {
    let producer = StepIr::new(
        StepId::new("macos-bash-reference").expect("producer step ID"),
        ValueTemplate::literal("Run Bash differential fixture").expect("producer step name"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal(
                "set -eu\ntest \"$(/usr/sbin/sysctl -n hw.ncpu)\" = 4\ntest \"$(/usr/sbin/sysctl -n hw.memsize)\" = 8589934592\ntest \"$(ulimit -u)\" = 512\ntest ! -e /Library/Automata/bin/automata-macos-vm-helper\nif /sbin/ifconfig -l | /usr/bin/tr ' ' '\\n' | /usr/bin/grep -Eq '^en[0-9]+$'; then exit 1; fi\ncase \"$(/Library/Automata/externals/node20/bin/node --version)\" in v20.*) ;; *) exit 1 ;; esac\ncase \"$(/Library/Automata/externals/node24/bin/node --version)\" in v24.*) ;; *) exit 1 ;; esac\nprintf 'differential.bash=ok\\nisolation.cpu=4\\nisolation.memory=8589934592\\nisolation.process_limit=512\\nisolation.no_host_helper=true\\nisolation.no_ethernet=true\\nactions.node20=ok\\nactions.node24=ok\\n'\nprintf 'AUTOMATA_DIFFERENTIAL_ENV=command-file\\n' >> \"$GITHUB_ENV\"\nprintf 'fixture=vm-output\\n' >> \"$GITHUB_OUTPUT\"\nprintf '%s\\n' vm-workspace > differential-artifact.txt",
            )
            .expect("producer command"),
            ShellTemplate::named(ValueTemplate::literal("bash").expect("Bash shell")),
        )),
    );
    let consumer = StepIr::new(
        StepId::new("macos-sh-reference").expect("consumer step ID"),
        ValueTemplate::literal("Run sh differential fixture").expect("consumer step name"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal(format!(
                "set -eu\ntest \"$AUTOMATA_DIFFERENTIAL_ENV\" = command-file\ntest \"$FROM_OUTPUT\" = vm-output\ntest \"$PWD\" = \"$GITHUB_WORKSPACE\"\ntest \"$(cat differential-artifact.txt)\" = vm-workspace\nprintf 'differential.sh=ok\\ndifferential.environment=%s\\ndifferential.output=%s\\ndifferential.workspace=true\\ndifferential.conclusion=success\\n%s\\n' \"$AUTOMATA_DIFFERENTIAL_ENV\" \"$FROM_OUTPUT\" '{SENTINEL}'"
            ))
            .expect("consumer command"),
            ShellTemplate::named(ValueTemplate::literal("sh").expect("sh shell")),
        )),
    )
    .with_environment(BTreeMap::from([(
        "FROM_OUTPUT".to_owned(),
        ValueSource::Expression(output_expression(
            "${{ steps.macos-bash-reference.outputs.fixture }}",
        )),
    )]));
    vec![producer, consumer]
}

#[cfg(target_os = "macos")]
fn output_expression(source: &str) -> ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_value_expression(source, GithubConditionPhase::Step)
        .expect("valid step-output expression")
}

#[cfg(target_os = "macos")]
fn assert_macos_differential_fixture(logs: &str) {
    for expected in DIFFERENTIAL_REFERENCE.lines() {
        assert!(
            logs.lines().any(|line| line == expected),
            "Automata VM shell fixture omitted {expected:?}; logs={logs:?}"
        );
    }
}

fn content_reference(key: &str, media_type: &str, bytes: &[u8]) -> JobContentReference {
    JobContentReference::new(
        key,
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        u64::try_from(bytes.len()).expect("test content size"),
        media_type,
    )
}

#[derive(Clone, Debug)]
struct S3Object {
    key: String,
    media_type: String,
    digest: Sha256Digest,
    bytes: Vec<u8>,
}

impl S3Object {
    fn new(reference: &JobContentReference, bytes: Vec<u8>) -> Self {
        Self {
            key: reference.object_key().to_owned(),
            media_type: reference.media_type().to_owned(),
            digest: reference.digest(),
            bytes,
        }
    }

    fn fixture_path(&self) -> String {
        format!("/{S3_BUCKET}/{S3_PREFIX}/{}", self.key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct S3RequestObservation {
    method: String,
    path: String,
    authorization_present: bool,
}

struct S3Fixture {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<S3RequestObservation>>>,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

impl S3Fixture {
    async fn spawn(objects: impl IntoIterator<Item = S3Object>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback S3 fixture");
        let address = listener.local_addr().expect("S3 fixture address");
        let objects = Arc::new(
            objects
                .into_iter()
                .map(|object| (object.key.clone(), object))
                .collect::<BTreeMap<_, _>>(),
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let shutdown = CancellationToken::new();
        let serve_shutdown = shutdown.clone();
        let serve_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = serve_shutdown.cancelled() => return,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { return };
                        let objects = Arc::clone(&objects);
                        let requests = Arc::clone(&serve_requests);
                        tokio::spawn(async move {
                            let _ = serve_s3_request(stream, &objects, &requests).await;
                        });
                    }
                }
            }
        });
        Self {
            address,
            requests,
            shutdown,
            task,
        }
    }

    fn requests(&self) -> Vec<S3RequestObservation> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn stop(mut self) {
        self.shutdown.cancel();
        if let Ok(result) = tokio::time::timeout(TEARDOWN_TIMEOUT, &mut self.task).await {
            result.expect("S3 fixture task");
            return;
        }

        self.task.abort();
        let _ = tokio::time::timeout(TEARDOWN_TIMEOUT, &mut self.task).await;
        panic!("S3 fixture exceeded teardown timeout");
    }
}

async fn serve_s3_request(
    stream: TcpStream,
    objects: &BTreeMap<String, S3Object>,
    requests: &Mutex<Vec<S3RequestObservation>>,
) -> io::Result<()> {
    let request = read_request_head(&stream).await?;
    let mut request_line = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace();
    let method = request_line.next().unwrap_or_default();
    let path = request_line
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();
    let authorization_present = request.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && !value.trim().is_empty()
        })
    });
    requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(S3RequestObservation {
            method: method.to_owned(),
            path: path.to_owned(),
            authorization_present,
        });
    let object = objects
        .values()
        .find(|object| path.ends_with(&format!("/{}", object.key)));
    let Some(object) = object else {
        return write_all(
            &stream,
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: {}\r\nx-amz-meta-automata-sha256: {}\r\nx-amz-meta-automata-size: {}\r\nx-amz-server-side-encryption: AES256\r\nconnection: close\r\n\r\n",
        object.bytes.len(),
        object.media_type,
        object.digest,
        object.bytes.len(),
    );
    write_all(&stream, head.as_bytes()).await?;
    write_all(&stream, &object.bytes).await
}

fn assert_s3_requests(requests: &[S3RequestObservation], expected_paths: &[String]) {
    let expected = expected_paths
        .iter()
        .cloned()
        .map(|path| S3RequestObservation {
            method: "GET".to_owned(),
            path,
            authorization_present: true,
        })
        .collect::<Vec<_>>();
    let mut observed = requests.to_vec();
    observed.sort_by(|left, right| left.path.cmp(&right.path));
    let mut expected = expected;
    expected.sort_by(|left, right| left.path.cmp(&right.path));
    assert_eq!(
        observed, expected,
        "runner signed GETs must match the exact immutable job-content reads"
    );
}

async fn read_request_head(stream: &TcpStream) -> io::Result<String> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4 * 1_024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        stream.readable().await?;
        match stream.try_read(&mut buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(received) => {
                request.extend_from_slice(&buffer[..received]);
                if request.len() > 32 * 1_024 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    String::from_utf8(request).map_err(|_| io::ErrorKind::InvalidData.into())
}

async fn write_all(stream: &TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.writable().await?;
        match stream.try_write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct ProcessObservation {
    hello_runner_id: Option<RunnerId>,
    hello_operating_system: Option<OperatingSystem>,
    hello_features: BTreeSet<RunnerFeature>,
    accepted: bool,
    command_cursor: Option<CommandCursor>,
    runtime_authority_progress: RuntimeAuthorityProgress,
    logs: Vec<u8>,
    conclusion: Option<JobConclusion>,
    completed_poll: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RuntimeAuthorityProgress {
    #[default]
    NotRequested,
    Requested,
    Acknowledged,
}

#[derive(Debug)]
struct ProcessFlowHandler {
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    lease: Lease,
    offer: LeaseOffer,
    authorities: JobRuntimeAuthorities,
    state: Mutex<ProcessFlowState>,
    result_ready: tokio::sync::Notify,
    completed_poll: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct ProcessFlowState {
    offered: bool,
    result_received: bool,
    observation: ProcessObservation,
}

impl ProcessFlowHandler {
    fn new(
        runner_id: RunnerId,
        session_id: RunnerSessionId,
        lease: Lease,
        job: JobIrEnvelope,
        authorities: JobRuntimeAuthorities,
    ) -> Self {
        let offer = LeaseOffer::new(
            ServerCommandHeader::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                session_id,
                OperationId::new(),
                CommandSequence::new(1).expect("command sequence"),
            ),
            RunnerSlotOrdinal::new(1).expect("slot"),
            lease.clone(),
            job,
        );
        Self {
            runner_id,
            session_id,
            lease,
            offer,
            authorities,
            state: Mutex::new(ProcessFlowState::default()),
            result_ready: tokio::sync::Notify::new(),
            completed_poll: tokio::sync::Notify::new(),
        }
    }

    fn observation(&self) -> ProcessObservation {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observation
            .clone()
    }

    fn offer_cursor(&self) -> CommandCursor {
        CommandCursor::through(self.offer.header().sequence())
    }

    async fn wait_for_result(&self) {
        self.result_ready.notified().await;
    }

    async fn wait_for_completed_poll(&self) {
        if !self.observation().completed_poll {
            self.completed_poll.notified().await;
        }
    }

    fn handle_handshake(
        &self,
        request: &AuthenticatedRunnerRequest,
    ) -> Result<ServerToRunner, ApplicationError> {
        let RunnerToServer::Hello(hello) = request.message().message() else {
            return Err(internal_application_error());
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.observation.hello_runner_id = Some(hello.runner().runner_id());
        state.observation.hello_operating_system =
            Some(hello.runner().platform().operating_system().clone());
        state
            .observation
            .hello_features
            .clone_from(hello.runner().features());
        if hello.runner().runner_id() != self.runner_id
            || hello.runner().platform().operating_system() != &platform_operating_system()
        {
            return Err(internal_application_error());
        }
        Ok(ServerToRunner::Hello(ServerHello::new(
            OperationId::new(),
            hello.operation_id(),
            NegotiatedSession::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                automata_ci_core::JobIrVersion::current(),
                self.session_id,
                SessionDisposition::Opened,
                CommandCursor::initial(),
            ),
            ServerTiming::new(
                UnixMillis::new(unix_millis()),
                1_000,
                process_control_timeout_millis(),
            ),
        )))
    }

    fn handle_sync(
        &self,
        request: &AuthenticatedRunnerRequest,
    ) -> Result<ServerToRunner, ApplicationError> {
        match request.message().message() {
            RunnerToServer::Hello(_) => Err(internal_application_error()),
            RunnerToServer::LeaseRequest(poll) => self.handle_lease_request(poll),
            RunnerToServer::LeaseResponse(response) => {
                if response.validate_for(&self.offer).is_err() {
                    return Err(internal_application_error());
                }
                self.state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .observation
                    .accepted = response.disposition() == &LeaseDisposition::Accepted;
                Ok(ServerToRunner::OperationAck(OperationAck::new(
                    reply_header(response.header()),
                )))
            }
            RunnerToServer::RuntimeAuthorityRequest(request) => {
                self.handle_runtime_authority_request(request)
            }
            RunnerToServer::RuntimeAuthorityAck(ack) => self.handle_runtime_authority_ack(*ack),
            RunnerToServer::Heartbeat(heartbeat) => {
                if heartbeat.attempt_id() != self.lease.attempt_id()
                    || heartbeat.guard() != self.lease.guard()
                {
                    return Err(internal_application_error());
                }
                Ok(ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                    reply_header(heartbeat.header()),
                    self.lease.attempt_id(),
                    self.lease.guard(),
                    self.lease.expires_at(),
                )))
            }
            RunnerToServer::JobState(state) => {
                if state.attempt_id() != self.lease.attempt_id()
                    || state.guard() != self.lease.guard()
                {
                    return Err(internal_application_error());
                }
                Ok(ServerToRunner::OperationAck(OperationAck::new(
                    reply_header(state.header()),
                )))
            }
            RunnerToServer::LogBatch(batch) => self.handle_log_batch(batch),
            RunnerToServer::JobResult(result) => self.handle_job_result(result),
            RunnerToServer::CommandAck(ack) => self.handle_command_ack(*ack),
        }
    }

    fn runtime_authority_bundle_digest(&self) -> Result<Sha256Digest, ApplicationError> {
        let encoded = encode_runtime_authorities(
            &self.authorities,
            self.offer.job(),
            self.offer.lease(),
            &ProtocolLimits::default(),
        )
        .map_err(|_| internal_application_error())?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(&encoded).into()))
    }

    fn handle_runtime_authority_request(
        &self,
        request: &RuntimeAuthorityRequest,
    ) -> Result<ServerToRunner, ApplicationError> {
        request
            .binding()
            .validate_for_offer(&self.offer)
            .map_err(|_| internal_application_error())?;
        let bundle_digest = self.runtime_authority_bundle_digest()?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.observation.accepted {
            return Err(internal_application_error());
        }
        if state.observation.runtime_authority_progress == RuntimeAuthorityProgress::NotRequested {
            state.observation.runtime_authority_progress = RuntimeAuthorityProgress::Requested;
        }
        Ok(ServerToRunner::RuntimeAuthorityGrant(Box::new(
            RuntimeAuthorityGrant::new(
                reply_header(request.header()),
                request.binding(),
                bundle_digest,
                self.authorities.clone(),
            ),
        )))
    }

    fn handle_runtime_authority_ack(
        &self,
        acknowledgement: RuntimeAuthorityAck,
    ) -> Result<ServerToRunner, ApplicationError> {
        acknowledgement
            .binding()
            .validate_for_offer(&self.offer)
            .map_err(|_| internal_application_error())?;
        if acknowledgement.bundle_digest() != self.runtime_authority_bundle_digest()? {
            return Err(internal_application_error());
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.observation.runtime_authority_progress == RuntimeAuthorityProgress::NotRequested {
            return Err(internal_application_error());
        }
        state.observation.runtime_authority_progress = RuntimeAuthorityProgress::Acknowledged;
        Ok(ServerToRunner::OperationAck(OperationAck::new(
            reply_header(acknowledgement.header()),
        )))
    }

    fn handle_lease_request(
        &self,
        poll: &LeaseRequest,
    ) -> Result<ServerToRunner, ApplicationError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.offered {
            state.offered = true;
            Ok(ServerToRunner::LeaseOffer(Box::new(self.offer.clone())))
        } else if state.result_received {
            state.observation.completed_poll = true;
            self.completed_poll.notify_one();
            Ok(ServerToRunner::NoWork(NoWork::new(
                reply_header(poll.header()),
                25,
            )))
        } else {
            Err(internal_application_error())
        }
    }

    fn handle_log_batch(&self, batch: &LogBatch) -> Result<ServerToRunner, ApplicationError> {
        if batch.guard() != self.lease.guard()
            || batch
                .frames()
                .iter()
                .any(|frame| frame.attempt_id() != self.lease.attempt_id())
        {
            return Err(internal_application_error());
        }
        let last = batch
            .frames()
            .last()
            .ok_or_else(internal_application_error)?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for frame in batch.frames() {
            state.observation.logs.extend_from_slice(frame.payload());
        }
        Ok(ServerToRunner::LogAck(LogAckMessage::new(
            reply_header(batch.header()),
            LogAck::new(last.stream_id(), Some(last.sequence())),
        )))
    }

    fn handle_job_result(
        &self,
        result: &JobResultMessage,
    ) -> Result<ServerToRunner, ApplicationError> {
        if result.result().attempt_id() != self.lease.attempt_id()
            || result.guard() != self.lease.guard()
        {
            return Err(internal_application_error());
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.observation.conclusion = Some(result.result().conclusion());
        state.result_received = true;
        self.result_ready.notify_one();
        Ok(ServerToRunner::OperationAck(OperationAck::new(
            reply_header(result.header()),
        )))
    }

    fn handle_command_ack(&self, ack: CommandAck) -> Result<ServerToRunner, ApplicationError> {
        let expected = self.offer_cursor();
        if ack.command_cursor() != expected {
            return Err(internal_application_error());
        }
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observation
            .command_cursor = Some(ack.command_cursor());
        Ok(ServerToRunner::OperationAck(OperationAck::new(
            reply_header(ack.header()),
        )))
    }
}

#[cfg(target_os = "macos")]
const fn process_control_timeout_millis() -> u32 {
    30 * 60 * 1_000
}

#[cfg(target_os = "macos")]
const fn process_result_timeout() -> Duration {
    Duration::from_mins(15)
}

#[cfg(target_os = "macos")]
const fn process_resource_capacity() -> ResourceCapacity {
    ResourceCapacity::new(4_000, 8_589_934_592, 0, 0)
}

#[cfg(target_os = "macos")]
const fn platform_operating_system() -> OperatingSystem {
    OperatingSystem::Macos
}

#[cfg(target_os = "macos")]
fn process_profile_digest() -> Sha256Digest {
    std::env::var(VM_TEMPLATE_SHA256_ENV)
        .unwrap_or_else(|_| panic!("{VM_TEMPLATE_SHA256_ENV} is required"))
        .parse()
        .unwrap_or_else(|_| panic!("{VM_TEMPLATE_SHA256_ENV} must be a lowercase SHA-256"))
}

impl RunnerControlHandler for ProcessFlowHandler {
    fn handshake(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(async move { self.handle_handshake(&request) })
    }

    fn sync(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(async move { self.handle_sync(&request) })
    }
}

fn reply_header(request: MessageHeader) -> MessageHeader {
    MessageHeader::reply(
        request.protocol_version(),
        request.session_id(),
        OperationId::new(),
        request.operation_id(),
    )
}

const fn internal_application_error() -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::Internal)
}

#[derive(Debug)]
struct AcceptingVerifier;

impl MachineIdentityVerifier for AcceptingVerifier {
    fn authenticate<'a>(
        &'a self,
        _evidence: &'a MachineAuthenticationEvidence,
    ) -> MachineAuthenticationFuture<'a> {
        Box::pin(async {
            AuthenticatedMachine::new(
                ExternalRunnerIdentity::new("runner.process-e2e").expect("external identity"),
                [0x5a; 32],
                UnixTimestamp::from_seconds(1_700_000_000),
                UnixTimestamp::from_seconds(4_000_000_000),
            )
            .map_err(|_| MachineAuthenticationError::Unavailable)
        })
    }
}

struct RunningControlServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), automata_ci_runner_transport::ServeError>>,
}

impl RunningControlServer {
    async fn spawn(pki: &TestPki, handler: Arc<dyn RunnerControlHandler>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind runner control fixture");
        let address = listener.local_addr().expect("control fixture address");
        let server = RunnerControlServer::new(
            listener,
            &pki.server_tls(),
            Arc::new(AcceptingVerifier),
            handler,
            ProtocolLimits::default(),
            TransportLimits::default(),
        )
        .expect("runner control fixture");
        let shutdown = CancellationToken::new();
        let serve_shutdown = shutdown.clone();
        let task = tokio::spawn(server.serve(serve_shutdown));
        Self {
            address,
            shutdown,
            task,
        }
    }

    async fn stop(mut self) {
        self.shutdown.cancel();
        if let Ok(result) = tokio::time::timeout(TEARDOWN_TIMEOUT, &mut self.task).await {
            result
                .expect("control fixture task")
                .expect("control fixture result");
            return;
        }

        self.task.abort();
        let _ = tokio::time::timeout(TEARDOWN_TIMEOUT, &mut self.task).await;
        panic!("control fixture exceeded teardown timeout");
    }
}

#[derive(Debug)]
struct Identity {
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}

impl Identity {
    fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.certificate.clone())]
    }

    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_key.clone()).into()
    }

    fn certificate_chain_pem(&self) -> String {
        pem("CERTIFICATE", &self.certificate)
    }

    fn private_key_pem(&self) -> String {
        pem("PRIVATE KEY", &self.private_key)
    }
}

#[derive(Debug)]
struct TestPki {
    root: Vec<u8>,
    server: Identity,
    client: Identity,
}

impl TestPki {
    fn new() -> Self {
        let root = certificate_authority();
        let server = leaf_identity(
            "automata process e2e server",
            vec!["127.0.0.1".to_owned()],
            ExtendedKeyUsagePurpose::ServerAuth,
            &root,
        );
        let client = leaf_identity(
            "runner.process-e2e",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &root,
        );
        Self {
            root: root.der().as_ref().to_vec(),
            server,
            client,
        }
    }

    fn root_store(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.root.clone()))
            .expect("generated root");
        roots
    }

    fn root_pem(&self) -> String {
        pem("CERTIFICATE", &self.root)
    }

    fn server_tls(&self) -> ServerTlsConfig {
        ServerTlsConfig::new(
            self.root_store(),
            self.server.certificate_chain(),
            self.server.private_key(),
        )
        .expect("server TLS")
    }
}

fn certificate_authority() -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate().expect("test CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    params
        .distinguished_name
        .push(DnType::CommonName, "automata process e2e root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, key).expect("self-signed test CA")
}

fn leaf_identity(
    name: &str,
    subject_alt_names: Vec<String>,
    purpose: ExtendedKeyUsagePurpose,
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> Identity {
    let key = KeyPair::generate().expect("test leaf key");
    let mut params = CertificateParams::new(subject_alt_names).expect("leaf parameters");
    params.distinguished_name.push(DnType::CommonName, name);
    params.extended_key_usages = vec![purpose];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let certificate = params.signed_by(&key, issuer).expect("signed test leaf");
    Identity {
        certificate: certificate.der().as_ref().to_vec(),
        private_key: key.serialize_der(),
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut value = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        value.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        value.push('\n');
    }
    writeln!(value, "-----END {label}-----").expect("write PEM footer");
    value
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)]
fn write_runner_config(
    root: &Path,
    runner_id: RunnerId,
    control_address: SocketAddr,
    s3_address: SocketAddr,
) -> PathBuf {
    let journal = root.join("journal");
    let spool = root.join("spool");
    let virtualization = required_macos_vm_environment(VM_STORAGE_ROOT_ENV);
    let helper = required_macos_vm_environment(VM_HELPER_ENV);
    let helper_sha256 = required_macos_vm_environment(VM_HELPER_SHA256_ENV);
    let helper_requirement = required_macos_vm_environment(VM_HELPER_REQUIREMENT_ENV);
    let template_manifest = required_macos_vm_environment(VM_TEMPLATE_MANIFEST_ENV);
    let template_sha256 = process_profile_digest().to_string();
    let storage_volume_uuid = required_macos_vm_environment(VM_STORAGE_VOLUME_UUID_ENV);
    let storage_quota_bytes = required_macos_storage_quota_bytes();
    let config = json!({
        "schema_version": RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION,
        "runner_id": runner_id.to_string(),
        "control_endpoint": format!("https://{control_address}/"),
        "state": {
            "journal": journal,
            "spool": spool,
            "macos_virtualization": virtualization,
        },
        "tls": {
            "server_roots": {"kind": "environment", "name": "AUTOMATA_PROCESS_E2E_SERVER_ROOTS_PEM"},
            "certificate_chain": {"kind": "environment", "name": "AUTOMATA_PROCESS_E2E_CERTIFICATE_CHAIN_PEM"},
            "private_key": {"kind": "environment", "name": "AUTOMATA_PROCESS_E2E_PRIVATE_KEY_PEM"},
        },
        "spool": {
            "protection_id": "macos-process-e2e-key-v1",
            "key_hex": {"kind": "environment", "name": "AUTOMATA_PROCESS_E2E_SPOOL_KEY_HEX"},
            "decrypt_only": [],
        },
        "inventory": {
            "labels": ["self-hosted", "macos", "arm64"],
            "groups": ["default"],
            "max_parallel_jobs": 1,
            "resources_per_job": {
                "cpu_millis": 4000,
                "memory_bytes": 8_589_934_592_u64,
                "ephemeral_disk_bytes": 0,
                "pids": 512,
            },
            "environment_profiles": [{
                "id": PROFILE_ID,
                "manifest_sha256": template_sha256.clone(),
                "workspace": "/Users/automata-job/workspaces",
                "default_environment": {},
            }],
        },
        "macos_virtualization": {
            "helper_executable": helper,
            "helper_sha256": helper_sha256,
            "helper_code_requirement": helper_requirement,
            "template_manifest": template_manifest,
            "template_manifest_sha256": template_sha256,
            "storage_volume_uuid": storage_volume_uuid,
            "storage_quota_bytes": storage_quota_bytes,
            "boot_timeout_seconds": 300,
            "stop_timeout_seconds": 10,
        },
        "executor": {
            "resources": {
                "cpu_millis": 4000,
                "memory_bytes": 8_589_934_592_u64,
                "ephemeral_disk_bytes": 0,
                "pids": 512,
            },
            "network": "disabled",
            "root_filesystem": "writable",
            "privilege": "unprivileged",
            "default_step_timeout_seconds": 60,
            "maximum_output_bytes": 1_048_576,
            "runner_root": "/Users/automata-job/runner",
            "home": "/Users/automata-job",
            "path": "/Library/Automata/externals/node24/bin:/Library/Automata/externals/node20/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "temp": "/Users/automata-job/tmp",
            "tool_cache": "/Users/automata-job/tool-cache",
            "toolchain": {
                "bash": "/bin/bash",
                "sh": "/bin/sh",
                "python": null,
                "pwsh": null,
                "powershell": null,
                "cmd": null,
                "install": "/usr/bin/install",
                "tar": "/usr/bin/tar",
                "sha256sum": "/usr/bin/shasum",
                "node12": null,
                "node16": null,
                "node20": "/Library/Automata/externals/node20/bin/node",
                "node24": "/Library/Automata/externals/node24/bin/node",
            },
        },
        "object_store": {
            "endpoint": format!("http://{s3_address}/"),
            "region": "us-east-1",
            "bucket": S3_BUCKET,
            "prefix": S3_PREFIX,
            "loopback_development": true,
            "tls_trust": {"mode": "web_pki"},
            "operation_timeout_seconds": 5,
            "access_key_id": {"kind": "environment", "name": "AUTOMATA_PROCESS_E2E_S3_ACCESS_KEY"},
            "secret_access_key": {"kind": "environment", "name": "AUTOMATA_PROCESS_E2E_S3_SECRET_KEY"},
        },
        "github": {
            "user_agent": "automata-runner-process-e2e/0.1.0",
            "server_url": "https://github.com/",
            "api_url": "https://api.github.com/",
            "graphql_url": "https://api.github.com/graphql",
        },
    });
    let config_path = root.join("runner.macos.process-e2e.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("encode runner config"),
    )
    .expect("write runner config");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("restrict runner config");
    config_path
}

#[cfg(target_os = "macos")]
fn required_macos_vm_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

#[cfg(target_os = "macos")]
fn required_macos_storage_quota_bytes() -> u64 {
    parse_macos_storage_quota_bytes(&required_macos_vm_environment(VM_STORAGE_QUOTA_BYTES_ENV))
        .unwrap_or_else(|| panic!("{VM_STORAGE_QUOTA_BYTES_ENV} must be a decimal byte count"))
}

#[cfg(target_os = "macos")]
fn parse_macos_storage_quota_bytes(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

#[cfg(target_os = "macos")]
#[test]
fn macos_storage_quota_requires_one_decimal_byte_count() {
    assert_eq!(
        parse_macos_storage_quota_bytes("107374182400").unwrap(),
        107_374_182_400
    );
    for invalid in ["", " 107374182400", "+107374182400", "100GiB"] {
        assert!(parse_macos_storage_quota_bytes(invalid).is_none());
    }
}

struct TemporaryRoot {
    parent: PathBuf,
    path: PathBuf,
}

impl TemporaryRoot {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical macOS temp root");
        let path = parent.join(format!(
            "automata-runner-process-e2e-{}",
            RunnerSessionId::new()
        ));
        fs::create_dir(&path).expect("create process E2E root");
        Self { parent, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("automata-runner-process-e2e-"));
        if safe_name && self.path.parent() == Some(self.parent.as_path()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn unix_millis() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch");
    i64::try_from(duration.as_millis()).expect("current Unix milliseconds fit i64")
}
