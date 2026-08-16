use std::{
    collections::BTreeMap,
    num::NonZeroU16,
    str::FromStr as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use automata_ci_core::{OperationId, RunnerId};
use automata_ci_execution::{
    Cancellation, CancellationDisposition, CopyFromRequest, CopyToRequest, EnvironmentProfile,
    EnvironmentProfileId, ExecutionArgv, ExecutionCommand, ExecutionEnvironment,
    ExecutionErrorKind, ExecutionTermination, NeverCancelled, ResourceLimits, RootFilesystemPolicy,
    SandboxCustody, SandboxGeneration, SandboxProvider, SandboxState, TargetPath,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestRejection, GuestRequest, GuestResponse, decode_frame, encode_frame,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::*;
use crate::{
    ComposeFrontend, DockerConnection, Engine, EngineArchitecture, EngineEndpoint, EngineSelection,
    InstallationName,
    engine::{
        AnchorEngineApi, EngineApi, EngineExecOutput, EngineFacts, InspectedVolume,
        PreparedEngineExec,
    },
};

const JOB_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GUEST_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROFILE_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const JOB_IMAGE_ID: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const GUEST_IMAGE_ID: &str =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const FAKE_GUEST: &[u8] = b"fake-automata-ci-sandbox-guest";

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    CreateContainer(ContainerDefinition),
    StartContainer(String),
    RemoveContainer(String),
    KillContainer(String),
    UploadArchive(String),
    CreateExec(Vec<String>, String),
    StartExec(Vec<String>),
}

#[derive(Clone)]
struct CachedGuestResponse {
    fingerprint: [u8; 32],
    response: GuestResponse,
}

#[allow(clippy::struct_excessive_bools)]
struct FakeState {
    facts: EngineFacts,
    images: BTreeMap<String, InspectedImage>,
    volumes: BTreeMap<String, InspectedVolume>,
    containers: BTreeMap<String, InspectedContainer>,
    guest_binaries: BTreeMap<String, Vec<u8>>,
    files: BTreeMap<String, Vec<u8>>,
    prepared: BTreeMap<String, (String, Vec<String>, String)>,
    replay: BTreeMap<String, CachedGuestResponse>,
    replay_capacity: usize,
    guest_executions: usize,
    lose_next_bootstrap_response: bool,
    reject_bootstrap: bool,
    bootstrap_ready: bool,
    invalid_guest_source_archive: bool,
    replace_after_upload: bool,
    replace_after_start: bool,
    replace_after_probe: bool,
    block_next_guest_start: bool,
    replace_job_after_boundaries: Option<usize>,
    cancel_after_boundaries: Option<(usize, Arc<AtomicBool>)>,
    recreate_first_removed_after_following_remove: bool,
    first_removed_for_recreation: Option<InspectedContainer>,
    block_next_guest_exec: bool,
    boundary_permit: bool,
    calls: Vec<Call>,
    next_id: u64,
}

impl FakeState {
    fn new() -> Self {
        Self {
            facts: EngineFacts {
                engine_id: "engine-identity".to_owned(),
                server_version: "29.7.2".to_owned(),
                minimum_api_version: "1.40".to_owned(),
                maximum_api_version: "1.55".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
            },
            images: BTreeMap::new(),
            volumes: BTreeMap::new(),
            containers: BTreeMap::new(),
            guest_binaries: BTreeMap::new(),
            files: BTreeMap::new(),
            prepared: BTreeMap::new(),
            replay: BTreeMap::new(),
            replay_capacity: 256,
            guest_executions: 0,
            lose_next_bootstrap_response: false,
            reject_bootstrap: false,
            bootstrap_ready: false,
            invalid_guest_source_archive: false,
            replace_after_upload: false,
            replace_after_start: false,
            replace_after_probe: false,
            block_next_guest_start: false,
            replace_job_after_boundaries: None,
            cancel_after_boundaries: None,
            recreate_first_removed_after_following_remove: false,
            first_removed_for_recreation: None,
            block_next_guest_exec: false,
            boundary_permit: false,
            calls: Vec::new(),
            next_id: 1,
        }
    }

    fn object_id(&mut self) -> String {
        let id = format!("{:064x}", self.next_id);
        self.next_id += 1;
        id
    }

    fn consume_boundary(&mut self) -> Result<(), EngineApiError> {
        if !std::mem::take(&mut self.boundary_permit) {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(())
    }
}

struct FakeEngine {
    anchor_name: String,
    state: Mutex<FakeState>,
    guest_exec_blocked: AtomicBool,
    release_guest_exec: AtomicBool,
    fail_released_guest_exec: AtomicBool,
    accesses: AtomicUsize,
}

impl FakeEngine {
    fn new(installation: &Installation) -> Self {
        let mut state = FakeState::new();
        let job = job_image();
        let guest = guest_image();
        state.images.insert(
            job.reference().to_owned(),
            inspected_image(&job, JOB_IMAGE_ID),
        );
        state.images.insert(
            guest.reference().to_owned(),
            inspected_image(&guest, GUEST_IMAGE_ID),
        );
        let anchor_name = installation.anchor_volume_name().to_owned();
        state.volumes.insert(
            anchor_name.clone(),
            InspectedVolume {
                name: anchor_name.clone(),
                driver: "local".to_owned(),
                scope: "local".to_owned(),
                options: BTreeMap::new(),
                labels: BTreeMap::from([
                    ("io.automata.local.managed".to_owned(), "true".to_owned()),
                    (
                        "io.automata.local.identity-schema".to_owned(),
                        "1".to_owned(),
                    ),
                    (
                        "io.automata.local.installation-id".to_owned(),
                        installation.id().to_string(),
                    ),
                    (
                        "io.automata.local.installation-key".to_owned(),
                        installation.selector_key().to_string(),
                    ),
                    (
                        "io.automata.local.compose-project".to_owned(),
                        installation.compose_project().to_string(),
                    ),
                    (
                        "io.automata.local.resource-kind".to_owned(),
                        "identity-anchor".to_owned(),
                    ),
                ]),
            },
        );
        Self {
            anchor_name,
            state: Mutex::new(state),
            guest_exec_blocked: AtomicBool::new(false),
            release_guest_exec: AtomicBool::new(false),
            fail_released_guest_exec: AtomicBool::new(false),
            accesses: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.state.lock().expect("fake state").calls.clone()
    }

    fn mutate(&self, update: impl FnOnce(&mut FakeState)) {
        update(&mut self.state.lock().expect("fake state"));
    }

    fn container(&self, name: &str) -> Option<InspectedContainer> {
        self.state
            .lock()
            .expect("fake state")
            .containers
            .get(name)
            .cloned()
    }

    fn mutation_count(&self) -> usize {
        self.calls().len()
    }

    fn access_count(&self) -> usize {
        self.accesses.load(Ordering::SeqCst)
    }

    fn guest_executions(&self) -> usize {
        self.state.lock().expect("fake state").guest_executions
    }

    fn guest_response(&self, request: GuestRequest) -> Result<GuestResponse, EngineApiError> {
        let fingerprint: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&request).map_err(|_| EngineApiError::InvalidResponse)?,
        )
        .into();
        let operation_id = guest_operation_id(&request).to_owned();
        let mut state = self.state.lock().expect("fake state");
        if let Some(cached) = state.replay.get(&operation_id) {
            return Ok(if cached.fingerprint == fingerprint {
                cached.response.clone()
            } else {
                rejected(GuestRejection::OperationConflict)
            });
        }
        if state.replay.len() >= state.replay_capacity {
            return Ok(rejected(GuestRejection::ReplayCapacityExceeded));
        }
        let response = match request {
            GuestRequest::Probe { .. } => GuestResponse::Ready {
                protocol: GUEST_PROTOCOL_VERSION,
            },
            GuestRequest::Exec { .. } => serde_json::from_value(serde_json::json!({
                "result": "exec",
                "protocol": GUEST_PROTOCOL_VERSION,
                "termination": {"kind": "exited", "code": 0},
                "records": [
                    {"stream": "stdout", "data_base64": BASE64.encode(b"ok"), "end_of_stream": false},
                    {"stream": "stdout", "data_base64": "", "end_of_stream": true},
                    {"stream": "stderr", "data_base64": "", "end_of_stream": true}
                ],
                "truncated": false
            }))
            .map_err(|_| EngineApiError::InvalidResponse)?,
            GuestRequest::WriteFile {
                path,
                content_base64,
                ..
            } => {
                let content = BASE64
                    .decode(content_base64)
                    .map_err(|_| EngineApiError::InvalidResponse)?;
                state.files.insert(path, content);
                GuestResponse::WriteFile {
                    protocol: GUEST_PROTOCOL_VERSION,
                }
            }
            GuestRequest::ReadFile { path, byte_limit, .. } => {
                let content = state
                    .files
                    .get(&path)
                    .filter(|content| content.len() <= byte_limit)
                    .cloned()
                    .ok_or(EngineApiError::InvalidResponse)?;
                GuestResponse::ReadFile {
                    protocol: GUEST_PROTOCOL_VERSION,
                    content_base64: BASE64.encode(content),
                }
            }
            _ => return Err(EngineApiError::InvalidResponse),
        };
        state.guest_executions += 1;
        state.replay.insert(
            operation_id,
            CachedGuestResponse {
                fingerprint,
                response: response.clone(),
            },
        );
        Ok(response)
    }
}

#[async_trait]
impl EngineApi for FakeEngine {
    async fn engine_facts(&self) -> Result<EngineFacts, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        Ok(self.state.lock().expect("fake state").facts.clone())
    }
}

#[async_trait]
impl AnchorEngineApi for FakeEngine {
    async fn inspect_volume(&self, name: &str) -> Result<Option<InspectedVolume>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .state
            .lock()
            .expect("fake state")
            .volumes
            .get(name)
            .cloned())
    }

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        if name != self.anchor_name || !state.volumes.contains_key(name) {
            return Err(EngineApiError::InvalidResponse);
        }
        state.boundary_permit = true;
        if let Some((remaining, cancelled)) = state.cancel_after_boundaries.take() {
            if remaining == 1 {
                cancelled.store(true, Ordering::SeqCst);
            } else {
                state.cancel_after_boundaries = Some((remaining - 1, cancelled));
            }
        }
        if let Some(remaining) = state.replace_job_after_boundaries.take() {
            if remaining == 1 {
                let id = state
                    .containers
                    .values()
                    .find(|container| container.definition.name.ends_with("-job"))
                    .map(|container| container.id.clone())
                    .ok_or(EngineApiError::InvalidResponse)?;
                replace_container(&mut state, &id)?;
            } else {
                state.replace_job_after_boundaries = Some(remaining - 1);
            }
        }
        Ok(Vec::new())
    }
}

#[async_trait]
impl SandboxEngineApi for FakeEngine {
    async fn inspect_image(
        &self,
        reference: &str,
    ) -> Result<Option<InspectedImage>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .state
            .lock()
            .expect("fake state")
            .images
            .get(reference)
            .cloned())
    }

    async fn inspect_container(
        &self,
        name: &str,
    ) -> Result<Option<InspectedContainer>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .state
            .lock()
            .expect("fake state")
            .containers
            .get(name)
            .cloned())
    }

    async fn create_container(
        &self,
        definition: ContainerDefinition,
    ) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::CreateContainer(definition.clone()));
        if state.containers.contains_key(&definition.name) {
            return Err(EngineApiError::RequestFailed);
        }
        let image_id = state
            .images
            .get(&definition.image)
            .ok_or(EngineApiError::InvalidResponse)?
            .id
            .clone();
        let id = state.object_id();
        state.containers.insert(
            definition.name.clone(),
            InspectedContainer {
                id,
                image_id,
                definition,
                state: EngineContainerState::Created,
                isolated: true,
            },
        );
        Ok(())
    }

    async fn start_container(&self, id: &str) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::StartContainer(id.to_owned()));
        find_container_mut(&mut state, id)?.state = EngineContainerState::Running;
        if std::mem::take(&mut state.replace_after_start) {
            replace_container(&mut state, id)?;
        }
        Ok(())
    }

    async fn remove_container(&self, id: &str) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::RemoveContainer(id.to_owned()));
        let name = state
            .containers
            .iter()
            .find_map(|(name, container)| (container.id == id).then(|| name.clone()));
        let removed = name.and_then(|name| state.containers.remove(&name));
        if state.recreate_first_removed_after_following_remove {
            if let Some(mut first) = state.first_removed_for_recreation.take() {
                first.id = state.object_id();
                state
                    .containers
                    .insert(first.definition.name.clone(), first);
                state.recreate_first_removed_after_following_remove = false;
            } else {
                state.first_removed_for_recreation = removed;
            }
        }
        state.guest_binaries.remove(id);
        Ok(())
    }

    async fn kill_container(&self, id: &str) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::KillContainer(id.to_owned()));
        find_container_mut(&mut state, id)?.state = EngineContainerState::Exited(137);
        Ok(())
    }

    async fn download_guest_image_binary(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().expect("fake state");
        state
            .containers
            .values()
            .find(|container| container.id == id)
            .filter(|container| {
                container.definition.name.ends_with("-guest-source")
                    && container.state == EngineContainerState::Created
            })
            .ok_or(EngineApiError::InvalidResponse)?;
        let archive = if state.invalid_guest_source_archive {
            two_file_archive(FAKE_GUEST)
        } else {
            guest_archive(FAKE_GUEST)
        }?;
        if archive.len() > byte_limit {
            return Err(EngineApiError::OutputLimit);
        }
        Ok(archive)
    }

    async fn download_sandbox_guest(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().expect("fake state");
        let bytes = state
            .guest_binaries
            .get(id)
            .ok_or(EngineApiError::InvalidResponse)?;
        let archive = guest_archive(bytes)?;
        if archive.len() > byte_limit {
            return Err(EngineApiError::OutputLimit);
        }
        Ok(archive)
    }

    async fn upload_sandbox_archive(&self, id: &str, archive: &[u8]) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::UploadArchive(id.to_owned()));
        let guest = extract_uploaded_guest(archive)?;
        state.guest_binaries.insert(id.to_owned(), guest);
        if std::mem::take(&mut state.replace_after_upload) {
            replace_container(&mut state, id)?;
        }
        Ok(())
    }

    async fn create_exec(
        &self,
        container_id: &str,
        command: &[String],
        user: &str,
    ) -> Result<PreparedEngineExec, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        if !state
            .containers
            .values()
            .any(|container| container.id == container_id)
        {
            return Err(EngineApiError::InvalidResponse);
        }
        state
            .calls
            .push(Call::CreateExec(command.to_vec(), user.to_owned()));
        let id = state.object_id();
        state.prepared.insert(
            id.clone(),
            (container_id.to_owned(), command.to_vec(), user.to_owned()),
        );
        Ok(PreparedEngineExec {
            id,
            container_id: container_id.to_owned(),
            command: command.to_vec(),
            user: user.to_owned(),
        })
    }

    async fn start_exec(
        &self,
        prepared: &PreparedEngineExec,
        request: &EngineExecRequest,
    ) -> Result<EngineExecOutput, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let command = {
            let mut state = self.state.lock().expect("fake state");
            state.consume_boundary()?;
            let (container_id, command, user) = state
                .prepared
                .remove(&prepared.id)
                .ok_or(EngineApiError::InvalidResponse)?;
            if container_id != request.container_id
                || prepared.container_id != request.container_id
                || prepared.command != request.command
                || user != request.user
                || prepared.user != request.user
            {
                return Err(EngineApiError::InvalidResponse);
            }
            state.calls.push(Call::StartExec(command.clone()));
            command
        };
        if command.get(1).map(String::as_str) == Some("bootstrap-local-client") {
            let mut state = self.state.lock().expect("fake state");
            if state.reject_bootstrap {
                return Ok(EngineExecOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: 1,
                });
            }
            state.bootstrap_ready = true;
            if std::mem::take(&mut state.lose_next_bootstrap_response) {
                return Err(EngineApiError::RequestFailed);
            }
            return Ok(EngineExecOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            });
        }
        if !self.state.lock().expect("fake state").bootstrap_ready {
            return Err(EngineApiError::RequestFailed);
        }
        let guest_request: GuestRequest =
            decode_frame(&request.stdin).map_err(|_| EngineApiError::InvalidResponse)?;
        let block = {
            let mut state = self.state.lock().expect("fake state");
            if state.block_next_guest_start {
                state.block_next_guest_start = false;
                true
            } else if matches!(&guest_request, GuestRequest::Exec { .. })
                && state.block_next_guest_exec
            {
                state.block_next_guest_exec = false;
                true
            } else {
                false
            }
        };
        if block {
            self.guest_exec_blocked.store(true, Ordering::SeqCst);
            while !self.release_guest_exec.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            self.guest_exec_blocked.store(false, Ordering::SeqCst);
            self.release_guest_exec.store(false, Ordering::SeqCst);
            if self.fail_released_guest_exec.swap(false, Ordering::SeqCst) {
                return Err(EngineApiError::RequestFailed);
            }
        }
        let is_probe = matches!(&guest_request, GuestRequest::Probe { .. });
        let response = self.guest_response(guest_request)?;
        if is_probe {
            let mut state = self.state.lock().expect("fake state");
            if std::mem::take(&mut state.replace_after_probe) {
                replace_container(&mut state, &request.container_id)?;
            }
        }
        let stdout = encode_frame(&response).map_err(|_| EngineApiError::InvalidResponse)?;
        if stdout.len() > request.stdout_limit {
            return Err(EngineApiError::OutputLimit);
        }
        Ok(EngineExecOutput {
            stdout,
            stderr: Vec::new(),
            exit_code: 0,
        })
    }
}

fn find_container_mut<'a>(
    state: &'a mut FakeState,
    id: &str,
) -> Result<&'a mut InspectedContainer, EngineApiError> {
    state
        .containers
        .values_mut()
        .find(|container| container.id == id)
        .ok_or(EngineApiError::InvalidResponse)
}

fn replace_container(state: &mut FakeState, id: &str) -> Result<(), EngineApiError> {
    let (name, mut replacement) = state
        .containers
        .iter()
        .find(|(_, container)| container.id == id)
        .map(|(name, container)| (name.clone(), container.clone()))
        .ok_or(EngineApiError::InvalidResponse)?;
    let replacement_id = state.object_id();
    replacement.id = replacement_id.clone();
    state.containers.insert(name, replacement);
    if let Some(guest) = state.guest_binaries.remove(id) {
        state.guest_binaries.insert(replacement_id, guest);
    }
    Ok(())
}

fn guest_operation_id(request: &GuestRequest) -> &str {
    match request {
        GuestRequest::Probe { operation_id, .. }
        | GuestRequest::Hello { operation_id, .. }
        | GuestRequest::Configure { operation_id, .. }
        | GuestRequest::Exec { operation_id, .. }
        | GuestRequest::WriteFile { operation_id, .. }
        | GuestRequest::AtomicCommitFile { operation_id, .. }
        | GuestRequest::ReadFile { operation_id, .. }
        | GuestRequest::ReadOptionalFile { operation_id, .. } => operation_id,
    }
}

fn rejected(kind: GuestRejection) -> GuestResponse {
    GuestResponse::Rejected {
        protocol: GUEST_PROTOCOL_VERSION,
        kind,
    }
}

fn guest_archive(bytes: &[u8]) -> Result<Vec<u8>, EngineApiError> {
    archive_with_files(&[("automata-ci-sandbox-guest", bytes)])
}

fn two_file_archive(bytes: &[u8]) -> Result<Vec<u8>, EngineApiError> {
    archive_with_files(&[
        ("automata-ci-sandbox-guest", bytes),
        ("foreign", b"collision"),
    ])
}

fn archive_with_files(files: &[(&str, &[u8])]) -> Result<Vec<u8>, EngineApiError> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o555);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(u64::try_from(bytes.len()).map_err(|_| EngineApiError::OutputLimit)?);
        header
            .set_path(path)
            .map_err(|_| EngineApiError::InvalidResponse)?;
        header.set_cksum();
        builder
            .append(&header, *bytes)
            .map_err(|_| EngineApiError::InvalidResponse)?;
    }
    builder
        .into_inner()
        .map_err(|_| EngineApiError::InvalidResponse)
}

fn extract_uploaded_guest(archive: &[u8]) -> Result<Vec<u8>, EngineApiError> {
    let mut tar = tar::Archive::new(archive);
    let mut guest = None;
    for entry in tar.entries().map_err(|_| EngineApiError::InvalidResponse)? {
        let mut entry = entry.map_err(|_| EngineApiError::InvalidResponse)?;
        if entry
            .path()
            .map_err(|_| EngineApiError::InvalidResponse)?
            .as_ref()
            == std::path::Path::new("automata/bin/automata-ci-sandbox-guest")
        {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes)
                .map_err(|_| EngineApiError::InvalidResponse)?;
            guest = Some(bytes);
        }
    }
    guest.ok_or(EngineApiError::InvalidResponse)
}

struct Fixture {
    provider: LocalDockerProvider,
    engine: Arc<FakeEngine>,
    installation: Installation,
}

impl Fixture {
    fn new() -> Self {
        let installation = Installation::new(
            InstallationName::new("test").expect("installation name"),
            InstallationId::new(),
        );
        let engine = Arc::new(FakeEngine::new(&installation));
        let provider = LocalDockerProvider::with_test_engine(
            PinnedDockerEngine::for_test(&selection(), engine.clone()),
            engine.clone(),
            installation.clone(),
            guest_image(),
            GUEST_IMAGE_ID.to_owned(),
        );
        Self {
            provider,
            engine,
            installation,
        }
    }

    fn reopen_provider(&self) -> LocalDockerProvider {
        LocalDockerProvider::with_test_engine(
            PinnedDockerEngine::for_test(&selection(), self.engine.clone()),
            self.engine.clone(),
            self.installation.clone(),
            guest_image(),
            GUEST_IMAGE_ID.to_owned(),
        )
    }
}

fn selection() -> EngineSelection {
    EngineSelection {
        engine: Engine::Docker,
        compose: ComposeFrontend::DockerPlugin,
        context_name: "default".to_owned(),
        endpoint: EngineEndpoint::UnixSocket,
        engine_id: "engine-identity".to_owned(),
        server_version: "29.7.2".to_owned(),
        api_version: "1.55".to_owned(),
        architecture: EngineArchitecture::Amd64,
        compose_version: "5.4.0".to_owned(),
        connection: DockerConnection {
            context_name: "default".to_owned(),
            host: "unix:///var/run/docker.sock".to_owned(),
            endpoint: EngineEndpoint::UnixSocket,
        },
    }
}

fn inspected_image(image: &ImmutableImage, id: &str) -> InspectedImage {
    InspectedImage {
        id: id.to_owned(),
        repo_digests: vec![image.reference().to_owned()],
        operating_system: "linux".to_owned(),
        architecture: "amd64".to_owned(),
        declared_volumes: Vec::new(),
        labels: BTreeMap::new(),
        environment_names: Vec::new(),
    }
}

fn job_image() -> ImmutableImage {
    ImmutableImage::new(format!("registry.example/automata/job@sha256:{JOB_DIGEST}"))
        .expect("job image")
}

fn guest_image() -> ImmutableImage {
    ImmutableImage::new(format!(
        "registry.example/automata/guest@sha256:{GUEST_DIGEST}"
    ))
    .expect("guest image")
}

fn sandbox_spec() -> SandboxSpec {
    sandbox_spec_with_resources(ResourceLimits::new(256 * 1024 * 1024, 2_000, 128).expect("limits"))
}

fn sandbox_spec_with_resources(resources: ResourceLimits) -> SandboxSpec {
    sandbox_spec_with_custody_and_resources(
        SandboxCustody::Job {
            runner_id: RunnerId::from_uuid(Uuid::from_u128(2)),
            slot_ordinal: NonZeroU16::new(3).expect("slot"),
        },
        resources,
    )
}

fn sandbox_spec_with_custody_and_resources(
    custody: SandboxCustody,
    resources: ResourceLimits,
) -> SandboxSpec {
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("example.local/linux").expect("profile id"),
        Sha256Digest::from_str(PROFILE_DIGEST).expect("profile digest"),
    );
    let environment = automata_ci_execution::SandboxEnvironment::new(
        profile,
        job_image(),
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("program"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive"),
        TargetPath::posix("/workspace").expect("profile workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("environment");
    SandboxSpec::new(
        OperationId::from_uuid(Uuid::from_u128(1)),
        SandboxGeneration::new(7).expect("generation"),
        custody,
        environment,
        TargetPath::posix("/workspace/repository").expect("workspace"),
        NetworkPolicy::Disabled,
        RootFilesystemPolicy::Writable,
        resources,
    )
    .with_privilege(SandboxPrivilegePolicy::Administrator)
}

fn true_command(spec: &SandboxSpec, operation: u128) -> ExecutionCommand {
    ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(operation)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command")
}

#[derive(Clone, Debug)]
struct ToggleCancellation {
    cancelled: Arc<AtomicBool>,
    observations: Arc<AtomicUsize>,
}

impl ToggleCancellation {
    fn active() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            observations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl Cancellation for ToggleCancellation {
    fn disposition(&self) -> CancellationDisposition {
        self.observations.fetch_add(1, Ordering::SeqCst);
        if self.cancelled.load(Ordering::SeqCst) {
            CancellationDisposition::Terminate
        } else {
            CancellationDisposition::Active
        }
    }
}

fn wait_for_test(mut predicate: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < deadline, "{message}");
        std::thread::yield_now();
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn lifecycle_uses_zero_volumes_and_exact_replay_cleanup() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    assert_eq!(record.state(), SandboxState::Running);
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job container");
    assert_eq!(
        job.definition.tmpfs,
        BTreeMap::from([
            (
                "/workspace/repository".to_owned(),
                job_tmpfs_options(256 * 1024 * 1024),
            ),
            (
                LOCAL_CONTROL_DIRECTORY.to_owned(),
                guest_control_tmpfs_options(),
            ),
        ])
    );
    assert!(fixture.engine.container(&names.helper).is_none());
    assert_eq!(
        fixture.engine.state.lock().expect("state").volumes.len(),
        1,
        "the installation anchor is the only volume"
    );
    let calls = fixture.engine.calls();
    let source = calls
        .iter()
        .find_map(|call| match call {
            Call::CreateContainer(definition) if definition.name.ends_with("-guest-source") => {
                Some(definition)
            }
            _ => None,
        })
        .expect("guest source definition");
    assert_eq!(source.entrypoint, LOCAL_DOCKER_GUEST_IMAGE_BINARY);
    assert!(source.arguments.is_empty());
    assert!(source.tmpfs.is_empty());
    assert_eq!(source.user, guest_client_user());
    assert!(source.read_only_root);
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, Call::UploadArchive(_)))
    );
    assert!(calls.iter().any(|call| matches!(
        call,
        Call::CreateExec(command, user)
            if command == &[LOCAL_DOCKER_SANDBOX_GUEST_BINARY, "bootstrap-local-client"]
                && user == &guest_seal_user()
    )));
    assert!(
        calls
            .iter()
            .all(|call| { !matches!(call, Call::StartContainer(id) if id != &job.id) })
    );
    assert!(calls.iter().any(|call| matches!(
        call,
        Call::CreateExec(command, user)
            if command == &[LOCAL_CONTROL_CLIENT, "local-client"]
                && user == &guest_client_user()
    )));

    let starts_before = calls
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("exact replay");
    assert_eq!(replay, record);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_before, starts_after, "running replay never restarts");

    let reopened = fixture.reopen_provider();
    let inspection = reopened
        .inspect(record.handle(), &NeverCancelled)
        .expect("inspect");
    assert_eq!(inspection.state(), SandboxState::Running);
    assert_eq!(inspection.custody(), spec.custody());
    let endpoint = reopened
        .attach(record.handle(), &NeverCancelled)
        .expect("attach");
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(10)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    let output = endpoint.exec(&command, &NeverCancelled).expect("exec");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    assert_eq!(output.stdout(), b"ok");
    let path = TargetPath::posix("/workspace/repository/result.txt").expect("path");
    endpoint
        .copy_to(
            &CopyToRequest::new(
                OperationId::from_uuid(Uuid::from_u128(11)),
                path.clone(),
                b"artifact".to_vec(),
            )
            .expect("copy request"),
            &NeverCancelled,
        )
        .expect("copy to");
    assert_eq!(
        endpoint
            .copy_from(
                &CopyFromRequest::new(OperationId::from_uuid(Uuid::from_u128(12)), path, 64)
                    .expect("read request"),
                &NeverCancelled,
            )
            .expect("copy from"),
        b"artifact"
    );
    drop(endpoint);

    let destroy = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(13)),
        record.handle().clone(),
        record.generation(),
    );
    assert_eq!(
        reopened
            .destroy(&destroy, &NeverCancelled)
            .expect("destroy"),
        DestroyDisposition::Destroyed
    );
    assert_eq!(
        reopened
            .destroy(&destroy, &NeverCancelled)
            .expect("destroy replay"),
        DestroyDisposition::AlreadyAbsent
    );
    assert!(
        fixture
            .engine
            .state
            .lock()
            .expect("state")
            .containers
            .is_empty()
    );
}

#[test]
fn ambiguous_bootstrap_response_stops_and_removes_the_unproven_container() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.lose_next_bootstrap_response = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("ambiguous bootstrap is never accepted");
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    assert!(fixture.engine.container(&names.job).is_none());
    let calls = fixture.engine.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(
                call,
                Call::CreateExec(command, user)
                    if command == &[LOCAL_DOCKER_SANDBOX_GUEST_BINARY, "bootstrap-local-client"]
                        && user == &guest_seal_user()
            ))
            .count(),
        1
    );
}

#[test]
fn attach_probe_start_failure_stops_exact_job_and_never_restarts_it() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    fixture
        .engine
        .mutate(|state| state.block_next_guest_start = true);
    fixture
        .engine
        .fail_released_guest_exec
        .store(true, Ordering::SeqCst);

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| fixture.provider.attach(record.handle(), &NeverCancelled));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "attach probe did not reach the controlled start",
        );
        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        call.join()
            .expect("attach thread")
            .expect_err("uncertain probe start")
    });
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Exited(137)
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("exited job is never restarted");
    assert_eq!(replay.kind(), ProviderErrorKind::InvalidState);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_after, starts_before);
}

#[test]
fn cancelled_in_flight_attach_probe_stops_exact_job_before_returning() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_start = true);
    let cancellation = ToggleCancellation::active();

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| fixture.provider.attach(record.handle(), &cancellation));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "attach probe did not reach the controlled start",
        );
        cancellation.cancel();
        wait_for_test(
            || call.is_finished(),
            "cancelled attach did not stop the exact job within the bound",
        );
        call.join()
            .expect("attach thread")
            .expect_err("cancelled probe start")
    });
    fixture
        .engine
        .guest_exec_blocked
        .store(false, Ordering::SeqCst);
    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Exited(137)
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
}

#[test]
fn unready_bootstrap_is_destroyed_and_never_adopted_or_retried() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| state.reject_bootstrap = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("unready broker fails closed");
    assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
    assert!(fixture.engine.container(&names.job).is_none());
    let calls = fixture.engine.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(
                call,
                Call::CreateExec(command, user)
                    if command == &[LOCAL_DOCKER_SANDBOX_GUEST_BINARY, "bootstrap-local-client"]
                        && user == &guest_seal_user()
            ))
            .count(),
        1
    );
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, Call::KillContainer(_)))
    );
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, Call::RemoveContainer(_)))
    );
}

#[test]
fn exited_job_is_never_restarted() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job_id = fixture.engine.container(&names.job).expect("job").id;
    fixture.engine.mutate(|state| {
        find_container_mut(state, &job_id).expect("job").state = EngineContainerState::Exited(0);
    });
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job_id))
        .count();
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("stopped create replay must fail");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job_id))
        .count();
    assert_eq!(starts_before, starts_after);
}

#[test]
fn endpoint_cancellation_is_prechecked_then_kills_only_the_exact_running_container() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");

    let mutations_before_pre_cancel = fixture.engine.mutation_count();
    let pre_cancelled = ToggleCancellation::active();
    pre_cancelled.cancel();
    let error = endpoint
        .exec(&true_command(&spec, 300), &pre_cancelled)
        .expect_err("pre-cancelled exec");
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert_eq!(fixture.engine.mutation_count(), mutations_before_pre_cancel);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Running
    );

    fixture
        .engine
        .mutate(|state| state.block_next_guest_start = true);
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    let cancellation = ToggleCancellation::active();
    let request = true_command(&spec, 301);
    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| endpoint.exec(&request, &cancellation));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "endpoint did not reach the controlled guest start",
        );
        cancellation.cancel();
        wait_for_test(
            || call.is_finished(),
            "cancelled endpoint did not stop the exact job within the bound",
        );
        call.join()
            .expect("endpoint thread")
            .expect_err("mid-exec cancellation")
    });
    fixture
        .engine
        .guest_exec_blocked
        .store(false, Ordering::SeqCst);
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("stopped job")
            .state,
        EngineContainerState::Exited(137)
    );
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_after, starts_before, "cancellation never restarts");

    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("exited sandbox is not restartable");
    assert_eq!(replay.kind(), ProviderErrorKind::InvalidState);
    let final_starts = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(final_starts, starts_before);
}

#[test]
fn queued_endpoint_cancellation_returns_before_holder_release_and_mutates_nothing() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let first = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("first endpoint");
    let second = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("second endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let command = |operation| {
        ExecutionCommand::new(
            OperationId::from_uuid(Uuid::from_u128(operation)),
            ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
                .expect("argv"),
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(2),
            1024,
        )
        .expect("command")
    };
    let first_command = command(302);
    let second_command = command(303);
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    let cancellation = ToggleCancellation::active();

    std::thread::scope(|scope| {
        let first_call = scope.spawn(|| first.exec(&first_command, &NeverCancelled));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "first endpoint operation did not reach the controlled exec",
        );

        let queued_cancellation = cancellation.clone();
        let second_call = scope.spawn(move || second.exec(&second_command, &queued_cancellation));
        wait_for_test(
            || cancellation.observations.load(Ordering::SeqCst) > 0,
            "second endpoint operation did not reach its pre-lock cancellation check",
        );
        cancellation.cancel();
        let mutations_before_release = fixture.engine.mutation_count();
        wait_for_test(
            || second_call.is_finished(),
            "queued endpoint did not return within the cancellation bound",
        );
        let queued_error = second_call
            .join()
            .expect("second call thread")
            .expect_err("queued cancellation");
        assert_eq!(queued_error.kind(), ExecutionErrorKind::Cancelled);
        assert_eq!(fixture.engine.mutation_count(), mutations_before_release);

        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        let first_output = first_call
            .join()
            .expect("first call thread")
            .expect("first exec");
        assert_eq!(first_output.termination(), ExecutionTermination::Exited(0));
    });

    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("running job")
            .state,
        EngineContainerState::Running
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .all(|call| !matches!(call, Call::KillContainer(id) if id == &job.id))
    );
}

#[test]
fn queued_provider_cancellation_returns_before_holder_release_and_mutates_nothing() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let first_command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(304)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    let cancellation = ToggleCancellation::active();

    std::thread::scope(|scope| {
        let first_call = scope.spawn(|| endpoint.exec(&first_command, &NeverCancelled));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "endpoint operation did not reach the controlled exec",
        );

        let queued_cancellation = cancellation.clone();
        let provider = &fixture.provider;
        let handle = record.handle();
        let provider_call = scope.spawn(move || provider.inspect(handle, &queued_cancellation));
        wait_for_test(
            || cancellation.observations.load(Ordering::SeqCst) > 0,
            "provider operation did not reach cancellation-aware lock acquisition",
        );
        cancellation.cancel();
        let mutations_before_release = fixture.engine.mutation_count();
        wait_for_test(
            || provider_call.is_finished(),
            "queued provider call did not return within the cancellation bound",
        );
        let queued_error = provider_call
            .join()
            .expect("provider call thread")
            .expect_err("queued cancellation");
        assert_eq!(queued_error.kind(), ProviderErrorKind::Cancelled);
        assert_eq!(fixture.engine.mutation_count(), mutations_before_release);

        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        let first_output = first_call
            .join()
            .expect("endpoint call thread")
            .expect("first exec");
        assert_eq!(first_output.termination(), ExecutionTermination::Exited(0));
    });

    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("running job")
            .state,
        EngineContainerState::Running
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .all(|call| !matches!(call, Call::KillContainer(id) if id == &job.id))
    );
}

#[test]
fn cancellation_dominates_a_simultaneous_guest_transport_failure_and_stops_exact_job() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(304)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    fixture
        .engine
        .fail_released_guest_exec
        .store(true, Ordering::SeqCst);
    let cancellation = ToggleCancellation::active();

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| endpoint.exec(&command, &cancellation));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "guest transport did not reach the controlled failure",
        );
        cancellation.cancel();
        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        call.join()
            .expect("endpoint thread")
            .expect_err("terminal cancellation dominates transport failure")
    });
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("stopped job")
            .state,
        EngineContainerState::Exited(137)
    );
}

#[test]
fn uncertain_guest_transport_failure_stops_exact_job_and_never_restarts_it() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(305)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    fixture
        .engine
        .fail_released_guest_exec
        .store(true, Ordering::SeqCst);

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| endpoint.exec(&command, &NeverCancelled));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "guest transport did not reach the controlled failure",
        );
        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        call.join()
            .expect("endpoint thread")
            .expect_err("uncertain guest transport failure")
    });
    assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Exited(137)
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );

    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("exited job is never restarted");
    assert_eq!(replay.kind(), ProviderErrorKind::InvalidState);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_after, starts_before);
}

#[test]
fn cancellation_during_final_custody_reinspection_stops_exact_job() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let cancellation = ToggleCancellation::active();
    fixture.engine.mutate(|state| {
        state.cancel_after_boundaries = Some((4, Arc::clone(&cancellation.cancelled)));
    });
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(305)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");

    let error = endpoint
        .exec(&command, &cancellation)
        .expect_err("final verification cancellation");
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("stopped job")
            .state,
        EngineContainerState::Exited(137)
    );
}

#[test]
fn image_declared_volumes_are_rejected_before_mutation() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| {
        state
            .images
            .get_mut(job_image().reference())
            .expect("job image")
            .declared_volumes
            .push("/data".to_owned());
    });
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("image volume rejection");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn foreign_name_collision_fails_closed_without_mutation() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    fixture.engine.mutate(|state| {
        let id = state.object_id();
        state.containers.insert(
            names.job.clone(),
            InspectedContainer {
                id,
                image_id: JOB_IMAGE_ID.to_owned(),
                definition: ContainerDefinition {
                    name: names.job,
                    image: job_image().reference().to_owned(),
                    entrypoint: "/bin/false".to_owned(),
                    arguments: Vec::new(),
                    labels: BTreeMap::new(),
                    environment: Vec::new(),
                    tmpfs: BTreeMap::new(),
                    working_directory: "/".to_owned(),
                    user: "0:0".to_owned(),
                    read_only_root: false,
                    memory_bytes: 1,
                    nano_cpus: 1,
                    pids_limit: 1,
                },
                state: EngineContainerState::Created,
                isolated: false,
            },
        );
    });
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("foreign collision");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn adversarial_guest_source_archive_fails_before_job_creation() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.invalid_guest_source_archive = true);
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("multi-entry guest source archive");
    assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
    assert!(!fixture.engine.calls().iter().any(|call| {
        matches!(call, Call::CreateContainer(definition) if definition.name.ends_with("-job"))
    }));
}

#[test]
fn name_replacement_after_archive_upload_is_never_adopted_or_started() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.replace_after_upload = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("post-upload name replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    let replacement = fixture.engine.container(&names.job).expect("replacement");
    let calls = fixture.engine.calls();
    let uploaded_id = calls
        .iter()
        .find_map(|call| match call {
            Call::UploadArchive(id) => Some(id),
            _ => None,
        })
        .expect("upload call");
    assert_ne!(&replacement.id, uploaded_id);
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, Call::StartContainer(_)))
    );
}

#[test]
fn name_replacement_after_start_is_never_adopted_or_bootstrapped() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.replace_after_start = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("post-start name replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    let replacement = fixture.engine.container(&names.job).expect("replacement");
    let calls = fixture.engine.calls();
    let started_id = calls
        .iter()
        .find_map(|call| match call {
            Call::StartContainer(id) => Some(id),
            _ => None,
        })
        .expect("start call");
    assert_ne!(&replacement.id, started_id);
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, Call::CreateExec(_, _)))
    );
}

#[test]
fn name_replacement_after_fresh_readiness_probe_is_not_reported_running() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.replace_after_probe = true);
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("post-readiness replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
}

#[test]
fn name_replacement_after_recovery_probe_is_not_adopted() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("initial create");
    fixture
        .engine
        .mutate(|state| state.replace_after_probe = true);
    let error = fixture
        .reopen_provider()
        .create(&spec, &NeverCancelled)
        .expect_err("post-recovery-probe replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
}

#[test]
fn name_replacement_after_attach_probe_is_not_attached() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    fixture
        .engine
        .mutate(|state| state.replace_after_probe = true);
    let error = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect_err("post-attach-probe replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
}

#[test]
fn name_replacement_during_final_inspect_boundary_is_not_reported() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    fixture
        .engine
        .mutate(|state| state.replace_job_after_boundaries = Some(2));
    let error = fixture
        .provider
        .inspect(record.handle(), &NeverCancelled)
        .expect_err("final-boundary replacement must invalidate the snapshot");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
}

#[test]
fn destroy_rejects_a_helper_recreated_while_the_job_is_removed() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let mut base_labels = job.definition.labels;
    base_labels.remove(LABEL_RESOURCE_KIND);
    let definition = helper_definition(
        &names,
        guest_image().reference(),
        &BTreeMap::new(),
        &[],
        &base_labels,
    );
    let original_helper_id = fixture.engine.state.lock().expect("state").object_id();
    fixture.engine.mutate(|state| {
        state.containers.insert(
            names.helper.clone(),
            InspectedContainer {
                id: original_helper_id.clone(),
                image_id: GUEST_IMAGE_ID.to_owned(),
                definition,
                state: EngineContainerState::Created,
                isolated: true,
            },
        );
        state.recreate_first_removed_after_following_remove = true;
    });
    let request = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(200)),
        record.handle().clone(),
        record.generation(),
    );
    let error = fixture
        .provider
        .destroy(&request, &NeverCancelled)
        .expect_err("recreated deterministic helper name must prevent success");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert!(fixture.engine.container(&names.job).is_none());
    let recreated = fixture
        .engine
        .container(&names.helper)
        .expect("recreated helper remains foreign to cleanup success");
    assert_ne!(recreated.id, original_helper_id);
}

#[test]
fn live_replay_cache_replays_exact_requests_and_fails_before_capacity_execution() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    fixture.engine.mutate(|state| {
        // The provider's exact framed readiness probe permanently owns one
        // replay slot for this container lifetime.
        state.replay_capacity = 3;
    });
    let baseline_executions = fixture.engine.guest_executions();
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach");
    let first = CopyToRequest::new(
        OperationId::from_uuid(Uuid::from_u128(100)),
        TargetPath::posix("/workspace/repository/first").expect("path"),
        b"first".to_vec(),
    )
    .expect("request");
    endpoint
        .copy_to(&first, &NeverCancelled)
        .expect("first operation");
    assert_eq!(fixture.engine.guest_executions(), baseline_executions + 1);
    endpoint
        .copy_to(&first, &NeverCancelled)
        .expect("same live operation replays");
    assert_eq!(fixture.engine.guest_executions(), baseline_executions + 1);

    let second = CopyToRequest::new(
        OperationId::from_uuid(Uuid::from_u128(101)),
        TargetPath::posix("/workspace/repository/second").expect("path"),
        b"second".to_vec(),
    )
    .expect("request");
    endpoint
        .copy_to(&second, &NeverCancelled)
        .expect("second operation");
    assert_eq!(fixture.engine.guest_executions(), baseline_executions + 2);

    let third_path = "/workspace/repository/third";
    let third = CopyToRequest::new(
        OperationId::from_uuid(Uuid::from_u128(102)),
        TargetPath::posix(third_path).expect("path"),
        b"third".to_vec(),
    )
    .expect("request");
    let full = endpoint
        .copy_to(&third, &NeverCancelled)
        .expect_err("capacity rejection");
    assert_eq!(full.kind(), ExecutionErrorKind::BackendRejected);
    assert_eq!(fixture.engine.guest_executions(), baseline_executions + 2);
    assert!(
        !fixture
            .engine
            .state
            .lock()
            .expect("state")
            .files
            .contains_key(third_path)
    );
    endpoint
        .copy_to(&first, &NeverCancelled)
        .expect("old response remains non-evicting");
    assert_eq!(fixture.engine.guest_executions(), baseline_executions + 2);
}

#[test]
fn exact_realized_configuration_is_rechecked_on_attach() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    fixture.engine.mutate(|state| {
        state.containers.get_mut(&names.job).expect("job").isolated = false;
    });
    let error = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect_err("tampered isolation");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
}

#[test]
fn provider_does_not_advertise_restart_safe_endpoint_replay() {
    let fixture = Fixture::new();
    assert!(
        !fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::RestartSafeEndpointReplay)
    );
}

#[test]
fn undersized_resource_limits_are_rejected_before_engine_access() {
    for resources in [
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES - 1,
            1_000,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
        )
        .expect("low memory resources"),
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
            MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS - 1,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
        )
        .expect("low CPU resources"),
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
            MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS - 1,
        )
        .expect("low PID resources"),
    ] {
        let fixture = Fixture::new();
        let accesses = fixture.engine.access_count();
        let error = fixture
            .provider
            .create(&sandbox_spec_with_resources(resources), &NeverCancelled)
            .expect_err("provider infrastructure minimum");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        assert_eq!(fixture.engine.access_count(), accesses);
        assert_eq!(fixture.engine.mutation_count(), 0);
    }
}

#[test]
fn exact_minimum_resource_limits_are_realized_without_hidden_headroom() {
    let fixture = Fixture::new();
    let spec = sandbox_spec_with_resources(
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
            MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
        )
        .expect("minimum resources"),
    );
    fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("minimum resources are supported");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    assert_eq!(
        job.definition.memory_bytes,
        i64::try_from(MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES).expect("minimum fits i64")
    );
    assert_eq!(
        job.definition.nano_cpus,
        i64::from(MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS) * 1_000_000
    );
    assert_eq!(
        job.definition.pids_limit,
        i64::from(MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS)
    );
}

#[test]
fn unsupported_spec_shape_is_rejected_before_engine_access() {
    let fixture = Fixture::new();
    let spec = sandbox_spec().with_privilege(SandboxPrivilegePolicy::Unprivileged);
    let accesses = fixture.engine.access_count();
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("unsupported privilege");
    assert_eq!(error.kind(), ProviderErrorKind::UnsupportedCapability);
    assert_eq!(fixture.engine.access_count(), accesses);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn archive_builder_is_deterministic_and_contains_only_owned_paths() {
    let first = sandbox_archive("/workspace/repository", FAKE_GUEST).expect("archive");
    let second = sandbox_archive("/workspace/repository", FAKE_GUEST).expect("archive");
    assert_eq!(first, second);
    assert_eq!(extract_uploaded_guest(&first).expect("guest"), FAKE_GUEST);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the fixed relay, an existing installation anchor, and digest-pinned local images"]
#[allow(clippy::too_many_lines)]
async fn fixed_relay_live_shell_and_javascript_conformance() {
    let installation_name = InstallationName::new(
        std::env::var("AUTOMATA_LOCAL_DOCKER_INSTALLATION")
            .expect("set the existing test installation name"),
    )
    .expect("installation name");
    let installation_id = InstallationId::parse_canonical(
        &std::env::var("AUTOMATA_LOCAL_DOCKER_INSTALLATION_ID")
            .expect("set the existing installation UUID"),
    )
    .expect("canonical installation UUID");
    let job_image = ImmutableImage::new(
        std::env::var("AUTOMATA_LOCAL_DOCKER_JOB_IMAGE")
            .expect("set a present digest-pinned Linux job image"),
    )
    .expect("job image");
    let guest_image = ImmutableImage::new(
        std::env::var("AUTOMATA_LOCAL_DOCKER_GUEST_IMAGE")
            .expect("set a present digest-pinned sandbox-guest image"),
    )
    .expect("guest image");
    assert!(
        std::path::Path::new(crate::engine::LOCAL_DOCKER_RELAY_SOCKET).exists(),
        "install the explicit fixed Engine relay fixture"
    );
    let installation = Installation::new(installation_name, installation_id);
    let provider = LocalDockerProvider::connect(installation, guest_image)
        .await
        .expect("local Docker provider");
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.local/live-linux").expect("profile id"),
        Sha256Digest::from_str(PROFILE_DIGEST).expect("profile digest"),
    );
    let environment = automata_ci_execution::SandboxEnvironment::new(
        profile,
        job_image,
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("keepalive"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive argv"),
        TargetPath::posix("/workspace").expect("profile workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("environment");
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = SandboxSpec::new(
        OperationId::new(),
        generation,
        SandboxCustody::Job {
            runner_id: RunnerId::new(),
            slot_ordinal: NonZeroU16::new(1).expect("slot"),
        },
        environment,
        TargetPath::posix("/workspace/repository").expect("workspace"),
        NetworkPolicy::Disabled,
        RootFilesystemPolicy::Writable,
        ResourceLimits::new(512 * 1024 * 1024, 1_000, 128).expect("resources"),
    )
    .with_privilege(SandboxPrivilegePolicy::Administrator);
    let record = provider
        .create(&spec, &NeverCancelled)
        .expect("create live sandbox");
    let run = (|| -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = provider.attach(record.handle(), &NeverCancelled)?;
        for (program, arguments, expected) in [
            (
                "/bin/bash",
                vec!["-c".to_owned(), "printf shell-live".to_owned()],
                b"shell-live".as_slice(),
            ),
            (
                "/usr/bin/node",
                vec![
                    "-e".to_owned(),
                    "process.stdout.write('node-live')".to_owned(),
                ],
                b"node-live".as_slice(),
            ),
        ] {
            let command = ExecutionCommand::new(
                OperationId::new(),
                ExecutionArgv::new(TargetPath::posix(program)?, arguments)?,
                spec.workspace().clone(),
                ExecutionEnvironment::empty(),
                Duration::from_secs(10),
                64 * 1024,
            )?;
            let output = endpoint.exec(&command, &NeverCancelled)?;
            assert_eq!(output.termination(), ExecutionTermination::Exited(0));
            assert_eq!(output.stdout(), expected);
        }

        let protected_envelope = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/bin/bash")?,
                vec![
                    "-c".to_owned(),
                    format!(
                        "set -eu; test \"$(stat -c '%u:%g:%a' {directory})\" = '{seal_uid}:{gid}:{sealed_mode:o}'; ! dd if={client} of=/dev/null status=none 2>/dev/null; ! chmod 0700 {client} 2>/dev/null; ! sh -c 'printf tamper > {client}' 2>/dev/null; ! readlink /proc/1/exe >/dev/null 2>&1; kill -KILL 1; sleep 0.1; test -d /proc/1; printf protected-live",
                        directory = LOCAL_CONTROL_DIRECTORY,
                        seal_uid = LOCAL_CONTROL_SEAL_UID,
                        gid = LOCAL_CONTROL_GID,
                        sealed_mode =
                            automata_ci_sandbox_guest::LOCAL_CONTROL_DIRECTORY_MODE_SEALED,
                        client = LOCAL_CONTROL_CLIENT,
                    ),
                ],
            )?,
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(10),
            64 * 1024,
        )?;
        let output = endpoint.exec(&protected_envelope, &NeverCancelled)?;
        assert_eq!(output.termination(), ExecutionTermination::Exited(0));
        assert_eq!(output.stdout(), b"protected-live");

        let direct_broker = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/usr/bin/node")?,
                vec![
                    "-e".to_owned(),
                    concat!(
                        "const net=require('net');",
                        "const body=Buffer.from(JSON.stringify({operation:'probe',",
                        "protocol:5,operation_id:'untrusted-root-direct-probe'}));",
                        "const frame=Buffer.alloc(4+body.length);",
                        "frame.writeUInt32BE(body.length);body.copy(frame,4);",
                        "const socket=net.createConnection({path:'\\0automata-ci-control-v1'});",
                        "let received=0;socket.on('connect',()=>socket.end(frame));",
                        "socket.on('data',chunk=>received+=chunk.length);",
                        "socket.on('close',()=>process.exit(received===0?0:1));",
                        "socket.on('error',()=>process.exit(0));",
                        "setTimeout(()=>process.exit(1),1000)"
                    )
                    .to_owned(),
                ],
            )?,
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(5),
            64 * 1024,
        )?;
        assert_eq!(
            endpoint
                .exec(&direct_broker, &NeverCancelled)?
                .termination(),
            ExecutionTermination::Exited(0),
            "capless root must not receive a broker response"
        );

        let forbidden_bootstrap = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix(LOCAL_DOCKER_SANDBOX_GUEST_BINARY)?,
                vec!["bootstrap-local-client".to_owned()],
            )?,
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(5),
            64 * 1024,
        )?;
        assert_eq!(
            endpoint
                .exec(&forbidden_bootstrap, &NeverCancelled)?
                .termination(),
            ExecutionTermination::Exited(1),
            "capless root cannot reopen the one-shot sealer"
        );

        let after_signal = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/bin/bash")?,
                vec!["-c".to_owned(), "printf broker-still-ready".to_owned()],
            )?,
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(5),
            64 * 1024,
        )?;
        let output = endpoint.exec(&after_signal, &NeverCancelled)?;
        assert_eq!(output.termination(), ExecutionTermination::Exited(0));
        assert_eq!(output.stdout(), b"broker-still-ready");
        Ok(())
    })();
    provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), record.handle().clone(), generation),
            &NeverCancelled,
        )
        .expect("destroy exact live sandbox");
    run.expect("live shell and JavaScript conformance");
}
