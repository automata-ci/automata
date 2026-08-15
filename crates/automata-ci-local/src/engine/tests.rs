use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use super::{
    CreateVolume, DockerInstallationAdapter, EngineApi, EngineApiError, EngineFacts,
    IDENTITY_ANCHOR_KIND, IDENTITY_SCHEMA, InspectedVolume, LABEL_COMPOSE_PROJECT,
    LABEL_IDENTITY_SCHEMA, LABEL_INSTALLATION_ID, LABEL_INSTALLATION_KEY, LABEL_MANAGED,
    LABEL_RESOURCE_KIND, LocalEngineErrorCode, MANAGED_VALUE, adapter_api_version, identity_labels,
};
use crate::{
    ComposeFrontend, DockerConnection, Engine, EngineArchitecture, EngineEndpoint, EngineSelection,
    Installation, InstallationId, InstallationName,
};

type VolumeMutation = Box<dyn Fn(&mut InspectedVolume) + Send + Sync>;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    EngineFacts,
    Inspect(String),
    Create(String),
    Attachments(String),
}

#[derive(Clone, Debug)]
enum CreateBehavior {
    Apply,
    ApplyThenFail,
    SucceedWithoutCreating,
    ConcurrentWinner(InspectedVolume),
}

struct FakeState {
    facts: EngineFacts,
    queued_facts: VecDeque<Result<EngineFacts, EngineApiError>>,
    volumes: BTreeMap<String, InspectedVolume>,
    attachments: BTreeMap<String, Vec<String>>,
    behavior: CreateBehavior,
    calls: Vec<Call>,
}

struct FakeEngine {
    state: Mutex<FakeState>,
}

impl FakeEngine {
    fn new() -> Self {
        Self {
            state: Mutex::new(FakeState {
                facts: healthy_facts(),
                queued_facts: VecDeque::new(),
                volumes: BTreeMap::new(),
                attachments: BTreeMap::new(),
                behavior: CreateBehavior::Apply,
                calls: Vec::new(),
            }),
        }
    }

    fn mutate(&self, update: impl FnOnce(&mut FakeState)) {
        update(&mut self.state.lock().expect("fake engine lock"));
    }

    fn calls(&self) -> Vec<Call> {
        self.state.lock().expect("fake engine lock").calls.clone()
    }
}

#[async_trait]
impl EngineApi for FakeEngine {
    async fn engine_facts(&self) -> Result<EngineFacts, EngineApiError> {
        let mut state = self.state.lock().expect("fake engine lock");
        state.calls.push(Call::EngineFacts);
        if let Some(facts) = state.queued_facts.pop_front() {
            facts
        } else {
            Ok(state.facts.clone())
        }
    }
    async fn inspect_volume(&self, name: &str) -> Result<Option<InspectedVolume>, EngineApiError> {
        let mut state = self.state.lock().expect("fake engine lock");
        state.calls.push(Call::Inspect(name.to_owned()));
        Ok(state.volumes.get(name).cloned())
    }

    async fn create_volume(&self, request: CreateVolume) -> Result<(), EngineApiError> {
        let mut state = self.state.lock().expect("fake engine lock");
        state.calls.push(Call::Create(request.name.clone()));
        let requested = InspectedVolume {
            name: request.name.clone(),
            driver: "local".to_owned(),
            scope: "local".to_owned(),
            options: BTreeMap::new(),
            labels: request.labels,
        };
        match state.behavior.clone() {
            CreateBehavior::Apply => {
                state.volumes.entry(request.name).or_insert(requested);
                Ok(())
            }
            CreateBehavior::ApplyThenFail => {
                state.volumes.entry(request.name).or_insert(requested);
                Err(EngineApiError::RequestFailed)
            }
            CreateBehavior::SucceedWithoutCreating => Ok(()),
            CreateBehavior::ConcurrentWinner(volume) => {
                state.volumes.insert(request.name, volume);
                Ok(())
            }
        }
    }

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, EngineApiError> {
        let mut state = self.state.lock().expect("fake engine lock");
        state.calls.push(Call::Attachments(name.to_owned()));
        Ok(state.attachments.get(name).cloned().unwrap_or_default())
    }
}

fn healthy_facts() -> EngineFacts {
    EngineFacts {
        engine_id: "engine-identity".to_owned(),
        server_version: "29.7.2".to_owned(),
        minimum_api_version: "1.40".to_owned(),
        maximum_api_version: "1.55".to_owned(),
        operating_system: "linux".to_owned(),
        architecture: "amd64".to_owned(),
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

fn test_adapter() -> (DockerInstallationAdapter, Arc<FakeEngine>) {
    let fake = Arc::new(FakeEngine::new());
    (
        DockerInstallationAdapter::with_test_engine(selection(), fake.clone()),
        fake,
    )
}

#[test]
fn adapter_api_is_capped_to_the_bounded_model_ceiling() {
    let capped = adapter_api_version("1.55").expect("supported selected API");
    assert_eq!((capped.major, capped.minor), (1, 53));

    let older = adapter_api_version("1.44").expect("older supported API");
    assert_eq!((older.major, older.minor), (1, 44));
}

#[tokio::test]
async fn engine_verification_uses_the_capped_adapter_api() {
    let (adapter, fake) = test_adapter();
    fake.mutate(|state| state.facts.maximum_api_version = "1.53".to_owned());
    assert_eq!(
        adapter
            .inspect_identity(&InstallationName::default())
            .await
            .expect("bounded transport API remains in the daemon range"),
        None
    );

    fake.mutate(|state| state.facts.minimum_api_version = "1.54".to_owned());
    assert_eq!(
        adapter
            .inspect_identity(&InstallationName::default())
            .await
            .expect_err("daemon minimum above the adapter ceiling must fail")
            .code(),
        LocalEngineErrorCode::EngineIdentityChanged
    );
}

fn anchor(name: &InstallationName, id: InstallationId) -> InspectedVolume {
    let installation = Installation::verified(name.clone(), id);
    InspectedVolume {
        name: installation.anchor_volume_name().to_owned(),
        driver: "local".to_owned(),
        scope: "local".to_owned(),
        options: BTreeMap::new(),
        labels: identity_labels(&installation),
    }
}

#[tokio::test]
async fn absent_anchor_is_created_post_inspected_and_then_adopted() {
    let (adapter, fake) = test_adapter();
    let name = InstallationName::default();
    let expected_name = Installation::expected(&name).anchor_volume_name;

    let created = adapter
        .create_or_adopt_identity(&name)
        .await
        .expect("create identity anchor");
    assert_eq!(created.anchor_volume_name(), expected_name);
    assert_eq!(
        fake.calls(),
        vec![
            Call::EngineFacts,
            Call::Inspect(expected_name.clone()),
            Call::Create(expected_name.clone()),
            Call::Inspect(expected_name.clone()),
            Call::Attachments(expected_name.clone()),
            Call::EngineFacts,
        ]
    );

    fake.mutate(|state| state.calls.clear());
    let adopted = adapter
        .create_or_adopt_identity(&name)
        .await
        .expect("adopt identity anchor");
    assert_eq!(adopted.id(), created.id());
    assert_eq!(
        fake.calls(),
        vec![
            Call::EngineFacts,
            Call::Inspect(expected_name.clone()),
            Call::Attachments(expected_name),
            Call::EngineFacts,
        ]
    );
}

#[tokio::test]
async fn post_inspection_not_the_create_response_decides_success() {
    let (adapter, fake) = test_adapter();
    let name = InstallationName::new("uncertain").expect("installation name");
    fake.mutate(|state| state.behavior = CreateBehavior::ApplyThenFail);

    let created = adapter
        .create_or_adopt_identity(&name)
        .await
        .expect("fresh inspection proves the create completed");
    assert_eq!(created.name(), &name);

    let (adapter, fake) = test_adapter();
    fake.mutate(|state| state.behavior = CreateBehavior::SucceedWithoutCreating);
    assert_eq!(
        adapter
            .create_or_adopt_identity(&name)
            .await
            .expect_err("missing post-create anchor must fail")
            .code(),
        LocalEngineErrorCode::MutationOutcomeUncertain
    );
}

#[tokio::test]
async fn a_concurrent_matching_winner_is_adopted() {
    let (adapter, fake) = test_adapter();
    let name = InstallationName::new("race").expect("installation name");
    let winner = anchor(&name, InstallationId::new());
    let winner_id =
        InstallationId::parse_canonical(winner.labels[super::LABEL_INSTALLATION_ID].as_str())
            .expect("winner installation ID");
    fake.mutate(|state| state.behavior = CreateBehavior::ConcurrentWinner(winner));

    assert_eq!(
        adapter
            .create_or_adopt_identity(&name)
            .await
            .expect("adopt concurrent winner")
            .id(),
        winner_id
    );
}

#[tokio::test]
async fn foreign_volume_shape_fails_without_mutation() {
    let name = InstallationName::new("foreign-shape").expect("installation name");
    for mutate in [
        |volume: &mut InspectedVolume| volume.driver = "nfs".to_owned(),
        |volume: &mut InspectedVolume| volume.scope = "global".to_owned(),
        |volume: &mut InspectedVolume| {
            volume
                .options
                .insert("device".to_owned(), "/host/path".to_owned());
        },
    ] {
        let (adapter, fake) = test_adapter();
        let mut volume = anchor(&name, InstallationId::new());
        mutate(&mut volume);
        fake.mutate(|state| {
            state.volumes.insert(volume.name.clone(), volume);
        });
        assert_eq!(
            adapter
                .create_or_adopt_identity(&name)
                .await
                .expect_err("foreign volume shape")
                .code(),
            LocalEngineErrorCode::IdentityCollision
        );
        assert!(
            !fake
                .calls()
                .iter()
                .any(|call| matches!(call, Call::Create(_)))
        );
    }
}

#[tokio::test]
async fn managed_label_contract_is_exact_but_foreign_labels_are_tolerated() {
    let name = InstallationName::new("labels").expect("installation name");
    let mutations: Vec<(&str, VolumeMutation)> = vec![
        (
            "missing owner",
            Box::new(|volume| {
                volume.labels.remove(LABEL_MANAGED);
            }),
        ),
        (
            "wrong schema",
            Box::new(|volume| {
                volume
                    .labels
                    .insert(LABEL_IDENTITY_SCHEMA.to_owned(), "2".to_owned());
            }),
        ),
        (
            "wrong key",
            Box::new(|volume| {
                volume
                    .labels
                    .insert(LABEL_INSTALLATION_KEY.to_owned(), "0".repeat(64));
            }),
        ),
        (
            "wrong project",
            Box::new(|volume| {
                volume.labels.insert(
                    LABEL_COMPOSE_PROJECT.to_owned(),
                    "automata-local-other".to_owned(),
                );
            }),
        ),
        (
            "wrong role",
            Box::new(|volume| {
                volume
                    .labels
                    .insert(LABEL_RESOURCE_KIND.to_owned(), "other".to_owned());
            }),
        ),
        (
            "unknown managed label",
            Box::new(|volume| {
                volume
                    .labels
                    .insert("io.automata.local.future".to_owned(), "value".to_owned());
            }),
        ),
        (
            "malformed uuid",
            Box::new(|volume| {
                volume
                    .labels
                    .insert(LABEL_INSTALLATION_ID.to_owned(), "not-a-uuid".to_owned());
            }),
        ),
    ];
    for (description, mutate) in mutations {
        let (adapter, fake) = test_adapter();
        let mut volume = anchor(&name, InstallationId::new());
        mutate(&mut volume);
        fake.mutate(|state| {
            state.volumes.insert(volume.name.clone(), volume);
        });
        let error = adapter
            .inspect_identity(&name)
            .await
            .expect_err(description);
        assert!(matches!(
            error.code(),
            LocalEngineErrorCode::IdentityCollision | LocalEngineErrorCode::InvalidIdentityAnchor
        ));
    }

    let (adapter, fake) = test_adapter();
    let mut volume = anchor(&name, InstallationId::new());
    volume
        .labels
        .insert("com.example.note".to_owned(), "allowed".to_owned());
    fake.mutate(|state| {
        state.volumes.insert(volume.name.clone(), volume);
    });
    assert!(
        adapter
            .inspect_identity(&name)
            .await
            .expect("foreign namespace is ignored")
            .is_some()
    );
}

#[tokio::test]
async fn running_or_stopped_attachment_blocks_adoption() {
    let (adapter, fake) = test_adapter();
    let name = InstallationName::new("attached").expect("installation name");
    let volume = anchor(&name, InstallationId::new());
    fake.mutate(|state| {
        state
            .attachments
            .insert(volume.name.clone(), vec!["stopped-container-id".to_owned()]);
        state.volumes.insert(volume.name.clone(), volume);
    });
    assert_eq!(
        adapter
            .inspect_identity(&name)
            .await
            .expect_err("any attachment must fail")
            .code(),
        LocalEngineErrorCode::IdentityAnchorAttached
    );
}

#[tokio::test]
async fn engine_drift_before_mutation_creates_nothing() {
    let (adapter, fake) = test_adapter();
    fake.mutate(|state| state.facts.engine_id = "replacement-engine".to_owned());
    assert_eq!(
        adapter
            .create_or_adopt_identity(&InstallationName::default())
            .await
            .expect_err("changed engine must fail")
            .code(),
        LocalEngineErrorCode::EngineIdentityChanged
    );
    assert_eq!(fake.calls(), vec![Call::EngineFacts]);
}

#[tokio::test]
async fn engine_drift_after_create_reports_uncertain_without_cleanup() {
    let (adapter, fake) = test_adapter();
    let mut changed = healthy_facts();
    changed.engine_id = "replacement-engine".to_owned();
    fake.mutate(|state| {
        state.queued_facts = VecDeque::from([Ok(healthy_facts()), Ok(changed)]);
    });
    assert_eq!(
        adapter
            .create_or_adopt_identity(&InstallationName::default())
            .await
            .expect_err("post-create engine drift")
            .code(),
        LocalEngineErrorCode::MutationOutcomeUncertain
    );
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|call| matches!(call, Call::Create(_)))
            .count(),
        1
    );
}

#[test]
fn identity_label_constants_are_not_accidentally_changed() {
    assert_eq!(MANAGED_VALUE, "true");
    assert_eq!(IDENTITY_SCHEMA, "1");
    assert_eq!(IDENTITY_ANCHOR_KIND, "identity-anchor");
}

#[tokio::test]
#[ignore = "requires an explicitly selected live local Docker Engine and removes its exact fixture"]
async fn live_docker_public_adapter_creates_and_re_adopts_one_exact_anchor() {
    assert_eq!(
        std::env::var("AUTOMATA_TEST_LOCAL_DOCKER").as_deref(),
        Ok("1"),
        "set AUTOMATA_TEST_LOCAL_DOCKER=1 to authorize the live fixture"
    );
    let report = Box::pin(crate::inspect(crate::DoctorRequest::new(
        crate::EngineRequest::Docker,
    )))
    .await;
    assert!(
        report.ready(),
        "live Docker preflight: {:?}",
        report.issues()
    );
    let adapter = DockerInstallationAdapter::connect(&report)
        .await
        .expect("connect exact Docker endpoint");
    let name = InstallationName::new(format!("live-{}", uuid::Uuid::new_v4().simple()))
        .expect("unique live installation name");

    let first = adapter
        .create_or_adopt_identity(&name)
        .await
        .expect("create live identity anchor");
    let second = adapter
        .create_or_adopt_identity(&name)
        .await
        .expect("adopt live identity anchor");
    assert_eq!(second.id(), first.id());

    let selection = report.selected_engine().expect("ready engine selection");
    let cleanup_engine = super::HttpEngine::connect(
        selection.connection(),
        adapter_api_version(selection.api_version()).expect("bounded API version"),
    )
    .expect("cleanup connection");
    let verified = adapter
        .inspect_identity(&name)
        .await
        .expect("reinspect before cleanup")
        .expect("live anchor exists before cleanup");
    assert_eq!(verified, first);
    cleanup_engine
        .remove_volume_for_test(verified.anchor_volume_name())
        .await
        .expect("remove the exact unattached live fixture");
    assert_eq!(
        adapter
            .inspect_identity(&name)
            .await
            .expect("inspect after exact cleanup"),
        None
    );
}
