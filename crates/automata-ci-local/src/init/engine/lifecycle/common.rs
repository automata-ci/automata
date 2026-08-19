//! Shared imports and constants for the private lifecycle implementation.

pub(super) use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    future::Future,
    io::{ErrorKind, IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::unix::net::UnixStream,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

pub(super) use automata_ci_core::{OperationId, Sha256Digest};
pub(super) use bollard::{
    Docker,
    container::{AttachContainerResults, LogOutput},
    models::{
        ContainerCreateBody, ContainerSummary, EventMessage, EventMessageTypeEnum, HostConfig,
        HostConfigCgroupnsModeEnum, HostConfigIsolationEnum, ImageConfig, Ipam, IpamConfig, Mount,
        MountBindOptionsPropagationEnum, MountType, MountVolumeOptions, Network,
        NetworkCreateRequest, NetworkInspect, RestartPolicy, RestartPolicyNameEnum,
    },
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, ListContainersOptionsBuilder,
        ListNetworksOptionsBuilder, ListVolumesOptionsBuilder, LogsOptionsBuilder,
        RemoveContainerOptionsBuilder, WaitContainerOptionsBuilder,
    },
};
pub(super) use bytes::Bytes;
pub(super) use futures::{Stream, StreamExt};
pub(super) use http_body_util::{BodyExt, Empty};
pub(super) use hyper::{Request, StatusCode, client::conn::http1};
pub(super) use hyper_util::rt::TokioIo;
pub(super) use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SocketAddrUnix,
    SocketFlags, SocketType,
};
pub(super) use serde::Deserialize;
pub(super) use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::UnixStream as TokioUnixStream,
    sync::{Mutex, OwnedMutexGuard, mpsc, oneshot},
    task::JoinHandle,
};
pub(super) use tokio_util::sync::CancellationToken;

pub(super) use crate::{
    DesiredSpec, Installation, MAX_LOCAL_DESIRED_SPEC_BYTES,
    lifecycle_helper::{CasDigestRequest, CasDigestResponse, CasRequest, CasTarget},
    local_docker::{
        LifecycleSiblingContainer, LifecycleSiblingNetwork, attest_lifecycle_sibling_custody_union,
        attest_lifecycle_sibling_union,
    },
    results_transport::{
        RESULTS_TRANSIT_GATEWAY_MODE_KEY, RESULTS_TRANSIT_GATEWAY_MODE_VALUE,
        ResultsTransitNetworkShape, exact_results_transit_base, results_transit_labels,
        results_transit_name,
    },
};

pub(super) use super::super::{
    ENGINE_TIMEOUT, HELPER_EXPOSED_PORT, HELPER_MEMORY_BYTES, HELPER_NANO_CPUS, HELPER_PIDS,
    HELPER_SHM_BYTES, HELPER_TIMEOUT, HelperDriver, InitEngine, LIFECYCLE_ATTESTER_KIND,
    MAX_ENGINE_RESOURCES, SealedEngineStatus, SealedImageStatus, SealedVolumeStatus,
    engine_resource_mismatch, engine_unavailable, exact_container_id, exact_container_id_text,
    expected_volume_labels, helper_has_ambient_authority, helper_log_config, helper_masked_paths,
    helper_mounts_match, helper_readonly_paths, helper_security_options,
    lifecycle_material_attester_labels, lifecycle_material_attester_name, not_found,
    reset_progress_from_presence, reset_volume_order, validate_helper, validate_volume,
    volume_labels, volume_name, volume_names,
};
pub(super) use crate::init::{
    LocalInitError, LocalInitErrorCode,
    epoch::ImmutableEpoch,
    materializer::VolumeRole,
    renderer::{
        ExpectedContainer, ExpectedLifecycleTopology, ExpectedMountSource, ExpectedNetwork,
    },
};

pub(super) const LOCK_KIND: &str = "lifecycle-lock";

pub(super) const LABEL_MANAGED: &str = "io.automata.local.managed";
pub(super) const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
pub(super) const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
pub(super) const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
pub(super) const LABEL_EPOCH: &str = "io.automata.local.epoch-fingerprint";
pub(super) const LABEL_PLAN: &str = "io.automata.local.plan-digest";
pub(super) const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
pub(super) const LABEL_OPERATION_ID: &str = "io.automata.local.lifecycle-operation-id";
pub(super) const LABEL_ENGINE_BOOT_ID: &str = "io.automata.local.engine-boot-id";
pub(super) const LABEL_ENGINE_PID: &str = "io.automata.local.engine-pid";
pub(super) const LABEL_ENGINE_START_TICKS: &str = "io.automata.local.engine-start-ticks";
pub(super) const DESIRED_READER_KIND: &str = "lifecycle-desired-reader";
pub(super) const CAS_WRITER_KIND: &str = "lifecycle-cas-writer";
pub(super) const CAS_DIGEST_READER_KIND: &str = "lifecycle-cas-digest-reader";
pub(super) const CAS_MOUNT: &str = "/run/automata-lifecycle-cas";
pub(super) const MAX_ONEOFF_LOG_BYTES: usize = 64 * 1024;
pub(super) const RECOVERY_ENGINE_QUIET_PERIOD: Duration = Duration::from_secs(2);
pub(super) const RECOVERY_ENGINE_QUIET_DEADLINE: Duration = Duration::from_secs(30);
pub(super) const ENGINE_GENERATION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const ENGINE_GENERATION_RESPONSE_MAXIMUM_BYTES: usize = 4096;
pub(super) const ENGINE_GENERATION_REQUEST: &[u8] =
    b"GET /_ping HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n";
pub(super) const RECOVERY_EVENT_URI: &str = "/v1.48/events?since=1";
pub(super) const RECOVERY_EVENT_MAXIMUM_BYTES: usize = 64 * 1024;
pub(super) const RECOVERY_EVENT_CHUNK_MAXIMUM_BYTES: usize = 256 * 1024;
pub(super) const ENGINE_INFO_URI: &str = "/v1.48/info";
pub(super) const ENGINE_INFO_MAXIMUM_BYTES: usize = 1024 * 1024;
