//! Unit coverage for lifecycle contracts shared across the private implementation modules.

use super::{common::*, lock::*, recovery::*, validation::*};

#[cfg(test)]
mod daemon_generation_tests {
    use super::*;
    use futures::channel::mpsc as futures_mpsc;

    fn generation(boot: u128, pid: u32, start_ticks: u64) -> EngineDaemonGeneration {
        EngineDaemonGeneration {
            boot_id: uuid::Uuid::from_u128(boot),
            pid,
            start_ticks,
        }
    }

    fn qualified_daemon_info() -> LifecycleDaemonInfo {
        LifecycleDaemonInfo {
            security_options: vec![
                "name=seccomp,profile=builtin".to_owned(),
                "name=cgroupns".to_owned(),
                "name=userns".to_owned(),
            ],
            memory_limit: true,
            swap_limit: true,
            cpu_cfs_period: true,
            cpu_cfs_quota: true,
            pids_limit: true,
            cgroup_version: "2".to_owned(),
            live_restore_enabled: false,
            default_runtime: "runc".to_owned(),
            default_ulimits: None,
        }
    }

    #[test]
    fn lifecycle_daemon_contract_is_closed_and_fail_closed() {
        let valid = qualified_daemon_info();
        validate_lifecycle_daemon_info(&valid).unwrap();
        let mut optional_nnp = valid.clone();
        optional_nnp
            .security_options
            .push("name=no-new-privileges".to_owned());
        validate_lifecycle_daemon_info(&optional_nnp).unwrap();

        let mut invalid = Vec::new();
        let mut missing_userns = valid.clone();
        missing_userns
            .security_options
            .retain(|option| option != "name=userns");
        invalid.push(missing_userns);
        let mut extra_security = valid.clone();
        extra_security
            .security_options
            .push("name=apparmor".to_owned());
        invalid.push(extra_security);
        let mut duplicate_security = valid.clone();
        duplicate_security
            .security_options
            .push("name=cgroupns".to_owned());
        invalid.push(duplicate_security);
        for mutate in [
            |info: &mut LifecycleDaemonInfo| info.memory_limit = false,
            |info: &mut LifecycleDaemonInfo| info.swap_limit = false,
            |info: &mut LifecycleDaemonInfo| info.cpu_cfs_period = false,
            |info: &mut LifecycleDaemonInfo| info.cpu_cfs_quota = false,
            |info: &mut LifecycleDaemonInfo| info.pids_limit = false,
            |info: &mut LifecycleDaemonInfo| info.live_restore_enabled = true,
        ] {
            let mut changed = valid.clone();
            mutate(&mut changed);
            invalid.push(changed);
        }
        let mut cgroup_one = valid.clone();
        cgroup_one.cgroup_version = "1".to_owned();
        invalid.push(cgroup_one);
        let mut wrong_runtime = valid.clone();
        wrong_runtime.default_runtime = "custom".to_owned();
        invalid.push(wrong_runtime);
        let mut default_ulimits = valid;
        default_ulimits.default_ulimits = Some(HashMap::from([(
            "nofile".to_owned(),
            serde_json::json!({"Hard": 1024, "Name": "nofile", "Soft": 1024}),
        )]));
        invalid.push(default_ulimits);

        for info in invalid {
            assert_eq!(
                validate_lifecycle_daemon_info(&info).unwrap_err().code(),
                LocalInitErrorCode::EngineUnavailable
            );
        }
    }

    #[test]
    fn rendered_masked_paths_normalize_supported_moby_defaults_only() {
        let base = [
            "/proc/acpi",
            "/proc/asound",
            "/proc/kcore",
            "/proc/keys",
            "/proc/latency_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/sys/devices/virtual/powercap",
            "/sys/firmware",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        assert!(valid_rendered_masked_paths(Some(&base)));

        let mut current = base.clone();
        current.extend([
            "/proc/interrupts".to_owned(),
            "/sys/devices/system/cpu/cpu0/thermal_throttle".to_owned(),
            "/sys/devices/system/cpu/cpu12/thermal_throttle".to_owned(),
        ]);
        assert!(valid_rendered_masked_paths(Some(&current)));

        let mut missing = base.clone();
        missing.pop();
        assert!(!valid_rendered_masked_paths(Some(&missing)));
        let mut duplicate = base.clone();
        duplicate.push(base[0].clone());
        assert!(!valid_rendered_masked_paths(Some(&duplicate)));
        for extra in [
            "/proc/unknown",
            "/sys/devices/system/cpu/cpu01/thermal_throttle",
            "/sys/devices/system/cpu/cpu0/other",
        ] {
            let mut invalid = base.clone();
            invalid.push(extra.to_owned());
            assert!(!valid_rendered_masked_paths(Some(&invalid)));
        }
    }

    fn none_endpoint(network_id: &str, running: bool) -> bollard::models::EndpointSettings {
        bollard::models::EndpointSettings {
            network_id: Some(network_id.to_owned()),
            endpoint_id: running.then(|| "c".repeat(64)),
            gateway: running.then(String::new),
            ip_address: running.then(String::new),
            ip_prefix_len: running.then_some(0),
            ipv6_gateway: running.then(String::new),
            global_ipv6_address: running.then(String::new),
            global_ipv6_prefix_len: running.then_some(0),
            mac_address: running.then(String::new),
            ..Default::default()
        }
    }

    #[test]
    fn running_none_network_accepts_only_null_exposed_port_bindings() {
        let sandbox_id = "a".repeat(64);
        let network_id = "b".repeat(64);
        let mut network = bollard::models::NetworkSettings {
            sandbox_id: Some(sandbox_id.clone()),
            sandbox_key: Some(format!("/var/run/docker/netns/{}", &sandbox_id[..12])),
            ports: Some(HashMap::from([("8080/tcp".to_owned(), None)])),
            networks: Some(HashMap::from([(
                "none".to_owned(),
                none_endpoint(&network_id, true),
            )])),
        };
        assert!(exact_running_none_network(&network, &network_id));
        network.ports = Some(HashMap::new());
        assert!(exact_running_none_network(&network, &network_id));
        network.ports = Some(HashMap::from([(
            "8080/tcp".to_owned(),
            Some(vec![bollard::models::PortBinding {
                host_ip: Some("127.0.0.1".to_owned()),
                host_port: Some("8080".to_owned()),
            }]),
        )]));
        assert!(!exact_running_none_network(&network, &network_id));
        network.ports = Some(HashMap::new());
        network
            .networks
            .as_mut()
            .unwrap()
            .get_mut("none")
            .unwrap()
            .aliases = Some(vec!["ambient".to_owned()]);
        assert!(!exact_running_none_network(&network, &network_id));
    }

    #[test]
    fn stopped_none_network_rejects_residual_operational_state() {
        let network_id = "b".repeat(64);
        let mut network = bollard::models::NetworkSettings {
            sandbox_id: Some(String::new()),
            sandbox_key: Some(String::new()),
            ports: Some(HashMap::new()),
            networks: Some(HashMap::from([(
                "none".to_owned(),
                none_endpoint(&network_id, false),
            )])),
        };
        assert!(exact_stopped_none_network(&network, &network_id));
        network
            .networks
            .as_mut()
            .unwrap()
            .get_mut("none")
            .unwrap()
            .ip_address = Some("172.18.0.2".to_owned());
        assert!(!exact_stopped_none_network(&network, &network_id));
        network
            .networks
            .as_mut()
            .unwrap()
            .get_mut("none")
            .unwrap()
            .ip_address = None;
        network.networks.as_mut().unwrap().insert(
            "bridge".to_owned(),
            bollard::models::EndpointSettings::default(),
        );
        assert!(!exact_stopped_none_network(&network, &network_id));
    }

    #[test]
    fn realized_port_keys_are_exact_while_stopped_oneoffs_release_them() {
        let rendered = crate::init::renderer::render_compose(&crate::desired_spec::tests::spec());
        let expected = &rendered.expected.containers["engine-relay"];
        let config = bollard::models::ContainerConfig {
            exposed_ports: Some(vec!["8080/tcp".to_owned()]),
            ..Default::default()
        };
        let image = ImageConfig {
            exposed_ports: Some(vec!["8080/tcp".to_owned()]),
            ..Default::default()
        };
        let host = HostConfig {
            port_bindings: Some(HashMap::new()),
            ..Default::default()
        };
        let mut network = bollard::models::NetworkSettings {
            ports: Some(HashMap::from([("8080/tcp".to_owned(), None)])),
            ..Default::default()
        };
        assert!(validate_rendered_ports(&config, &host, &network, expected, &image, true).is_ok());

        network
            .ports
            .as_mut()
            .unwrap()
            .insert("9000/tcp".to_owned(), None);
        assert!(validate_rendered_ports(&config, &host, &network, expected, &image, true).is_err());

        network.ports = Some(HashMap::new());
        assert!(validate_rendered_ports(&config, &host, &network, expected, &image, false).is_ok());
        network.ports = Some(HashMap::from([("8080/tcp".to_owned(), None)]));
        assert!(
            validate_rendered_ports(&config, &host, &network, expected, &image, false).is_err()
        );
    }

    #[test]
    fn lifecycle_lock_labels_are_the_exact_image_and_managed_union() {
        let image = BTreeMap::from([
            (
                "org.opencontainers.image.source".to_owned(),
                "automata".to_owned(),
            ),
            (
                "org.opencontainers.image.version".to_owned(),
                "1".to_owned(),
            ),
        ]);
        let managed = BTreeMap::from([("io.automata.local.managed".to_owned(), "true".to_owned())]);
        let labels = lifecycle_lock_expected_labels(&image, managed.clone()).unwrap();
        assert_eq!(labels.len(), 3);
        assert_eq!(labels["org.opencontainers.image.source"], "automata");
        assert_eq!(labels["io.automata.local.managed"], "true");

        let mut colliding = image;
        colliding.insert(
            "io.automata.local.ambient".to_owned(),
            "forbidden".to_owned(),
        );
        assert_eq!(
            lifecycle_lock_expected_labels(&colliding, managed)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineResourceMismatch
        );
    }

    #[test]
    fn interrupted_holder_exit_remains_sticky_stopped_evidence() {
        let id = "a".repeat(64);
        let operation_id = OperationId::new();
        for exit_code in [None, Some(0), Some(1), Some(137)] {
            let state = bollard::models::ContainerState {
                running: Some(false),
                pid: Some(0),
                exit_code,
                ..Default::default()
            };
            assert_eq!(
                classify_lifecycle_lock_process_state(&state, &id, operation_id).unwrap(),
                LifecycleLockObservation::Stopped {
                    id: id.clone(),
                    operation_id,
                },
                "EOF, partial-frame, and signal exits must remain recoverable exact-ID evidence"
            );
        }

        let live = bollard::models::ContainerState {
            running: Some(true),
            pid: Some(42),
            exit_code: Some(1),
            ..Default::default()
        };
        assert_eq!(
            classify_lifecycle_lock_process_state(&live, &id, operation_id).unwrap(),
            LifecycleLockObservation::Live { id, operation_id }
        );
    }

    #[test]
    fn reset_runner_discovery_accepts_zero_or_one_authority_only() {
        assert_eq!(sole_local_docker_runner_id(BTreeSet::new()).unwrap(), None);
        let first = uuid::Uuid::from_u128(1);
        assert_eq!(
            sole_local_docker_runner_id(BTreeSet::from([first])).unwrap(),
            Some(first)
        );
        assert_eq!(
            sole_local_docker_runner_id(BTreeSet::from([first, uuid::Uuid::from_u128(2)]))
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineResourceMismatch
        );
    }

    #[tokio::test]
    async fn holder_eof_wins_over_a_queued_mutation_permit() {
        let output = futures::stream::empty::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let (permit, permitted) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::AuthorizeMutation(permit))
            .await
            .unwrap();

        assert!(
            monitor_lifecycle_lock_output(output, requests, lost.clone())
                .await
                .is_err()
        );
        assert!(lost.is_cancelled());
        assert!(permitted.await.is_err());
    }

    #[tokio::test]
    async fn graceful_holder_release_linearizes_before_clean_eof() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        frame_sent.send(()).unwrap();
        drop(output);

        assert!(monitor.await.unwrap().is_ok());
        assert!(!lost.is_cancelled());
    }

    #[tokio::test]
    async fn graceful_holder_release_accepts_eof_before_frame_confirmation() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        drop(output);
        tokio::task::yield_now().await;
        frame_sent.send(()).unwrap();

        assert!(monitor.await.unwrap().is_ok());
        assert!(!lost.is_cancelled());
    }

    #[tokio::test]
    async fn graceful_holder_release_rejects_eof_without_frame_confirmation() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        drop(output);
        drop(frame_sent);

        assert!(monitor.await.unwrap().is_err());
        assert!(lost.is_cancelled());
    }

    #[tokio::test]
    async fn holder_output_wins_over_a_release_frame() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        output.unbounded_send(()).unwrap();
        frame_sent.send(()).unwrap();

        assert!(monitor.await.unwrap().is_err());
        assert!(lost.is_cancelled());
    }

    #[test]
    fn holder_loss_dominates_caller_cancellation() {
        let holder_lost = CancellationToken::new();
        let caller = CancellationToken::new();
        holder_lost.cancel();
        caller.cancel();
        let (commands, _requests) = mpsc::channel(1);
        let mutation = LifecycleMutationFence {
            commands,
            holder_lost,
            caller,
            gate: Arc::new(Mutex::new(LifecycleMutationGateState::default())),
        };
        assert_eq!(
            mutation.checkpoint().unwrap_err().code(),
            LocalInitErrorCode::ResetRequired
        );
    }

    #[tokio::test]
    async fn mutation_gate_drains_one_request_then_closes_permanently() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let holder_lost = CancellationToken::new();
        let caller = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            holder_lost.clone(),
        ));
        let gate = Arc::new(Mutex::new(LifecycleMutationGateState::default()));
        let mutation = LifecycleMutationFence {
            commands,
            holder_lost,
            caller,
            gate: Arc::clone(&gate),
        };
        let (started, start) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let running = tokio::spawn({
            let mutation = mutation.clone();
            async move {
                mutation
                    .run(async move {
                        started.send(()).unwrap();
                        let _completed = finished.await;
                    })
                    .await
            }
        });
        start.await.unwrap();
        assert!(Arc::clone(&gate).try_lock_owned().is_err());
        finish.send(()).unwrap();
        running.await.unwrap().unwrap();

        let mut release = Arc::clone(&gate).lock_owned().await;
        release.closed = true;
        drop(release);
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = mutation
            .run({
                let polled = Arc::clone(&polled);
                async move {
                    polled.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .await;
        assert_eq!(
            result.unwrap_err().code(),
            LocalInitErrorCode::ResetRequired
        );
        assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));

        drop(output);
        assert!(monitor.await.unwrap().is_err());
    }

    #[test]
    fn stopped_daemon_requires_positive_absence_not_elapsed_time() {
        let stopped = generation(1, 42, 100);
        assert_eq!(
            daemon_generation_absence_from_observation(&stopped, stopped.boot_id, Ok(100))
                .unwrap_err()
                .code(),
            LocalInitErrorCode::ResetRequired
        );
        assert_eq!(
            daemon_generation_absence_from_observation(
                &stopped,
                stopped.boot_id,
                Err(ErrorKind::PermissionDenied),
            )
            .unwrap_err()
            .code(),
            LocalInitErrorCode::ResetRequired
        );
    }

    #[test]
    fn host_reboot_missing_pid_and_pid_reuse_are_positive_absence() {
        let stopped = generation(1, 42, 100);
        assert!(
            daemon_generation_absence_from_observation(
                &stopped,
                uuid::Uuid::from_u128(2),
                Ok(100),
            )
            .is_ok()
        );
        assert!(
            daemon_generation_absence_from_observation(
                &stopped,
                stopped.boot_id,
                Err(ErrorKind::NotFound),
            )
            .is_ok()
        );
        assert!(
            daemon_generation_absence_from_observation(&stopped, stopped.boot_id, Ok(101)).is_ok()
        );
    }

    #[test]
    fn replacement_daemon_must_differ_and_remain_stable_through_the_fence() {
        let stopped = generation(1, 42, 100);
        let replacement = generation(1, 43, 200);
        assert_eq!(
            validate_replacement_daemon_generation(&stopped, &stopped, &stopped)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::ResetRequired
        );
        assert_eq!(
            validate_replacement_daemon_generation(
                &stopped,
                &replacement,
                &generation(1, 44, 300),
            )
            .unwrap_err()
            .code(),
            LocalInitErrorCode::ResetRequired
        );
        assert!(
            validate_replacement_daemon_generation(&stopped, &replacement, &replacement).is_ok()
        );
    }

    #[test]
    fn daemon_generation_labels_are_exact_and_canonical() {
        let installation = Installation::verified(
            crate::InstallationName::default(),
            crate::InstallationId::new(),
        );
        let operation = OperationId::new();
        let generation = generation(1, 42, 100);
        let labels = lifecycle_lock_labels(&installation, operation, &generation);
        assert_eq!(daemon_generation_from_labels(&labels).unwrap(), generation);

        for key in [
            LABEL_ENGINE_BOOT_ID,
            LABEL_ENGINE_PID,
            LABEL_ENGINE_START_TICKS,
        ] {
            let mut malformed = labels.clone();
            malformed.insert(key.to_owned(), "not-canonical".to_owned());
            assert_eq!(
                daemon_generation_from_labels(&malformed)
                    .unwrap_err()
                    .code(),
                LocalInitErrorCode::EngineResourceMismatch
            );
        }
    }

    #[test]
    fn daemon_generation_ping_response_is_closed() {
        validate_engine_generation_response(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .unwrap();
        for invalid in [
            b"HTTP/1.0 500 Internal Server Error\r\n\r\nOK".as_slice(),
            b"HTTP/1.0 200 OK\r\n\r\nNO".as_slice(),
            b"HTTP/1.0 200 OK\n\nOK".as_slice(),
            b"HTTP/1.0 200 OK\r\n\r\nOKextra".as_slice(),
        ] {
            assert_eq!(
                validate_engine_generation_response(invalid)
                    .unwrap_err()
                    .code(),
                LocalInitErrorCode::EngineUnavailable
            );
        }
    }

    #[test]
    #[ignore = "requires the fixed local Docker Engine"]
    fn live_daemon_generation_identifies_the_response_writer() {
        let generation = current_engine_daemon_generation().unwrap();
        assert_ne!(generation.pid, 1, "socket owner is not the response writer");
        let command = fs::read_to_string(format!("/proc/{}/comm", generation.pid)).unwrap();
        assert_eq!(command.trim_end(), "dockerd");
    }
}
