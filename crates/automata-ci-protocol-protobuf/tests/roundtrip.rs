use crate::common;

use automata_ci_core::{
    IsolationLevel, JobResourceAllocation, OperatingSystem, OperationId, ResourceCapacity,
    RunnerRequirements, SandboxFeature,
};
use automata_ci_protocol::{LeaseRequest, ProtocolLimits, RunnerToServer, ServerToRunner};
use automata_ci_protocol_protobuf::{
    PROTOBUF_PACKAGE, decode_job_ir, decode_runner_frame, decode_server_frame, encode_job_ir,
    encode_runner_frame, encode_server_frame,
};
use sha2::{Digest as _, Sha256};

#[test]
fn every_runner_envelope_variant_round_trips_losslessly() {
    let limits = ProtocolLimits::default();
    for (name, message) in common::runner_messages() {
        let encoded = encode_runner_frame(&message, &limits).expect("encode runner fixture");
        let decoded = decode_runner_frame(&encoded, &limits).expect("decode runner fixture");
        assert_eq!(decoded.into_message(), message, "runner variant {name}");
    }
}

#[test]
fn first_and_successor_lease_requests_round_trip_with_exact_chain_position() {
    let limits = ProtocolLimits::default();
    let acknowledged = OperationId::new();
    let messages = [
        RunnerToServer::LeaseRequest(LeaseRequest::first(
            common::request_header(101),
            common::slot(),
        )),
        RunnerToServer::LeaseRequest(LeaseRequest::successor(
            common::request_header(102),
            common::slot(),
            acknowledged,
        )),
    ];

    for message in messages {
        let encoded = encode_runner_frame(&message, &limits).expect("encode lease request");
        let decoded = decode_runner_frame(&encoded, &limits)
            .expect("decode lease request")
            .into_message();
        assert_eq!(decoded, message);
    }
}

#[test]
fn every_server_envelope_variant_round_trips_losslessly() {
    let limits = ProtocolLimits::default();
    for (name, message) in common::server_messages() {
        let encoded = encode_server_frame(&message, &limits).expect("encode server fixture");
        let decoded = decode_server_frame(&encoded, &limits).expect("decode server fixture");
        assert_eq!(decoded.into_message(), message, "server variant {name}");
    }
}

#[test]
fn resource_allocation_round_trips_with_exact_requests_and_limits() {
    let requests = ResourceCapacity::new(1_500, 2 * 1024 * 1024 * 1024, 4096, 0);
    let limits = ResourceCapacity::new(3_000, 6 * 1024 * 1024 * 1024, 8192, 0);
    let allocation = JobResourceAllocation::new(requests, limits).expect("valid allocation");
    let job = common::rich_job_with_requirements(
        RunnerRequirements::default().with_resource_allocation(allocation),
    );
    let message = ServerToRunner::LeaseOffer(Box::new(common::lease_offer_with_job(job)));

    let encoded = encode_server_frame(&message, &ProtocolLimits::default()).expect("encode offer");
    let decoded = decode_server_frame(&encoded, &ProtocolLimits::default())
        .expect("decode offer")
        .into_message();
    let ServerToRunner::LeaseOffer(offer) = decoded else {
        panic!("decoded lease offer");
    };

    assert_eq!(
        offer.job().job().requirements().minimum_resources(),
        requests
    );
    assert_eq!(
        offer.job().job().requirements().resource_allocation(),
        Some(allocation)
    );
}

#[test]
fn windows_hyperv_placement_round_trips_and_binds_the_job_digest() {
    let limits = ProtocolLimits::default();
    let exact = common::rich_job_with_requirements(
        RunnerRequirements::default().with_windows_hyperv_container(),
    );
    let encoded = encode_job_ir(&exact, &limits).expect("encode exact Windows placement");
    let digest = Sha256::digest(&encoded);
    let decoded = decode_job_ir(&encoded, &limits).expect("decode exact Windows placement");
    let requirements = decoded.job().requirements();
    assert_eq!(
        requirements.operating_system(),
        Some(&OperatingSystem::Windows)
    );
    assert_eq!(
        requirements.minimum_isolation(),
        IsolationLevel::VirtualMachine
    );
    assert!(
        requirements
            .sandbox_features()
            .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
    );
    let replay = encode_job_ir(&decoded, &limits).expect("re-encode exact Windows placement");
    assert_eq!(replay, encoded);
    assert_eq!(Sha256::digest(&replay), digest);

    let generic_vm = common::rich_job_with_requirements(
        RunnerRequirements::default().with_minimum_isolation(IsolationLevel::VirtualMachine),
    );
    let generic_bytes = encode_job_ir(&generic_vm, &limits).expect("encode generic VM placement");
    assert_ne!(Sha256::digest(generic_bytes), digest);
}

#[test]
fn managed_secret_overlay_round_trips_with_exact_lease_binding_and_entries() {
    let offer = common::lease_offer_with_job(common::rich_job());
    let overlay = common::managed_secret_overlay(offer.lease());
    let offer = offer
        .with_managed_secret_bindings(overlay.clone())
        .expect("lease-bound overlay");
    let message = ServerToRunner::LeaseOffer(Box::new(offer));

    let encoded = encode_server_frame(&message, &ProtocolLimits::default()).expect("encode offer");
    let decoded = decode_server_frame(&encoded, &ProtocolLimits::default())
        .expect("decode offer")
        .into_message();
    let ServerToRunner::LeaseOffer(offer) = decoded else {
        panic!("decoded lease offer");
    };

    assert_eq!(offer.managed_secret_bindings(), Some(&overlay));
}

#[test]
fn repeated_encodes_are_byte_identical() {
    let limits = ProtocolLimits::default();
    for (_, message) in common::runner_messages() {
        let first = encode_runner_frame(&message, &limits).expect("first encode");
        let second = encode_runner_frame(&message, &limits).expect("second encode");
        assert_eq!(first, second);
    }
    for (_, message) in common::server_messages() {
        let first = encode_server_frame(&message, &limits).expect("first encode");
        let second = encode_server_frame(&message, &limits).expect("second encode");
        assert_eq!(first, second);
    }
}

#[test]
fn public_api_exposes_the_stable_package_not_private_dtos() {
    assert_eq!(PROTOBUF_PACKAGE, "automata.runner.v1");
}
