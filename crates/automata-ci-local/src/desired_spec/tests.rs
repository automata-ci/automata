use std::{collections::BTreeSet, net::Ipv4Addr, num::NonZeroU16};

use automata_ci_core::{EnvironmentProfile, EnvironmentProfileId, Sha256Digest};
use automata_ci_execution::ImmutableImage;
use automata_ci_runner_journal::MAX_JOURNALED_SLOTS;

use super::{
    DesiredSpec, DesiredSpecErrorCode, DesiredSpecImages, DesiredSpecInput, LocalImportedImage,
    LocalProfile, ResultsTransit,
};
use crate::{EngineArchitecture, Installation, InstallationId, InstallationName};

const FIXED_INSTALLATION_ID: &str = "11111111-1111-4111-8111-111111111111";

pub(crate) fn installation() -> Installation {
    Installation::verified(
        InstallationName::default(),
        InstallationId::parse_canonical(FIXED_INSTALLATION_ID)
            .expect("fixed version-four installation ID"),
    )
}

fn image(name: &str, digest_byte: u8) -> ImmutableImage {
    ImmutableImage::new(format!(
        "registry.example/automata/{name}@sha256:{}",
        format!("{digest_byte:02x}").repeat(32)
    ))
    .expect("fixed immutable image")
}

fn imported_image(config_byte: u8, manifest_byte: u8) -> LocalImportedImage {
    LocalImportedImage::new(
        format!("sha256:{}", format!("{config_byte:02x}").repeat(32)),
        format!("sha256:{}", format!("{manifest_byte:02x}").repeat(32)),
    )
    .expect("fixed local imported image")
}

fn images(seed: u8) -> DesiredSpecImages {
    DesiredSpecImages::new(
        image("automata", seed),
        image("runner", seed.wrapping_add(1)),
        image("postgres", seed.wrapping_add(2)),
        image("rustfs", seed.wrapping_add(3)),
        image("sandbox-guest", seed.wrapping_add(4)),
        imported_image(seed.wrapping_add(5), seed.wrapping_add(6)),
    )
}

fn images_with_one_change(index: usize) -> DesiredSpecImages {
    let mut seeds = [17_u8, 18, 19, 20, 21, 22];
    seeds[index] = seeds[index].wrapping_add(64);
    DesiredSpecImages::new(
        image("automata", seeds[0]),
        image("runner", seeds[1]),
        image("postgres", seeds[2]),
        image("rustfs", seeds[3]),
        image("sandbox-guest", seeds[4]),
        imported_image(seeds[5], seeds[5].wrapping_add(1)),
    )
}

fn profile(architecture: EngineArchitecture, seed: u8) -> LocalProfile {
    let id = match architecture {
        EngineArchitecture::Amd64 => "automata.dev/github-hosted-ubuntu-24-04-x64-v1",
        EngineArchitecture::Arm64 => "automata.local/ubuntu-24-04-arm64-container-v1",
    };
    LocalProfile::new(
        architecture,
        EnvironmentProfile::new(
            EnvironmentProfileId::new(id).expect("fixed profile identity"),
            Sha256Digest::from_bytes([seed; 32]),
        ),
        image("job", seed),
    )
    .expect("fixed local profile")
}

fn results_transit() -> ResultsTransit {
    ResultsTransit::new(
        "172.20.0.0/23",
        Ipv4Addr::new(172, 20, 0, 1),
        Ipv4Addr::new(172, 20, 0, 2),
    )
    .expect("fixed Results transit")
}

fn input(
    max_parallel_jobs: u16,
    human_port: u16,
    architecture: EngineArchitecture,
    seed: u8,
) -> DesiredSpecInput {
    DesiredSpecInput::new(
        NonZeroU16::new(max_parallel_jobs).expect("nonzero capacity"),
        NonZeroU16::new(human_port).expect("nonzero host port"),
        profile(architecture, seed),
        images(seed.wrapping_add(16)),
        results_transit(),
    )
    .expect("bounded desired-spec input")
}

pub(crate) fn spec() -> DesiredSpec {
    DesiredSpec::new(
        &installation(),
        input(3, 8080, EngineArchitecture::Amd64, 1),
    )
    .expect("nonoverlapping desired spec")
}

#[test]
fn canonical_document_has_a_stable_golden_vector() {
    let spec = spec();
    let bytes = spec.canonical_bytes();
    assert!(bytes.len() < 16 * 1024);
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_eq!(
        String::from_utf8(bytes).expect("canonical JSON is UTF-8"),
        concat!(
            "{\"schema\":\"automata.local/desired-spec/v1\",",
            "\"installation\":{\"id\":\"11111111-1111-4111-8111-111111111111\",",
            "\"selector_key\":\"df06ebed0fcba9b2d00b0476426924f354f73d0d7c6cd4ed2844b52787ccd120\",",
            "\"compose_project\":\"automata-local-df06ebed0fcba9b2d00b0476426924f3\"},",
            "\"platform\":{\"architecture\":\"linux/amd64\"},",
            "\"capacity\":{\"max_parallel_jobs\":3},\"human\":{\"host_port\":8080},",
            "\"profile\":{\"id\":\"automata.dev/github-hosted-ubuntu-24-04-x64-v1\",",
            "\"manifest_sha256\":\"0101010101010101010101010101010101010101010101010101010101010101\",",
            "\"image\":\"registry.example/automata/job@sha256:0101010101010101010101010101010101010101010101010101010101010101\"},",
            "\"images\":{\"automata\":\"registry.example/automata/automata@sha256:1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"runner\":\"registry.example/automata/runner@sha256:1212121212121212121212121212121212121212121212121212121212121212\",",
            "\"postgres\":\"registry.example/automata/postgres@sha256:1313131313131313131313131313131313131313131313131313131313131313\",",
            "\"rustfs\":\"registry.example/automata/rustfs@sha256:1414141414141414141414141414141414141414141414141414141414141414\",",
            "\"sandbox_guest\":\"registry.example/automata/sandbox-guest@sha256:1515151515151515151515151515151515151515151515151515151515151515\",",
            "\"service_proxy\":{\"reference\":\"automata.local/automata-ci-service-proxy:manifest-1717171717171717171717171717171717171717171717171717171717171717\",",
            "\"config_image_id\":\"sha256:1616161616161616161616161616161616161616161616161616161616161616\",",
            "\"manifest_image_id\":\"sha256:1717171717171717171717171717171717171717171717171717171717171717\"}},",
            "\"results_transit\":{\"subnet\":\"172.20.0.0/23\",\"gateway\":\"172.20.0.1\",",
            "\"results_address\":\"172.20.0.2\"},",
            "\"plan_sha256\":\"8ee06ca78bc85e89ac5c38d8ba8cc28c999937648937a69190e7bb5b1355645e\"}\n"
        )
    );
}

#[test]
fn exact_worker_bounds_are_enforced() {
    let upper = u16::try_from(MAX_JOURNALED_SLOTS).expect("journal slot limit fits u16");
    assert!(
        DesiredSpecInput::new(
            NonZeroU16::new(upper).expect("nonzero journal limit"),
            NonZeroU16::new(1).expect("nonzero port"),
            profile(EngineArchitecture::Amd64, 1),
            images(2),
            results_transit(),
        )
        .is_ok()
    );

    let outside = upper.checked_add(1).expect("test boundary fits u16");
    assert_eq!(
        DesiredSpecInput::new(
            NonZeroU16::new(outside).expect("nonzero outside value"),
            NonZeroU16::new(1).expect("nonzero port"),
            profile(EngineArchitecture::Amd64, 1),
            images(2),
            results_transit(),
        )
        .expect_err("capacity above durable journal limit must fail")
        .code(),
        DesiredSpecErrorCode::Capacity
    );
}

#[test]
fn architecture_and_profile_identity_are_one_closed_pair() {
    let wrong = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.local/ubuntu-24-04-arm64-container-v1")
            .expect("fixed profile identity"),
        Sha256Digest::from_bytes([1; 32]),
    );
    assert_eq!(
        LocalProfile::new(EngineArchitecture::Amd64, wrong, image("job", 1))
            .expect_err("cross-architecture profile must fail")
            .code(),
        DesiredSpecErrorCode::Profile
    );
}

#[test]
fn local_imported_image_binds_the_exact_tag_and_both_content_ids() {
    let imported = imported_image(0x16, 0x17);
    assert_eq!(
        imported.reference(),
        concat!(
            "automata.local/automata-ci-service-proxy:manifest-",
            "1717171717171717171717171717171717171717171717171717171717171717"
        )
    );
    for (config, manifest) in [
        ("11".repeat(32), format!("sha256:{}", "22".repeat(32))),
        (
            format!("sha256:{}", "AA".repeat(32)),
            format!("sha256:{}", "22".repeat(32)),
        ),
        (
            format!("sha256:{}", "11".repeat(32)),
            "sha256:short".to_owned(),
        ),
    ] {
        assert_eq!(
            LocalImportedImage::new(config, manifest)
                .unwrap_err()
                .code(),
            DesiredSpecErrorCode::ImportedImage
        );
    }
}

#[test]
fn every_explicit_desired_input_changes_the_plan_digest() {
    let installation = installation();
    let mut variants = vec![
        input(3, 8080, EngineArchitecture::Amd64, 1),
        input(4, 8080, EngineArchitecture::Amd64, 1),
        input(3, 8081, EngineArchitecture::Amd64, 1),
        input(3, 8080, EngineArchitecture::Arm64, 1),
    ];
    variants.push(
        DesiredSpecInput::new(
            NonZeroU16::new(3).expect("nonzero capacity"),
            NonZeroU16::new(8080).expect("nonzero port"),
            LocalProfile::new(
                EngineArchitecture::Amd64,
                EnvironmentProfile::new(
                    EnvironmentProfileId::new("automata.dev/github-hosted-ubuntu-24-04-x64-v1")
                        .expect("profile ID"),
                    Sha256Digest::from_bytes([2; 32]),
                ),
                image("job", 1),
            )
            .expect("profile with changed manifest"),
            images(17),
            results_transit(),
        )
        .expect("changed profile manifest input"),
    );
    variants.push(
        DesiredSpecInput::new(
            NonZeroU16::new(3).expect("nonzero capacity"),
            NonZeroU16::new(8080).expect("nonzero port"),
            LocalProfile::new(
                EngineArchitecture::Amd64,
                EnvironmentProfile::new(
                    EnvironmentProfileId::new("automata.dev/github-hosted-ubuntu-24-04-x64-v1")
                        .expect("profile ID"),
                    Sha256Digest::from_bytes([1; 32]),
                ),
                image("job", 2),
            )
            .expect("profile with changed image"),
            images(17),
            results_transit(),
        )
        .expect("changed profile image input"),
    );
    for index in 0..6 {
        variants.push(
            DesiredSpecInput::new(
                NonZeroU16::new(3).expect("nonzero capacity"),
                NonZeroU16::new(8080).expect("nonzero port"),
                profile(EngineArchitecture::Amd64, 1),
                images_with_one_change(index),
                results_transit(),
            )
            .expect("changed image input"),
        );
    }
    variants.push(
        DesiredSpecInput::new(
            NonZeroU16::new(3).expect("nonzero capacity"),
            NonZeroU16::new(8080).expect("nonzero port"),
            profile(EngineArchitecture::Amd64, 1),
            images(17),
            ResultsTransit::new(
                "172.22.0.0/23",
                Ipv4Addr::new(172, 22, 0, 1),
                Ipv4Addr::new(172, 22, 0, 2),
            )
            .expect("changed Results transit"),
        )
        .expect("changed Results transit input"),
    );
    let digests = variants
        .into_iter()
        .map(|input| {
            DesiredSpec::new(&installation, input)
                .expect("nonoverlapping desired spec")
                .plan_digest()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(digests.len(), 13);
}

#[test]
fn results_transit_is_canonical_private_first_host_and_nonoverlapping() {
    for (subnet, gateway, address) in [
        ("172.20.0.1/23", [172, 20, 0, 1], [172, 20, 0, 2]),
        ("172.20.0.0/24", [172, 20, 0, 1], [172, 20, 0, 2]),
        ("203.0.112.0/23", [203, 0, 112, 1], [203, 0, 112, 2]),
        ("172.20.0.0/23", [172, 20, 0, 2], [172, 20, 0, 3]),
        ("172.20.0.0/23", [172, 20, 0, 1], [172, 20, 0, 1]),
        ("172.20.0.0/23", [172, 20, 0, 1], [172, 20, 2, 2]),
    ] {
        assert_eq!(
            ResultsTransit::new(subnet, Ipv4Addr::from(gateway), Ipv4Addr::from(address))
                .expect_err("invalid Results transit must fail")
                .code(),
            DesiredSpecErrorCode::ResultsTransit
        );
    }

    let provider_pool = ResultsTransit::new(
        "10.223.0.0/20",
        Ipv4Addr::new(10, 223, 0, 1),
        Ipv4Addr::new(10, 223, 0, 2),
    )
    .expect("canonical private pool shape");
    let input = DesiredSpecInput::new(
        NonZeroU16::new(1).expect("capacity"),
        NonZeroU16::new(8080).expect("port"),
        profile(EngineArchitecture::Amd64, 1),
        images(17),
        provider_pool,
    )
    .expect("bounded desired input");
    assert_eq!(
        DesiredSpec::new(&installation(), input)
            .expect_err("provider front pool overlap must fail")
            .code(),
        DesiredSpecErrorCode::ResultsTransit
    );
}

#[test]
fn desired_document_is_value_free_and_contains_no_runtime_identity() {
    let value: serde_json::Value =
        serde_json::from_slice(&spec().canonical_bytes()).expect("canonical desired JSON");
    let object = value.as_object().expect("desired document object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "capacity",
            "human",
            "images",
            "installation",
            "plan_sha256",
            "platform",
            "profile",
            "results_transit",
            "schema",
        ]
    );
    let encoded = value.to_string();
    for forbidden in [
        "repository",
        "snapshot",
        "credential",
        "secret",
        "token",
        "password",
        "container_id",
        "network_id",
        "engine_id",
        "context",
    ] {
        assert!(!encoded.contains(forbidden), "forbidden field: {forbidden}");
    }
}
