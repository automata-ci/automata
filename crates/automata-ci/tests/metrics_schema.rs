use automata_ci::{build_info::BuildInfo, server::ControlPlaneMetrics};

mod schema_contract {
    include!("../../automata-ci-metrics/tests/support/schema_contract.rs");
}

const MANIFEST: &str = include_str!("../../../deploy/observability/cardinality.json");

#[test]
#[ignore = "developer helper for reviewing deliberate schema changes"]
fn print_inferred_control_plane_schema() {
    let metrics =
        ControlPlaneMetrics::new(BuildInfo::current()).expect("valid embedded build provenance");
    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded OpenMetrics exposition");
    println!(
        "{}",
        schema_contract::inferred_profile_json(
            exposition.as_str(),
            &[
                "automata_ci_control_plane_",
                "automata_ci_postgres_",
                "automata_ci_results_",
                "automata_ci_storage_",
            ],
        )
    );
}

#[test]
fn control_plane_registry_exactly_matches_the_canonical_schema() {
    let metrics =
        ControlPlaneMetrics::new(BuildInfo::current()).expect("valid embedded build provenance");
    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded OpenMetrics exposition");
    schema_contract::assert_exposition_contract(
        MANIFEST,
        exposition.as_str(),
        &["common", "control_plane"],
    );
}
