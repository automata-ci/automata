use automata_ci_execution::{ContainerEngine, ExecutionEndpoint, SandboxProvider};
use static_assertions::assert_obj_safe;

assert_obj_safe!(SandboxProvider);
assert_obj_safe!(ExecutionEndpoint);
assert_obj_safe!(ContainerEngine);

#[test]
fn provider_engine_and_endpoint_ports_remain_independently_object_safe() {
    fn accepts_provider(_: &dyn SandboxProvider) {}
    fn accepts_endpoint(_: &dyn ExecutionEndpoint) {}
    fn accepts_engine(_: &dyn ContainerEngine) {}

    let _ = accepts_provider;
    let _ = accepts_endpoint;
    let _ = accepts_engine;
}
