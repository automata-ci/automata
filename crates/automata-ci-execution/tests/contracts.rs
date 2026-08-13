use automata_ci_execution::{ContainerEngine, ExecutionEndpoint, SandboxProvider};
use static_assertions::assert_obj_safe;

assert_obj_safe!(SandboxProvider);
assert_obj_safe!(ExecutionEndpoint);
assert_obj_safe!(ContainerEngine);
