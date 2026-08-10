mod support;

use automata_ci_auth::machine::MachineIdentityVerifier;
use automata_ci_runner_auth::{
    DurableRunnerMachineAuthenticator, RunnerMachineAuthLimits, RunnerMachineDirectory,
};
use automata_ci_runner_control::RunnerRegistrationAuthorizer;
use static_assertions::{assert_impl_all, assert_obj_safe};

assert_obj_safe!(RunnerMachineDirectory);
assert_obj_safe!(MachineIdentityVerifier);
assert_obj_safe!(RunnerRegistrationAuthorizer);
assert_impl_all!(DurableRunnerMachineAuthenticator: Send, Sync);

#[test]
fn runtime_composition_ports_remain_object_safe() {
    assert!(RunnerMachineAuthLimits::new(0, 1, 1).is_err());
    assert!(RunnerMachineAuthLimits::new(1, 2, 1).is_err());
    assert!(RunnerMachineAuthLimits::new(33, 1, 1).is_err());
    assert!(RunnerMachineAuthLimits::new(1, 1_048_577, 1_048_577).is_err());
    assert!(RunnerMachineAuthLimits::new(1, 1, 4_194_305).is_err());
}
