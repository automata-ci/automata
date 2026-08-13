mod support;

use automata_ci_runner_auth::RunnerMachineAuthLimits;
#[test]
fn limits_reject_zero_incoherent_and_excessive_values() {
    assert!(RunnerMachineAuthLimits::new(0, 1, 1).is_err());
    assert!(RunnerMachineAuthLimits::new(1, 2, 1).is_err());
    assert!(RunnerMachineAuthLimits::new(33, 1, 1).is_err());
    assert!(RunnerMachineAuthLimits::new(1, 1_048_577, 1_048_577).is_err());
    assert!(RunnerMachineAuthLimits::new(1, 1, 4_194_305).is_err());
}
