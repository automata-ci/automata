use automata_ci_auth::{
    github::GithubEndpoint, human::AuthenticationProvider, installation::InstallationRepository,
    login::LoginTransactionRepository, machine::MachineIdentityVerifier,
    session::HumanSessionRepository, vault::ProviderTokenVault,
};
use static_assertions::assert_obj_safe;

assert_obj_safe!(AuthenticationProvider);
assert_obj_safe!(InstallationRepository);
assert_obj_safe!(MachineIdentityVerifier);
assert_obj_safe!(HumanSessionRepository);
assert_obj_safe!(LoginTransactionRepository);
assert_obj_safe!(GithubEndpoint);
assert_obj_safe!(ProviderTokenVault);

#[test]
fn runtime_plugin_ports_remain_object_safe() {
    // The compile-time assertions above are the contract. This named test keeps the
    // property visible in ordinary test output.
}
