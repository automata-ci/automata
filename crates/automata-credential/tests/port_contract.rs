use automata_credential::RepositoryCredentialBroker;

static_assertions::assert_obj_safe!(RepositoryCredentialBroker);

#[test]
fn repository_credential_broker_is_object_safe() {
    fn accepts(_: &dyn RepositoryCredentialBroker) {}
    let _ = accepts;
}
