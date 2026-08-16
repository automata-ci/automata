use automata_ci_core::{
    TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence,
    TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion,
};

pub(crate) fn trusted_push_snapshot() -> TrustSnapshot {
    let repository =
        TrustRepositoryEvidence::new("100", "10").expect("stable repository trust evidence");
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_original_actor(
                    TrustActorEvidence::new("200", TrustActorKind::User, TrustAutomationKind::None)
                        .expect("stable actor trust evidence"),
                )
                .with_repositories(repository.clone(), repository)
                .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                .with_revisions("0123456789abcdef", "0123456789abcdef", "0123456789abcdef")
                .with_fork(false)
                .with_token_recursion(TrustTokenRecursion::Suppressed),
        )
        .expect("complete same-repository trust snapshot")
}
