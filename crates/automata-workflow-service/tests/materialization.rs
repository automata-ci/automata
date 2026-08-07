mod support;

use std::sync::Arc;

use automata_core::{ContainerFeature, JobContentReference, Sha256Digest, WorkflowJobKey};
use automata_store::WorkflowAdmissionIdempotency;
use automata_workflow_service::{
    AdmissionIdGenerator as _, MaterializeWorkflowRequest, Sha256AdmissionIdGenerator,
    WorkflowJobIdentity, WorkflowMaterializer as _, github_hosted_ubuntu_24_04_catalog,
};
use sha2::{Digest as _, Sha256};

#[test]
fn unchanged_ci_recompiles_and_materializes_all_jobs_with_exact_profile_and_dag() {
    let request = support::ci_request(
        "materialization-tenant",
        WorkflowAdmissionIdempotency::provider_delivery(support::DELIVERY).expect("delivery"),
    );
    let ids = Sha256AdmissionIdGenerator;
    let repository_id = ids.repository_id(request.tenant(), request.repository());
    let workflow_id = ids.workflow_id(repository_id, request.workflow_path());
    let run_id = ids.run_id(request.tenant(), request.idempotency());
    let identities = request
        .plan()
        .jobs()
        .iter()
        .map(|job| {
            let key = job.key().value().clone();
            WorkflowJobIdentity::new(key.clone(), ids.job_id(run_id, &key))
        })
        .collect::<Vec<_>>();
    let materializer = automata_workflow_service::GithubWorkflowMaterializer::new(
        github_hosted_ubuntu_24_04_catalog().expect("catalog"),
    );
    let output = materializer
        .materialize(&MaterializeWorkflowRequest::new(
            &request,
            repository_id,
            workflow_id,
            run_id,
            &identities,
            &event_reference(&request),
        ))
        .expect("materialize exact CI");

    assert_eq!(
        output
            .jobs()
            .iter()
            .map(|job| job.key().as_str())
            .collect::<Vec<_>>(),
        ["verify", "frontend", "dist"]
    );
    let expected_profile: Sha256Digest =
        "b0c2f5c0cad341e34c422a1b69bcc70bb82224f24d8512026cab9346dd1c6087"
            .parse()
            .expect("digest");
    for job in output.jobs() {
        let execution = job.envelope().execution();
        assert_eq!(job.envelope().version().get(), 4);
        assert_eq!(execution.workflow_name(), request.workflow_name());
        assert_eq!(execution.git_ref(), request.git_ref());
        assert_eq!(execution.workspace(), request.workspace());
        assert_eq!(execution.actor(), Some("local-bootstrap"));
        assert_eq!(execution.run_number(), None);
        assert_eq!(execution.run_attempt(), Some(1));
        assert_eq!(execution.event(), &event_reference(&request));
        let profile = job
            .envelope()
            .job()
            .requirements()
            .environment_profile()
            .expect("hosted profile");
        assert_eq!(
            profile.id().as_str(),
            "automata.dev/github-hosted-ubuntu-24-04-x64-v1"
        );
        assert_eq!(profile.digest(), expected_profile);
        assert!(
            job.envelope()
                .job()
                .requirements()
                .container_features()
                .contains(&ContainerFeature::DOCKER_COMPATIBLE_API)
        );
    }
    let concurrency = output.concurrency().expect("workflow concurrency");
    assert_eq!(concurrency.display_key(), "ci-CI-refs/heads/main");
    assert_eq!(concurrency.normalized_key(), "ci-ci-refs/heads/main");
    assert!(concurrency.cancel_in_progress());

    let verify = request
        .plan()
        .job(&WorkflowJobKey::new("verify").expect("key"))
        .expect("verify");
    let frontend = request
        .plan()
        .job(&WorkflowJobKey::new("frontend").expect("key"))
        .expect("frontend");
    let dist = request
        .plan()
        .job(&WorkflowJobKey::new("dist").expect("key"))
        .expect("dist");
    assert!(verify.needs().is_empty());
    assert!(frontend.needs().is_empty());
    assert_eq!(
        dist.needs()
            .iter()
            .map(|dependency| dependency.value().as_str())
            .collect::<Vec<_>>(),
        ["verify", "frontend"]
    );
}

#[test]
fn checked_profile_manifest_and_lock_match_catalog_attestation() {
    let manifest =
        include_bytes!("../../../images/github-hosted-ubuntu-24.04-x64/profile-manifest.json");
    let document: serde_json::Value =
        serde_json::from_slice(manifest).expect("checked profile manifest JSON");
    let lock: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../images/github-hosted-ubuntu-24.04-x64/profile-lock.json"
    ))
    .expect("checked profile lock JSON");
    assert_eq!(document["toolchain"]["clang"], "clang-18=1:18.1.3-1ubuntu1");
    assert_eq!(
        document["toolchain"]["libclang"],
        "libclang1-18=1:18.1.3-1ubuntu1"
    );
    let wasi_sdk = &document["toolchain"]["wasi_sdk"];
    assert_eq!(wasi_sdk["version"], "24.0");
    assert_eq!(wasi_sdk["platform"], "x86_64-linux");
    assert_eq!(wasi_sdk["archive"], "wasi-sdk-24.0-x86_64-linux.tar.gz");
    assert_eq!(
        wasi_sdk["archive_sha256"],
        "c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5"
    );
    assert_eq!(wasi_sdk["installation_root"], "/opt/wasi-sdk-24.0");
    assert_eq!(wasi_sdk["environment"], "WASI_SDK=/opt/wasi-sdk-24.0");
    let actual = Sha256Digest::from_bytes(Sha256::digest(manifest).into());
    let containerfile =
        include_bytes!("../../../images/github-hosted-ubuntu-24.04-x64/Containerfile");
    let containerfile_digest = Sha256Digest::from_bytes(Sha256::digest(containerfile).into());
    assert_eq!(lock["profile_id"], document["profile_id"]);
    assert_eq!(lock["image"], document["image"]);
    assert_eq!(lock["profile_manifest_sha256"], actual.to_string());
    assert_eq!(
        lock["containerfile_sha256"],
        containerfile_digest.to_string()
    );
    let catalog = github_hosted_ubuntu_24_04_catalog().expect("catalog");
    let selector = automata_core::RunnerLabel::new("ubuntu-24.04").expect("selector");
    assert_eq!(
        catalog
            .get(&selector)
            .expect("mapping")
            .environment_profile()
            .digest(),
        actual
    );
}

#[test]
fn exact_source_revalidation_rejects_a_plan_from_different_bytes() {
    let request = support::operation_request("mismatch-tenant");
    let mut changed = support::CI_SOURCE.to_owned();
    changed.push('\n');
    let mismatched = automata_workflow_service::WorkflowAdmissionRequest::builder(
        request.tenant().clone(),
        request.repository().clone(),
        request.workflow_path(),
        bytes::Bytes::from(changed),
        request.event().clone(),
        request.plan().clone(),
        request.idempotency().clone(),
    )
    .commit_sha(request.commit_sha())
    .git_ref(request.git_ref())
    .workflow_name(request.workflow_name())
    .workspace(request.workspace())
    .actor(request.actor().expect("fixture actor"))
    .run_attempt(request.run_attempt().expect("fixture attempt"))
    .build()
    .expect("provenance remains structurally valid");
    let ids = Sha256AdmissionIdGenerator;
    let repository_id = ids.repository_id(mismatched.tenant(), mismatched.repository());
    let workflow_id = ids.workflow_id(repository_id, mismatched.workflow_path());
    let run_id = ids.run_id(mismatched.tenant(), mismatched.idempotency());
    let identities = mismatched
        .plan()
        .jobs()
        .iter()
        .map(|job| {
            let key = job.key().value().clone();
            WorkflowJobIdentity::new(key.clone(), ids.job_id(run_id, &key))
        })
        .collect::<Vec<_>>();
    let materializer = automata_workflow_service::GithubWorkflowMaterializer::new(
        github_hosted_ubuntu_24_04_catalog().expect("catalog"),
    );
    assert!(
        materializer
            .materialize(&MaterializeWorkflowRequest::new(
                &mismatched,
                repository_id,
                workflow_id,
                run_id,
                &identities,
                &event_reference(&mismatched),
            ))
            .is_err()
    );
}

fn event_reference(
    request: &automata_workflow_service::WorkflowAdmissionRequest,
) -> JobContentReference {
    let digest = Sha256Digest::from_bytes(Sha256::digest(request.event()).into());
    JobContentReference::new(
        format!("admission/v1/workflow-event/sha256/{digest}"),
        digest,
        u64::try_from(request.event().len()).expect("event size"),
        automata_workflow_service::WORKFLOW_EVENT_MEDIA_TYPE,
    )
}

#[test]
fn application_ports_are_object_safe() {
    static_assertions::assert_obj_safe!(
        automata_workflow_service::AdmissionClock,
        automata_workflow_service::AdmissionIdGenerator,
        automata_workflow_service::WorkflowMaterializer,
        automata_store::WorkflowAdmissionRepository,
        automata_store::RunReconciliationRepository,
    );
    let _: Arc<dyn automata_workflow_service::WorkflowMaterializer> =
        Arc::new(automata_workflow_service::GithubWorkflowMaterializer::new(
            github_hosted_ubuntu_24_04_catalog().expect("catalog"),
        ));
}
