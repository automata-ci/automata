use crate::github_manifest_fixture;

use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_schedule::CronExpression;
use automata_ci_store::{
    ClaimDueGithubScheduleFire, ClaimGithubScheduleDiscovery, ClaimedGithubScheduleFire,
    CompleteGithubScheduleFire, GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE,
    GITHUB_SCHEDULE_INVALID_REGISTRY_FAILURE, GithubCheckName, GithubCheckSubjectKey,
    GithubProviderGitRef, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryName, GithubScheduleArchive, GithubScheduleClaimFence,
    GithubScheduleDiscoveryClaim, GithubScheduleFireClaim, GithubScheduleFireConclusion,
    GithubScheduleFireId, GithubScheduleFireReceipt, GithubScheduleRegistryEntry,
    GithubScheduleRegistryId, GithubScheduleRegistryReceipt, GithubScheduleSourceAuthority,
    GithubScheduleValueError, GithubScheduleWorkerId, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthoritySelector, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, MAX_GITHUB_REGISTERED_SCHEDULES,
    MAX_GITHUB_SCHEDULE_CLAIM_MILLIS, MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS,
    MAX_GITHUB_SCHEDULE_RETRY_MILLIS, ObjectKey, ProviderConnectionId, ProviderInstallationId,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    RegisterGithubScheduleRegistry, RegisterGithubScheduledCheckSubject, RetryGithubScheduleFire,
    TenantScope,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use github_manifest_fixture::fixture_github_runtime_policy;

const SOURCE_REVISION: &str = "1111111111111111111111111111111111111111";
const MAX_ARCHIVE_BYTES: u64 = 256 * 1_024 * 1_024;

#[test]
fn durable_identities_fences_and_archives_reject_invalid_sentinels() {
    assert_eq!(
        GithubScheduleRegistryId::from_uuid(Uuid::nil()),
        Err(GithubScheduleValueError::InvalidRegistryId)
    );
    assert_eq!(
        GithubScheduleFireId::from_uuid(Uuid::nil()),
        Err(GithubScheduleValueError::InvalidFireId)
    );
    assert_eq!(
        GithubScheduleWorkerId::from_uuid(Uuid::nil()),
        Err(GithubScheduleValueError::InvalidWorkerId)
    );

    let registry_id = registry_id(1);
    let fire_id = fire_id(2);
    let worker_id = worker_id(3);
    assert_eq!(registry_id.as_uuid(), Uuid::from_u128(1));
    assert_eq!(fire_id.as_uuid(), Uuid::from_u128(2));
    assert_eq!(worker_id.as_uuid(), Uuid::from_u128(3));

    assert_eq!(
        GithubScheduleClaimFence::new(0),
        Err(GithubScheduleValueError::InvalidClaimFence)
    );
    assert_eq!(
        GithubScheduleClaimFence::new(u64::try_from(i64::MAX).expect("positive") + 1),
        Err(GithubScheduleValueError::InvalidClaimFence)
    );
    assert_eq!(fence(7).get(), 7);

    let key = ObjectKey::new("github/schedules/archive.tar.gz").expect("object key");
    let digest = digest(9);
    assert!(matches!(
        GithubScheduleArchive::new(digest, key.clone(), 0),
        Err(GithubScheduleValueError::InvalidArchive)
    ));
    assert!(matches!(
        GithubScheduleArchive::new(digest, key.clone(), MAX_ARCHIVE_BYTES + 1),
        Err(GithubScheduleValueError::InvalidArchive)
    ));
    let archive = GithubScheduleArchive::new(digest, key, MAX_ARCHIVE_BYTES)
        .expect("maximum-sized archive descriptor");
    assert_eq!(archive.digest(), digest);
    assert_eq!(
        archive.object_key().as_str(),
        "github/schedules/archive.tar.gz"
    );
    assert_eq!(archive.encoded_size(), MAX_ARCHIVE_BYTES);
    assert_eq!(archive.media_type(), GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE);
}

#[test]
fn registry_entry_preserves_definition_and_derives_its_digest() {
    let schedule_entry = entry(
        0,
        ".ci/workflows/nightly.yml",
        10,
        3,
        "15 4 * * MON-FRI",
        "Europe/Sofia",
        10_000,
    );
    assert_eq!(schedule_entry.ordinal(), 0);
    assert_eq!(schedule_entry.workflow_path(), ".ci/workflows/nightly.yml");
    assert_eq!(schedule_entry.workflow_source_digest(), digest(10));
    assert_eq!(schedule_entry.schedule_ordinal(), 3);
    assert_eq!(schedule_entry.cron_expression(), "15 4 * * MON-FRI");
    assert_eq!(schedule_entry.timezone(), "Europe/Sofia");
    assert_eq!(schedule_entry.next_fire_at(), UnixMillis::new(10_000));
    assert_eq!(
        schedule_entry.entry_digest(),
        expected_entry_digest(
            ".ci/workflows/nightly.yml",
            digest(10),
            3,
            "15 4 * * MON-FRI",
            "Europe/Sofia",
        )
    );

    for mutation in [
        entry(
            0,
            ".ci/workflows/other.yml",
            10,
            3,
            "15 4 * * MON-FRI",
            "Europe/Sofia",
            10_000,
        ),
        entry(
            0,
            ".ci/workflows/nightly.yml",
            11,
            3,
            "15 4 * * MON-FRI",
            "Europe/Sofia",
            10_000,
        ),
        entry(
            0,
            ".ci/workflows/nightly.yml",
            10,
            4,
            "15 4 * * MON-FRI",
            "Europe/Sofia",
            10_000,
        ),
        entry(
            0,
            ".ci/workflows/nightly.yml",
            10,
            3,
            "45 4 * * MON-FRI",
            "Europe/Sofia",
            10_000,
        ),
        entry(
            0,
            ".ci/workflows/nightly.yml",
            10,
            3,
            "15 4 * * MON-FRI",
            "UTC",
            10_000,
        ),
    ] {
        assert_ne!(mutation.entry_digest(), schedule_entry.entry_digest());
    }
    assert_eq!(
        entry(
            1,
            ".ci/workflows/nightly.yml",
            10,
            3,
            "15 4 * * MON-FRI",
            "Europe/Sofia",
            20_000,
        )
        .entry_digest(),
        schedule_entry.entry_digest(),
        "registry position and runtime cursor are not source-definition identity"
    );

    let debug = format!("{schedule_entry:?}");
    assert!(debug.contains("GithubCheckSubjectKey([REDACTED])"));
    assert!(!debug.contains(".ci/workflows/nightly.yml"));
}

#[test]
fn registry_entry_rejects_invalid_bounds_and_schedule_fields() {
    for invalid in [
        GithubScheduleRegistryEntry::new(
            u16::try_from(MAX_GITHUB_REGISTERED_SCHEDULES).expect("bounded"),
            workflow_path(".ci/workflows/nightly.yml"),
            digest(1),
            0,
            "0/5 * * * *",
            "UTC",
            UnixMillis::new(1),
        ),
        GithubScheduleRegistryEntry::new(
            0,
            workflow_path(".ci/workflows/nightly.yml"),
            digest(1),
            64,
            "0/5 * * * *",
            "UTC",
            UnixMillis::new(1),
        ),
        GithubScheduleRegistryEntry::new(
            0,
            workflow_path(".ci/workflows/nightly.yml"),
            digest(1),
            0,
            "* * * * *",
            "UTC",
            UnixMillis::new(1),
        ),
        GithubScheduleRegistryEntry::new(
            0,
            workflow_path(".ci/workflows/nightly.yml"),
            digest(1),
            0,
            "0/5 * * * *",
            "Not/A_Real_Zone",
            UnixMillis::new(1),
        ),
        GithubScheduleRegistryEntry::new(
            0,
            workflow_path(".ci/workflows/nightly.yml"),
            digest(1),
            0,
            "0/5 * * * *",
            "UTC",
            UnixMillis::new(-1),
        ),
    ] {
        assert!(matches!(
            invalid,
            Err(GithubScheduleValueError::InvalidEntry)
        ));
    }
}

#[test]
fn discovery_request_preserves_private_and_public_authority_evidence() {
    let private_manifest = manifest("schedule-private", ProviderRepositoryVisibility::Private, 1);
    let public_manifest = manifest("schedule-public", ProviderRepositoryVisibility::Public, 1);
    let private_selector = source_selector(&private_manifest, 30);
    let private_authority = GithubScheduleSourceAuthority::Private(private_selector.clone());
    let owner = ProviderRepositoryOwnerId::new(404).expect("owner ID");

    let request = ClaimGithubScheduleDiscovery::new(
        registry_id(31),
        private_manifest.clone(),
        owner,
        private_authority.clone(),
        worker_id(32),
        MAX_GITHUB_SCHEDULE_CLAIM_MILLIS,
    )
    .expect("compatible private discovery request");
    assert_eq!(request.registry_id(), registry_id(31));
    assert_eq!(request.manifest(), &private_manifest);
    assert_eq!(request.repository_owner_id(), owner);
    assert_eq!(request.worker_id(), worker_id(32));
    assert_eq!(request.lease_millis(), MAX_GITHUB_SCHEDULE_CLAIM_MILLIS);
    assert_eq!(
        request.source_authority().as_durable_str(),
        "private_repository_source_read"
    );
    assert_eq!(
        request
            .source_authority()
            .private_selector()
            .expect("private selector"),
        &private_selector
    );

    let public = ClaimGithubScheduleDiscovery::new(
        registry_id(33),
        public_manifest.clone(),
        owner,
        GithubScheduleSourceAuthority::PublicAnonymous,
        worker_id(34),
        1,
    )
    .expect("public anonymous discovery request");
    assert_eq!(
        public.source_authority().as_durable_str(),
        "public_anonymous"
    );
    assert_eq!(public.source_authority().private_selector(), None);
}

#[test]
fn discovery_request_rejects_owner_and_source_authority_mismatches() {
    let private_manifest = manifest("schedule-private", ProviderRepositoryVisibility::Private, 1);
    let public_manifest = manifest("schedule-public", ProviderRepositoryVisibility::Public, 1);
    let private_authority =
        GithubScheduleSourceAuthority::Private(source_selector(&private_manifest, 30));
    let owner = ProviderRepositoryOwnerId::new(404).expect("owner ID");
    assert!(matches!(
        ClaimGithubScheduleDiscovery::new(
            registry_id(35),
            private_manifest.clone(),
            ProviderRepositoryOwnerId::new(405).expect("different owner ID"),
            private_authority.clone(),
            worker_id(36),
            1,
        ),
        Err(GithubScheduleValueError::RepositoryOwnerMismatch)
    ));
    assert!(matches!(
        ClaimGithubScheduleDiscovery::new(
            registry_id(37),
            unbound_manifest(
                "schedule-owner-unbound",
                ProviderRepositoryVisibility::Public,
                1,
            ),
            owner,
            GithubScheduleSourceAuthority::PublicAnonymous,
            worker_id(38),
            1,
        ),
        Err(GithubScheduleValueError::RepositoryOwnerMismatch)
    ));

    for (candidate_manifest, authority) in [
        (
            private_manifest.clone(),
            GithubScheduleSourceAuthority::PublicAnonymous,
        ),
        (public_manifest.clone(), private_authority.clone()),
        (
            private_manifest.clone(),
            GithubScheduleSourceAuthority::Private(source_selector(
                &manifest("another-tenant", ProviderRepositoryVisibility::Private, 1),
                35,
            )),
        ),
        (
            private_manifest.clone(),
            GithubScheduleSourceAuthority::Private(
                GithubServerServiceAuthoritySelector::from_durable_parts(
                    private_manifest.tenant().clone(),
                    GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(36))
                        .expect("authority ID"),
                    digest(36),
                    GithubServerServiceRevision::new(2).expect("revision"),
                    private_manifest.policy_revision(),
                ),
            ),
        ),
    ] {
        assert!(matches!(
            ClaimGithubScheduleDiscovery::new(
                registry_id(37),
                candidate_manifest,
                owner,
                authority,
                worker_id(38),
                1,
            ),
            Err(GithubScheduleValueError::InvalidSourceAuthority)
        ));
    }
}

#[test]
fn discovery_request_rejects_invalid_lease_bounds() {
    let private_manifest = manifest("schedule-private", ProviderRepositoryVisibility::Private, 1);
    let private_authority =
        GithubScheduleSourceAuthority::Private(source_selector(&private_manifest, 30));
    let owner = ProviderRepositoryOwnerId::new(404).expect("owner ID");
    for lease in [0, -1, MAX_GITHUB_SCHEDULE_CLAIM_MILLIS + 1] {
        assert!(matches!(
            ClaimGithubScheduleDiscovery::new(
                registry_id(39),
                private_manifest.clone(),
                owner,
                private_authority.clone(),
                worker_id(40),
                lease,
            ),
            Err(GithubScheduleValueError::InvalidLease)
        ));
    }
}

#[test]
fn registry_preserves_canonical_inventory_evidence() {
    let provider_manifest = manifest(
        "registry-validation",
        ProviderRepositoryVisibility::Private,
        1,
    );
    let authority = GithubScheduleSourceAuthority::Private(source_selector(&provider_manifest, 50));
    let claim = discovery_claim(51, 52, 1_000, 2_000);
    let entries = canonical_registry_entries(claim);
    let registry = RegisterGithubScheduleRegistry::new(
        claim,
        provider_manifest.clone(),
        authority.clone(),
        SOURCE_REVISION,
        archive(3, "github/schedules/three.tar.gz", 300),
        entries.clone(),
    )
    .expect("canonical registry");
    assert_eq!(registry.registry_id(), registry_id(51));
    assert_eq!(registry.discovery_claim(), claim);
    assert_eq!(registry.manifest(), &provider_manifest);
    assert_eq!(registry.repository_owner_id().get(), 404);
    assert_eq!(registry.source_authority(), &authority);
    assert_eq!(registry.source_revision(), SOURCE_REVISION);
    assert_eq!(registry.archive().digest(), digest(3));
    assert_eq!(registry.entries(), entries);
}

#[test]
fn registry_rejects_invalid_source_revisions() {
    let provider_manifest = manifest(
        "registry-validation",
        ProviderRepositoryVisibility::Private,
        1,
    );
    let authority = GithubScheduleSourceAuthority::Private(source_selector(&provider_manifest, 50));
    let claim = discovery_claim(51, 52, 1_000, 2_000);
    let entries = canonical_registry_entries(claim);
    for revision in [
        "111111111111111111111111111111111111111",
        "11111111111111111111111111111111111111111",
        "111111111111111111111111111111111111111g",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(matches!(
            RegisterGithubScheduleRegistry::new(
                claim,
                provider_manifest.clone(),
                authority.clone(),
                revision,
                archive(3, "github/schedules/three.tar.gz", 300),
                entries.clone(),
            ),
            Err(GithubScheduleValueError::InvalidRegistry)
        ));
    }
}

#[test]
fn registry_rejects_noncanonical_inventory_shapes() {
    let provider_manifest = manifest(
        "registry-validation",
        ProviderRepositoryVisibility::Private,
        1,
    );
    let authority = GithubScheduleSourceAuthority::Private(source_selector(&provider_manifest, 50));
    let claim = discovery_claim(51, 52, 1_000, 2_000);
    let invalid_inventories = [
        vec![discovered_entry(
            claim.claimed_at(),
            1,
            ".ci/workflows/a.yml",
            1,
            0,
            "0/5 * * * *",
            "UTC",
        )],
        vec![
            discovered_entry(
                claim.claimed_at(),
                0,
                ".ci/workflows/b.yml",
                2,
                0,
                "0/5 * * * *",
                "UTC",
            ),
            discovered_entry(
                claim.claimed_at(),
                1,
                ".ci/workflows/a.yml",
                1,
                0,
                "0/5 * * * *",
                "UTC",
            ),
        ],
        vec![
            discovered_entry(
                claim.claimed_at(),
                0,
                ".ci/workflows/a.yml",
                1,
                0,
                "0/5 * * * *",
                "UTC",
            ),
            discovered_entry(
                claim.claimed_at(),
                1,
                ".ci/workflows/a.yml",
                1,
                0,
                "3/5 * * * *",
                "UTC",
            ),
        ],
        vec![
            discovered_entry(
                claim.claimed_at(),
                0,
                ".ci/workflows/a.yml",
                1,
                0,
                "0/5 * * * *",
                "UTC",
            ),
            discovered_entry(
                claim.claimed_at(),
                1,
                ".ci/workflows/a.yml",
                2,
                1,
                "3/5 * * * *",
                "UTC",
            ),
        ],
    ];
    for invalid_entries in invalid_inventories {
        assert!(matches!(
            RegisterGithubScheduleRegistry::new(
                claim,
                provider_manifest.clone(),
                authority.clone(),
                SOURCE_REVISION,
                archive(3, "github/schedules/three.tar.gz", 300),
                invalid_entries,
            ),
            Err(GithubScheduleValueError::InvalidRegistry)
        ));
    }
}

#[test]
fn registry_rejects_authority_incompatible_with_the_manifest() {
    let provider_manifest = manifest(
        "registry-validation",
        ProviderRepositoryVisibility::Private,
        1,
    );
    let claim = discovery_claim(51, 52, 1_000, 2_000);
    assert!(matches!(
        RegisterGithubScheduleRegistry::new(
            claim,
            provider_manifest,
            GithubScheduleSourceAuthority::PublicAnonymous,
            SOURCE_REVISION,
            archive(3, "github/schedules/three.tar.gz", 300),
            canonical_registry_entries(claim),
        ),
        Err(GithubScheduleValueError::InvalidRegistry)
    ));
}

#[test]
fn registry_rejects_only_a_tampered_first_fire_cursor() {
    let provider_manifest = manifest(
        "registry-validation",
        ProviderRepositoryVisibility::Private,
        1,
    );
    let authority = GithubScheduleSourceAuthority::Private(source_selector(&provider_manifest, 50));
    let claim = discovery_claim(51, 52, 1_000, 2_000);
    let tampered_occurrence = vec![entry(
        0,
        ".ci/workflows/a.yml",
        1,
        0,
        "0/5 * * * *",
        "UTC",
        10_001,
    )];
    assert!(matches!(
        RegisterGithubScheduleRegistry::new(
            claim,
            provider_manifest,
            authority,
            SOURCE_REVISION,
            archive(3, "github/schedules/non-occurrence.tar.gz", 300),
            tampered_occurrence,
        ),
        Err(GithubScheduleValueError::InvalidRegistry)
    ));
}

#[test]
fn registry_accepts_an_exact_maximum_inventory() {
    let mut maximum = Vec::with_capacity(MAX_GITHUB_REGISTERED_SCHEDULES);
    let maximum_claim = discovery_claim(53, 54, 1_000, 2_000);
    for ordinal in 0..MAX_GITHUB_REGISTERED_SCHEDULES {
        maximum.push(discovered_entry(
            maximum_claim.claimed_at(),
            u16::try_from(ordinal).expect("bounded ordinal"),
            &format!(".ci/workflows/{ordinal:03}.yml"),
            u8::try_from(ordinal % 255 + 1).expect("digest byte"),
            0,
            "0/5 * * * *",
            "UTC",
        ));
    }
    RegisterGithubScheduleRegistry::new(
        maximum_claim,
        manifest("registry-maximum", ProviderRepositoryVisibility::Public, 1),
        GithubScheduleSourceAuthority::PublicAnonymous,
        SOURCE_REVISION,
        archive(4, "github/schedules/maximum.tar.gz", 400),
        maximum.clone(),
    )
    .expect("maximum canonical inventory");
}

#[test]
fn inventory_digest_excludes_separately_bound_registry_evidence() {
    let provider_manifest = manifest("inventory-digest", ProviderRepositoryVisibility::Public, 1);
    let baseline_claim = discovery_claim(60, 61, 1_000, 2_000);
    let baseline_entries = baseline_inventory_entries(baseline_claim);
    let baseline = RegisterGithubScheduleRegistry::new(
        baseline_claim,
        provider_manifest.clone(),
        GithubScheduleSourceAuthority::PublicAnonymous,
        SOURCE_REVISION,
        archive(6, "github/schedules/baseline.tar.gz", 600),
        baseline_entries.clone(),
    )
    .expect("baseline registry");
    assert_eq!(
        baseline.inventory_digest(),
        expected_inventory_digest(&baseline_entries)
    );

    let same_definitions_claim = discovery_claim(62, 63, 3_000, 4_000);
    let same_definitions = baseline_inventory_entries(same_definitions_claim);
    let separately_bound_registry = RegisterGithubScheduleRegistry::new(
        same_definitions_claim,
        manifest(
            "inventory-other-manifest",
            ProviderRepositoryVisibility::Public,
            2,
        ),
        GithubScheduleSourceAuthority::PublicAnonymous,
        "2222222222222222222222222222222222222222",
        archive(7, "github/schedules/other.tar.gz", 700),
        same_definitions,
    )
    .expect("same inventory with different registry evidence");
    assert_eq!(
        baseline.inventory_digest(),
        separately_bound_registry.inventory_digest(),
        "manifest, source revision, archive, authority, and first-fire cursors are separately exact evidence"
    );
}

#[test]
fn inventory_digest_changes_for_each_source_definition_mutation() {
    let provider_manifest = manifest("inventory-digest", ProviderRepositoryVisibility::Public, 1);
    let baseline_claim = discovery_claim(60, 61, 1_000, 2_000);
    let baseline_entries = baseline_inventory_entries(baseline_claim);
    let baseline_digest = RegisterGithubScheduleRegistry::new(
        baseline_claim,
        provider_manifest.clone(),
        GithubScheduleSourceAuthority::PublicAnonymous,
        SOURCE_REVISION,
        archive(6, "github/schedules/baseline.tar.gz", 600),
        baseline_entries.clone(),
    )
    .expect("baseline registry")
    .inventory_digest();
    let mutations = [
        vec![discovered_entry(
            baseline_claim.claimed_at(),
            0,
            ".ci/workflows/a.yml",
            1,
            0,
            "0/5 * * * *",
            "UTC",
        )],
        vec![
            discovered_entry(
                baseline_claim.claimed_at(),
                0,
                ".ci/workflows/a.yml",
                9,
                0,
                "0/5 * * * *",
                "UTC",
            ),
            baseline_entries[1].clone(),
        ],
        vec![
            discovered_entry(
                baseline_claim.claimed_at(),
                0,
                ".ci/workflows/a.yml",
                1,
                0,
                "3/5 * * * *",
                "UTC",
            ),
            baseline_entries[1].clone(),
        ],
        vec![
            baseline_entries[0].clone(),
            discovered_entry(
                baseline_claim.claimed_at(),
                1,
                ".ci/workflows/c.yml",
                2,
                0,
                "0 3 * * *",
                "Europe/Sofia",
            ),
        ],
        vec![
            baseline_entries[0].clone(),
            discovered_entry(
                baseline_claim.claimed_at(),
                1,
                ".ci/workflows/b.yml",
                2,
                0,
                "0 3 * * *",
                "UTC",
            ),
        ],
    ];
    for (index, entries) in mutations.into_iter().enumerate() {
        let index = u128::try_from(index).expect("bounded mutation index");
        let registry = RegisterGithubScheduleRegistry::new(
            discovery_claim(70 + index, 80 + index, 1_000, 2_000),
            provider_manifest.clone(),
            GithubScheduleSourceAuthority::PublicAnonymous,
            SOURCE_REVISION,
            archive(6, "github/schedules/baseline.tar.gz", 600),
            entries,
        )
        .expect("canonical mutated registry");
        assert_ne!(registry.inventory_digest(), baseline_digest);
    }
}

#[test]
fn discovery_and_fire_claim_snapshots_enforce_timestamp_and_attempt_invariants() {
    let discovery = GithubScheduleDiscoveryClaim::from_durable_parts(
        registry_id(90),
        worker_id(91),
        fence(1),
        UnixMillis::new(1_000),
        UnixMillis::new(1_000 + MAX_GITHUB_SCHEDULE_CLAIM_MILLIS),
    )
    .expect("maximum discovery lease");
    assert_eq!(discovery.registry_id(), registry_id(90));
    assert_eq!(discovery.worker_id(), worker_id(91));
    assert_eq!(discovery.fence(), fence(1));
    assert_eq!(discovery.claimed_at(), UnixMillis::new(1_000));
    assert_eq!(
        discovery.expires_at(),
        UnixMillis::new(1_000 + MAX_GITHUB_SCHEDULE_CLAIM_MILLIS)
    );
    for (claimed_at, expires_at) in [
        (-1, 1),
        (1, 1),
        (2, 1),
        (1, 1 + MAX_GITHUB_SCHEDULE_CLAIM_MILLIS + 1),
    ] {
        assert!(matches!(
            GithubScheduleDiscoveryClaim::from_durable_parts(
                registry_id(90),
                worker_id(91),
                fence(1),
                UnixMillis::new(claimed_at),
                UnixMillis::new(expires_at),
            ),
            Err(GithubScheduleValueError::InvalidClaim)
        ));
    }

    let claim = fire_claim(92, 93, MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS, 4, 10_000, 10_001);
    assert_eq!(claim.fire_id(), fire_id(92));
    assert_eq!(claim.worker_id(), worker_id(93));
    assert_eq!(claim.attempt(), MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS);
    assert_eq!(claim.fence(), fence(4));
    assert_eq!(claim.claimed_at(), UnixMillis::new(10_000));
    assert_eq!(claim.expires_at(), UnixMillis::new(10_001));

    let renewed = GithubScheduleFireClaim::from_durable_parts(
        fire_id(92),
        worker_id(93),
        1,
        fence(5),
        UnixMillis::new(10_000),
        UnixMillis::new(10_000 + 2 * MAX_GITHUB_SCHEDULE_CLAIM_MILLIS),
    )
    .expect("renewed snapshot can outlive one interval from its original claim time");
    assert!(
        renewed.expires_at().get() - renewed.claimed_at().get() > MAX_GITHUB_SCHEDULE_CLAIM_MILLIS
    );

    for (attempt, claimed_at, expires_at) in [
        (0, 1, 2),
        (MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS + 1, 1, 2),
        (1, -1, 2),
        (1, 1, 1),
        (1, 2, 1),
    ] {
        assert!(matches!(
            GithubScheduleFireClaim::from_durable_parts(
                fire_id(94),
                worker_id(95),
                attempt,
                fence(1),
                UnixMillis::new(claimed_at),
                UnixMillis::new(expires_at),
            ),
            Err(GithubScheduleValueError::InvalidClaim)
        ));
    }

    let policy = ClaimDueGithubScheduleFire::new(worker_id(96), MAX_GITHUB_SCHEDULE_CLAIM_MILLIS)
        .expect("maximum fire lease request");
    assert_eq!(policy.worker_id(), worker_id(96));
    assert_eq!(policy.lease_millis(), MAX_GITHUB_SCHEDULE_CLAIM_MILLIS);
    for lease in [0, -1, MAX_GITHUB_SCHEDULE_CLAIM_MILLIS + 1] {
        assert!(matches!(
            ClaimDueGithubScheduleFire::new(worker_id(96), lease),
            Err(GithubScheduleValueError::InvalidLease)
        ));
    }
}

#[test]
fn completion_and_retry_accept_only_bounded_sanitized_outcomes() {
    let claim = fire_claim(100, 101, 2, 3, 10_000, 20_000);
    let run_id = RunId::from_uuid(Uuid::from_u128(102));
    let admitted = CompleteGithubScheduleFire::new(
        claim,
        GithubScheduleFireConclusion::Admitted(run_id),
        UnixMillis::new(0),
    )
    .expect("the repository, not claim time, verifies advancement from durable scheduled_at");
    assert_eq!(admitted.claim(), claim);
    assert_eq!(
        admitted.conclusion(),
        &GithubScheduleFireConclusion::Admitted(run_id)
    );
    assert_eq!(admitted.next_fire_at(), Some(UnixMillis::new(0)));

    for conclusion in [
        GithubScheduleFireConclusion::Skipped("workflow_not_selected".into()),
        GithubScheduleFireConclusion::Failed("github.schedule:compile-failed".into()),
        GithubScheduleFireConclusion::Failed(format!("a{}z", "b".repeat(126))),
    ] {
        CompleteGithubScheduleFire::new(claim, conclusion, UnixMillis::new(30_000))
            .expect("sanitized terminal conclusion");
    }
    for kind in [
        String::new(),
        "UPPERCASE".into(),
        "contains secret".into(),
        "path/segment".into(),
        ".leading".into(),
        "trailing-".into(),
        format!("a{}z", "b".repeat(127)),
    ] {
        for conclusion in [
            GithubScheduleFireConclusion::Skipped(kind.clone()),
            GithubScheduleFireConclusion::Failed(kind.clone()),
        ] {
            assert!(matches!(
                CompleteGithubScheduleFire::new(claim, conclusion, UnixMillis::new(30_000)),
                Err(GithubScheduleValueError::InvalidConclusion)
            ));
        }
    }
    assert!(matches!(
        CompleteGithubScheduleFire::new(
            claim,
            GithubScheduleFireConclusion::Admitted(run_id),
            UnixMillis::new(-1),
        ),
        Err(GithubScheduleValueError::InvalidConclusion)
    ));

    let invalid_registry = CompleteGithubScheduleFire::invalid_registry(claim);
    assert_eq!(invalid_registry.claim(), claim);
    assert_eq!(
        invalid_registry.conclusion(),
        &GithubScheduleFireConclusion::Failed(GITHUB_SCHEDULE_INVALID_REGISTRY_FAILURE.to_owned())
    );
    assert_eq!(invalid_registry.next_fire_at(), None);

    let retry = RetryGithubScheduleFire::new(
        claim,
        MAX_GITHUB_SCHEDULE_RETRY_MILLIS,
        "provider.transient-503",
    )
    .expect("maximum sanitized retry");
    assert_eq!(retry.claim(), claim);
    assert_eq!(retry.retry_after_millis(), MAX_GITHUB_SCHEDULE_RETRY_MILLIS);
    assert_eq!(retry.failure_kind(), "provider.transient-503");
    for (delay, kind) in [
        (0, "transient"),
        (-1, "transient"),
        (MAX_GITHUB_SCHEDULE_RETRY_MILLIS + 1, "transient"),
        (1, "contains secret"),
        (1, "-leading"),
    ] {
        assert!(matches!(
            RetryGithubScheduleFire::new(claim, delay, kind),
            Err(GithubScheduleValueError::InvalidRetry)
        ));
    }
}

#[test]
fn claimed_fire_and_receipts_preserve_complete_noncredential_evidence() {
    let manifest = manifest("claimed-fire", ProviderRepositoryVisibility::Public, 1);
    let claim = fire_claim(110, 111, 1, 2, 10_000, 20_000);
    let archive = archive(8, "github/schedules/claimed.tar.gz", 800);
    let entry = entry(
        0,
        ".ci/workflows/claimed.yml",
        9,
        0,
        "0/5 * * * *",
        "UTC",
        30_000,
    );
    let fire = ClaimedGithubScheduleFire::from_durable_parts(
        claim,
        manifest.tenant().clone(),
        manifest.repository_id(),
        "provider-repository-202".into(),
        "example".into(),
        "neutral-schedules".into(),
        manifest.connection_id(),
        registry_id(112),
        manifest.revision(),
        manifest.digest(),
        SOURCE_REVISION.into(),
        "refs/heads/main".into(),
        archive.clone(),
        entry.clone(),
        UnixMillis::new(30_000),
    );
    assert_eq!(fire.claim(), claim);
    assert_eq!(fire.tenant(), manifest.tenant());
    assert_eq!(fire.repository_id(), manifest.repository_id());
    assert_eq!(fire.provider_repository_id(), "provider-repository-202");
    assert_eq!(fire.repository_owner(), "example");
    assert_eq!(fire.repository_name(), "neutral-schedules");
    assert_eq!(fire.connection_id(), manifest.connection_id());
    assert_eq!(fire.registry_id(), registry_id(112));
    assert_eq!(fire.manifest_revision(), manifest.revision());
    assert_eq!(fire.manifest_digest(), manifest.digest());
    assert_eq!(fire.source_revision(), SOURCE_REVISION);
    assert_eq!(fire.default_branch_ref(), "refs/heads/main");
    assert_eq!(fire.archive(), &archive);
    assert_eq!(fire.entry(), &entry);
    assert_eq!(fire.scheduled_at(), UnixMillis::new(30_000));
    let debug = format!("{fire:?}");
    assert!(debug.contains("GithubCheckSubjectKey([REDACTED])"));
    assert!(!debug.contains(".ci/workflows/claimed.yml"));

    let check = RegisterGithubScheduledCheckSubject::new(claim);
    assert_eq!(check.claim(), claim);
    let registry_receipt = GithubScheduleRegistryReceipt::from_durable_parts(
        registry_id(112),
        UnixMillis::new(40_000),
        true,
    );
    assert_eq!(registry_receipt.registry_id(), registry_id(112));
    assert_eq!(registry_receipt.registered_at(), UnixMillis::new(40_000));
    assert!(registry_receipt.is_replay());
    let fire_receipt =
        GithubScheduleFireReceipt::from_durable_parts(fire_id(110), UnixMillis::new(50_000));
    assert_eq!(fire_receipt.fire_id(), fire_id(110));
    assert_eq!(fire_receipt.recorded_at(), UnixMillis::new(50_000));
}

fn baseline_inventory_entries(
    claim: GithubScheduleDiscoveryClaim,
) -> Vec<GithubScheduleRegistryEntry> {
    vec![
        discovered_entry(
            claim.claimed_at(),
            0,
            ".ci/workflows/a.yml",
            1,
            0,
            "0/5 * * * *",
            "UTC",
        ),
        discovered_entry(
            claim.claimed_at(),
            1,
            ".ci/workflows/b.yml",
            2,
            0,
            "0 3 * * *",
            "Europe/Sofia",
        ),
    ]
}

fn canonical_registry_entries(
    claim: GithubScheduleDiscoveryClaim,
) -> Vec<GithubScheduleRegistryEntry> {
    vec![
        discovered_entry(
            claim.claimed_at(),
            0,
            ".ci/workflows/a.yml",
            1,
            0,
            "0/5 * * * *",
            "UTC",
        ),
        discovered_entry(
            claim.claimed_at(),
            1,
            ".ci/workflows/a.yml",
            1,
            1,
            "3/5 * * * *",
            "UTC",
        ),
        discovered_entry(
            claim.claimed_at(),
            2,
            ".ci/workflows/b.yml",
            2,
            0,
            "0 3 * * *",
            "UTC",
        ),
    ]
}

fn manifest(
    tenant: &str,
    visibility: ProviderRepositoryVisibility,
    revision: u64,
) -> GithubProviderManifest {
    unbound_manifest(tenant, visibility, revision)
        .with_repository_owner_id(ProviderRepositoryOwnerId::new(404).expect("owner ID"))
}

fn unbound_manifest(
    tenant: &str,
    visibility: ProviderRepositoryVisibility,
    revision: u64,
) -> GithubProviderManifest {
    let runtime = fixture_github_runtime_policy(1);
    GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        ProviderConnectionId::from_uuid(Uuid::from_u128(0x1_0000 + u128::from(revision)))
            .expect("connection"),
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryId::new(202).expect("repository"),
        GithubRepositoryName::new("example/neutral-schedules").expect("repository name"),
        visibility,
        GithubServerServiceAppId::new(303).expect("App"),
        GithubServerServiceAppClientId::new("Iv1.1111111111111111").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        digest(7),
        GithubServerServiceRevision::new(revision).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(digest(8)).expect("webhook verifier"),
        GithubServerServiceRevision::new(revision).expect("verifier revision"),
        GithubServerServiceRevision::new(revision).expect("policy revision"),
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime.runner_policy,
        runtime.revision,
        runtime.semantic_digest,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
        GithubCheckName::new("Neutral CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(revision).expect("manifest revision"),
    )
}

fn source_selector(
    manifest: &GithubProviderManifest,
    authority_id: u128,
) -> GithubServerServiceAuthoritySelector {
    let identity = GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(authority_id))
            .expect("authority ID"),
        manifest.repository_id(),
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        GithubServerServiceScope::PrivateRepositorySourceRead,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        digest(99),
    )
    .expect("source authority identity");
    GithubServerServiceAuthoritySelector::from_identity(&identity)
}

fn registry_id(value: u128) -> GithubScheduleRegistryId {
    GithubScheduleRegistryId::from_uuid(Uuid::from_u128(value)).expect("registry ID")
}

fn fire_id(value: u128) -> GithubScheduleFireId {
    GithubScheduleFireId::from_uuid(Uuid::from_u128(value)).expect("fire ID")
}

fn worker_id(value: u128) -> GithubScheduleWorkerId {
    GithubScheduleWorkerId::from_uuid(Uuid::from_u128(value)).expect("worker ID")
}

fn fence(value: u64) -> GithubScheduleClaimFence {
    GithubScheduleClaimFence::new(value).expect("claim fence")
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn workflow_path(value: &str) -> GithubCheckSubjectKey {
    GithubCheckSubjectKey::new(value).expect("workflow path")
}

#[allow(clippy::too_many_arguments)]
fn entry(
    ordinal: u16,
    path: &str,
    source_digest: u8,
    schedule_ordinal: u16,
    cron: &str,
    timezone: &str,
    next_fire_at: i64,
) -> GithubScheduleRegistryEntry {
    GithubScheduleRegistryEntry::new(
        ordinal,
        workflow_path(path),
        digest(source_digest),
        schedule_ordinal,
        cron,
        timezone,
        UnixMillis::new(next_fire_at),
    )
    .expect("schedule registry entry")
}

#[allow(clippy::too_many_arguments)]
fn discovered_entry(
    discovered_at: UnixMillis,
    ordinal: u16,
    path: &str,
    source_digest: u8,
    schedule_ordinal: u16,
    cron: &str,
    timezone: &str,
) -> GithubScheduleRegistryEntry {
    let next_fire_at = CronExpression::parse(cron)
        .expect("valid cron expression")
        .next_after(discovered_at, timezone)
        .expect("next scheduled occurrence")
        .get();
    entry(
        ordinal,
        path,
        source_digest,
        schedule_ordinal,
        cron,
        timezone,
        next_fire_at,
    )
}

fn archive(byte: u8, key: &str, size: u64) -> GithubScheduleArchive {
    GithubScheduleArchive::new(
        digest(byte),
        ObjectKey::new(key).expect("archive key"),
        size,
    )
    .expect("archive")
}

fn discovery_claim(
    registry: u128,
    worker: u128,
    claimed_at: i64,
    expires_at: i64,
) -> GithubScheduleDiscoveryClaim {
    GithubScheduleDiscoveryClaim::from_durable_parts(
        registry_id(registry),
        worker_id(worker),
        fence(1),
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
    )
    .expect("discovery claim")
}

fn fire_claim(
    fire: u128,
    worker: u128,
    attempt: u16,
    claim_fence: u64,
    claimed_at: i64,
    expires_at: i64,
) -> GithubScheduleFireClaim {
    GithubScheduleFireClaim::from_durable_parts(
        fire_id(fire),
        worker_id(worker),
        attempt,
        fence(claim_fence),
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
    )
    .expect("fire claim")
}

fn expected_entry_digest(
    workflow_path: &str,
    source_digest: Sha256Digest,
    schedule_ordinal: u16,
    cron: &str,
    timezone: &str,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.store.github-schedule-entry.v1\0");
    for part in [
        workflow_path.as_bytes(),
        source_digest.as_bytes(),
        schedule_ordinal.to_be_bytes().as_slice(),
        cron.as_bytes(),
        timezone.as_bytes(),
    ] {
        hasher.update(
            u64::try_from(part.len())
                .expect("bounded part")
                .to_be_bytes(),
        );
        hasher.update(part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn expected_inventory_digest(entries: &[GithubScheduleRegistryEntry]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.store.github-schedule-inventory.v1\0");
    hasher.update(
        u64::try_from(entries.len())
            .expect("bounded entry count")
            .to_be_bytes(),
    );
    for entry in entries {
        hasher.update(entry.entry_digest().as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}
