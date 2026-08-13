use automata_ci_core::{
    Architecture, OperatingSystem, RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerId,
    RunnerLabel, RunnerPlatform,
};
use automata_ci_store::{
    MAX_REGISTERED_RUNNERS, RunnerCapabilityAdmissionError,
    RunnerCapabilityAdmissionRepository as _, RunnerCapabilityReadiness,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::{TestResult, run_with_database};

fn capabilities(
    runner_id: RunnerId,
    features: impl IntoIterator<Item = RunnerFeature>,
) -> RunnerCapabilities {
    RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([RunnerLabel::new("linux").expect("label")])
    .with_groups([RunnerGroup::new("g1").expect("group")])
    .with_max_parallel_jobs(2)
    .expect("slots")
    .with_features(features)
}

async fn seed_tenant_and_group(pool: &PgPool, tenant: &str) -> TestResult<Uuid> {
    sqlx::query(
        "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,$2,1,1)",
    )
    .bind(tenant)
    .bind(format!("{tenant} test"))
    .execute(pool)
    .await?;
    let group_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO runner_groups (
            id,tenant_id,name,normalized_name,routing_policy,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'g1','g1','{}'::jsonb,1,1)
        ",
    )
    .bind(group_id)
    .bind(tenant)
    .execute(pool)
    .await?;
    Ok(group_id)
}

async fn insert_runner(
    pool: &PgPool,
    tenant: &str,
    group_id: Uuid,
    index: usize,
    document: &RunnerCapabilities,
) -> TestResult {
    let name = format!("runner-{index}");
    sqlx::query(
        r"
        INSERT INTO runners (
            id,tenant_id,group_id,name,normalized_name,labels,capabilities,slots,
            status,generation,external_identity,desired_state,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,$3,$4,$4,ARRAY['linux'],$5,2,'offline',1,$6,'active',1,1)
        ",
    )
    .bind(document.runner_id().as_uuid())
    .bind(tenant)
    .bind(group_id)
    .bind(name)
    .bind(serde_json::to_value(document)?)
    .bind(format!(
        "automata:runner:{}",
        document.runner_id().as_uuid().hyphenated()
    ))
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary database"]
async fn durable_capabilities_are_canonical_runner_bound_and_oidc_readiness_gated() -> TestResult {
    run_with_database(|database| async move {
        let tenant = "runner-capability-authority";
        let group_id = seed_tenant_and_group(database.pool(), tenant).await?;
        let runner_id = RunnerId::new();
        insert_runner(
            database.pool(),
            tenant,
            group_id,
            0,
            &capabilities(runner_id, [RunnerFeature::SHELL_STEPS]),
        )
        .await?;
        database
            .store()
            .verify_runner_capability_readiness(RunnerCapabilityReadiness::unavailable())
            .await?;

        let oidc = capabilities(
            runner_id,
            [RunnerFeature::SHELL_STEPS, RunnerFeature::OIDC_TOKENS],
        );
        sqlx::query("UPDATE runners SET capabilities=$2 WHERE id=$1")
            .bind(runner_id.as_uuid())
            .bind(serde_json::to_value(oidc)?)
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .verify_runner_capability_readiness(RunnerCapabilityReadiness::unavailable())
                .await,
            Err(RunnerCapabilityAdmissionError::ConfigurationDrift {
                resource: "runner capability admission"
            })
        ));
        database
            .store()
            .verify_runner_capability_readiness(
                RunnerCapabilityReadiness::unavailable().with_github_oidc(),
            )
            .await?;

        let mismatched = capabilities(RunnerId::new(), [RunnerFeature::SHELL_STEPS]);
        sqlx::query("UPDATE runners SET capabilities=$2 WHERE id=$1")
            .bind(runner_id.as_uuid())
            .bind(serde_json::to_value(mismatched)?)
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .verify_runner_capability_readiness(RunnerCapabilityReadiness::unavailable())
                .await,
            Err(RunnerCapabilityAdmissionError::CorruptData)
        ));

        let mut noncanonical =
            serde_json::to_value(capabilities(runner_id, [RunnerFeature::SHELL_STEPS]))?;
        noncanonical["features"] = serde_json::json!([
            RunnerFeature::SHELL_STEPS.as_str(),
            RunnerFeature::SHELL_STEPS.as_str()
        ]);
        sqlx::query("UPDATE runners SET capabilities=$2 WHERE id=$1")
            .bind(runner_id.as_uuid())
            .bind(noncanonical)
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .verify_runner_capability_readiness(RunnerCapabilityReadiness::unavailable())
                .await,
            Err(RunnerCapabilityAdmissionError::CorruptData)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary database"]
async fn durable_runner_inventory_admits_64_and_rejects_65() -> TestResult {
    run_with_database(|database| async move {
        let tenant = "runner-capability-ceiling";
        let group_id = seed_tenant_and_group(database.pool(), tenant).await?;
        for index in 0..MAX_REGISTERED_RUNNERS {
            let runner_id = RunnerId::new();
            insert_runner(
                database.pool(),
                tenant,
                group_id,
                index,
                &capabilities(runner_id, [RunnerFeature::SHELL_STEPS]),
            )
            .await?;
        }
        database
            .store()
            .verify_runner_capability_readiness(RunnerCapabilityReadiness::unavailable())
            .await?;

        let runner_id = RunnerId::new();
        insert_runner(
            database.pool(),
            tenant,
            group_id,
            MAX_REGISTERED_RUNNERS,
            &capabilities(runner_id, [RunnerFeature::SHELL_STEPS]),
        )
        .await?;
        assert!(matches!(
            database
                .store()
                .verify_runner_capability_readiness(RunnerCapabilityReadiness::unavailable())
                .await,
            Err(RunnerCapabilityAdmissionError::ConfigurationDrift {
                resource: "runner capability admission"
            })
        ));
        Ok(())
    })
    .await
}
