use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

#[derive(Debug)]
pub(super) enum GithubCheckAggregationError {
    Operation(sqlx::Error),
    CorruptData,
}

impl From<sqlx::Error> for GithubCheckAggregationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Operation(error)
    }
}

/// Serializes child finalization through its delivery-wide all-direct Check.
pub(super) async fn lock_all_direct_check_for_run(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: Uuid,
) -> Result<Option<Uuid>, GithubCheckAggregationError> {
    let delivery_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT child.provider_delivery_id
        FROM github_check_subjects AS child
        JOIN github_provider_delivery_evidence AS evidence
          ON evidence.provider_delivery_id = child.provider_delivery_id
         AND evidence.tenant_id = child.tenant_id
         AND evidence.repository_id = child.repository_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        JOIN github_check_subjects AS aggregate
          ON aggregate.id = evidence.github_check_subject_id
         AND aggregate.provider_delivery_id = evidence.provider_delivery_id
         AND aggregate.tenant_id = evidence.tenant_id
        WHERE child.workflow_run_id = $1
          AND child.subject_kind = 'workflow'
          AND manifest.workflow_selection_kind = 'all_direct'
        FOR UPDATE OF aggregate
        ",
    )
    .bind(run_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(delivery_id)
}

/// Reconciles one delivery-wide Check from admission and terminal child state.
#[allow(clippy::too_many_lines)] // One locked reconciliation owns the aggregate transition.
pub(super) async fn reconcile_all_direct_check(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: Uuid,
    updated_at_ms: i64,
) -> Result<(), GithubCheckAggregationError> {
    let aggregate = sqlx::query(
        r"
        SELECT aggregate.id, aggregate.desired_state,
               aggregate.desired_conclusion, aggregate.terminal_cause,
               aggregate.desired_revision, aggregate.desired_updated_at_ms
        FROM github_provider_delivery_evidence AS evidence
        JOIN provider_delivery_inbox AS inbox
          ON inbox.id = evidence.provider_delivery_id
         AND inbox.tenant_id = evidence.tenant_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        JOIN github_check_subjects AS aggregate
          ON aggregate.id = evidence.github_check_subject_id
         AND aggregate.provider_delivery_id = evidence.provider_delivery_id
         AND aggregate.tenant_id = evidence.tenant_id
        WHERE evidence.provider_delivery_id = $1
          AND inbox.state = 'completed'
          AND manifest.workflow_selection_kind = 'all_direct'
        FOR UPDATE OF aggregate
        ",
    )
    .bind(delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(aggregate) = aggregate else {
        return Ok(());
    };

    let row = sqlx::query(
        r"
        SELECT count(*) FILTER (
                   WHERE outcome.outcome_kind = 'failed'
               ) AS failed_count,
               count(*) FILTER (
                   WHERE outcome.outcome_kind = 'admitted'
               ) AS admitted_count,
               count(child.id) FILTER (
                   WHERE outcome.outcome_kind = 'admitted'
               ) AS child_count,
               count(*) FILTER (
                   WHERE outcome.outcome_kind = 'admitted'
                     AND child.desired_state = 'completed'
               ) AS terminal_count,
               count(*) FILTER (
                   WHERE child.desired_conclusion = 'failure'
               ) AS failure_count,
               count(*) FILTER (
                   WHERE child.desired_conclusion = 'timed_out'
               ) AS timed_out_count,
               count(*) FILTER (
                   WHERE child.desired_conclusion = 'cancelled'
               ) AS cancelled_count,
               count(*) FILTER (
                   WHERE child.desired_conclusion = 'action_required'
               ) AS action_required_count,
               count(*) FILTER (
                   WHERE child.desired_conclusion = 'success'
               ) AS success_count,
               count(*) FILTER (
                   WHERE child.desired_conclusion = 'skipped'
               ) AS skipped_count
        FROM provider_delivery_workflow_outcomes AS outcome
        LEFT JOIN github_check_subjects AS child
          ON child.provider_delivery_id = outcome.inbox_id
         AND child.tenant_id = outcome.tenant_id
         AND child.workflow_run_id = outcome.run_id
         AND child.subject_kind = 'workflow'
        WHERE outcome.inbox_id = $1
        ",
    )
    .bind(delivery_id)
    .fetch_one(&mut **transaction)
    .await?;

    let desired = desired_aggregate(AggregateCounts {
        failed: row.try_get("failed_count")?,
        admitted: row.try_get("admitted_count")?,
        children: row.try_get("child_count")?,
        terminal: row.try_get("terminal_count")?,
        failure: row.try_get("failure_count")?,
        timed_out: row.try_get("timed_out_count")?,
        cancelled: row.try_get("cancelled_count")?,
        action_required: row.try_get("action_required_count")?,
        success: row.try_get("success_count")?,
        skipped: row.try_get("skipped_count")?,
    })?;

    let subject_id: Uuid = aggregate.try_get("id")?;
    let state: String = aggregate.try_get("desired_state")?;
    let conclusion: Option<String> = aggregate.try_get("desired_conclusion")?;
    let cause: Option<String> = aggregate.try_get("terminal_cause")?;
    let revision: i64 = aggregate.try_get("desired_revision")?;
    let prior_updated_at: i64 = aggregate.try_get("desired_updated_at_ms")?;

    match desired {
        DesiredAggregate::InProgress => {
            if state == "in_progress" && conclusion.is_none() && cause.is_none() && revision == 2 {
                return Ok(());
            }
            if updated_at_ms < prior_updated_at {
                return Err(GithubCheckAggregationError::CorruptData);
            }
            if state != "queued" || conclusion.is_some() || cause.is_some() || revision != 1 {
                return Err(GithubCheckAggregationError::CorruptData);
            }
            update_aggregate(
                transaction,
                subject_id,
                "in_progress",
                None,
                None,
                revision,
                updated_at_ms,
            )
            .await
        }
        DesiredAggregate::Terminal(expected_conclusion, expected_cause) => {
            if state == "completed"
                && conclusion.as_deref() == Some(expected_conclusion)
                && cause.as_deref() == Some(expected_cause)
                && matches!(revision, 2 | 3)
            {
                return Ok(());
            }
            if updated_at_ms < prior_updated_at {
                return Err(GithubCheckAggregationError::CorruptData);
            }
            if !matches!(
                (state.as_str(), revision),
                ("queued", 1) | ("in_progress", 2)
            ) || conclusion.is_some()
                || cause.is_some()
            {
                return Err(GithubCheckAggregationError::CorruptData);
            }
            update_aggregate(
                transaction,
                subject_id,
                "completed",
                Some(expected_conclusion),
                Some(expected_cause),
                revision,
                updated_at_ms,
            )
            .await
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesiredAggregate {
    InProgress,
    Terminal(&'static str, &'static str),
}

#[derive(Clone, Copy, Debug, Default)]
struct AggregateCounts {
    failed: i64,
    admitted: i64,
    children: i64,
    terminal: i64,
    failure: i64,
    timed_out: i64,
    cancelled: i64,
    action_required: i64,
    success: i64,
    skipped: i64,
}

fn desired_aggregate(
    counts: AggregateCounts,
) -> Result<DesiredAggregate, GithubCheckAggregationError> {
    let classified_terminal = counts.failure
        + counts.timed_out
        + counts.cancelled
        + counts.action_required
        + counts.success
        + counts.skipped;
    if counts.admitted != counts.children
        || counts.terminal > counts.admitted
        || (counts.terminal == counts.admitted && classified_terminal != counts.terminal)
    {
        return Err(GithubCheckAggregationError::CorruptData);
    }
    Ok(if counts.failed > 0 {
        DesiredAggregate::Terminal("failure", "workflow_failure")
    } else if counts.admitted == 0 {
        DesiredAggregate::Terminal("skipped", "workflow_skipped")
    } else if counts.terminal < counts.admitted {
        DesiredAggregate::InProgress
    } else if counts.failure > 0 {
        DesiredAggregate::Terminal("failure", "workflow_failure")
    } else if counts.timed_out > 0 {
        DesiredAggregate::Terminal("timed_out", "workflow_timed_out")
    } else if counts.cancelled > 0 {
        DesiredAggregate::Terminal("cancelled", "workflow_cancelled")
    } else if counts.action_required > 0 {
        DesiredAggregate::Terminal("action_required", "provider_unknown")
    } else if counts.success > 0 {
        DesiredAggregate::Terminal("success", "workflow_success")
    } else {
        DesiredAggregate::Terminal("skipped", "workflow_skipped")
    })
}

async fn update_aggregate(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: Uuid,
    state: &'static str,
    conclusion: Option<&'static str>,
    cause: Option<&'static str>,
    prior_revision: i64,
    updated_at_ms: i64,
) -> Result<(), GithubCheckAggregationError> {
    let updated = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE github_check_subjects
        SET desired_state = $2, desired_conclusion = $3,
            terminal_cause = $4, desired_revision = desired_revision + 1,
            desired_updated_at_ms = $6
        WHERE id = $1
          AND desired_revision = $5
          AND desired_updated_at_ms <= $6
        RETURNING id
        ",
    )
    .bind(subject_id)
    .bind(state)
    .bind(conclusion)
    .bind(cause)
    .bind(prior_revision)
    .bind(updated_at_ms)
    .fetch_optional(&mut **transaction)
    .await?;
    if updated == Some(subject_id) {
        Ok(())
    } else {
        Err(GithubCheckAggregationError::CorruptData)
    }
}

#[cfg(test)]
mod tests {
    use super::{AggregateCounts, DesiredAggregate, desired_aggregate};

    #[test]
    fn admitted_workflows_cannot_complete_the_required_check_before_results() {
        assert_eq!(
            desired_aggregate(AggregateCounts {
                admitted: 2,
                children: 2,
                terminal: 1,
                success: 1,
                ..AggregateCounts::default()
            })
            .expect("consistent aggregate"),
            DesiredAggregate::InProgress
        );
        assert_eq!(
            desired_aggregate(AggregateCounts {
                admitted: 2,
                children: 2,
                terminal: 2,
                success: 2,
                ..AggregateCounts::default()
            })
            .expect("consistent aggregate"),
            DesiredAggregate::Terminal("success", "workflow_success")
        );
    }

    #[test]
    fn aggregate_propagates_pre_admission_and_terminal_failures() {
        assert_eq!(
            desired_aggregate(AggregateCounts {
                failed: 1,
                ..AggregateCounts::default()
            })
            .expect("consistent aggregate"),
            DesiredAggregate::Terminal("failure", "workflow_failure")
        );
        assert_eq!(
            desired_aggregate(AggregateCounts {
                admitted: 1,
                children: 1,
                terminal: 1,
                failure: 1,
                ..AggregateCounts::default()
            })
            .expect("consistent aggregate"),
            DesiredAggregate::Terminal("failure", "workflow_failure")
        );
    }
}
