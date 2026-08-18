use async_trait::async_trait;
use automata_ci_core::{GitObjectId, OperationId, RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    EVENT_CONTROL_SUBJECT_SCHEMA, EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
    EVENT_SUBJECT_PROGRESS_SCHEMA, EVENT_SUBJECT_SELECTION_SCHEMA, EventControlSubject,
    EventControlSubjectId, EventSubjectId, EventSubjectOrigin, EventSubjectOriginKind,
    EventSubjectOriginRegistry, EventSubjectProgress, EventSubjectProgressReceipt,
    EventSubjectRegistrationReceipt, EventSubjectRepository, EventSubjectSelection,
    EventSubjectStoreError, EventSubjectTerminalOutcome, GithubScheduleFireId, ProviderDeliveryId,
    RegisterEventSubject, RepositoryId, RepositoryOperationError, TenantScope,
};
use sqlx::{AssertSqlSafe, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::PostgresStore;

const SELECTION_COLUMNS: &str = r"
    selection.subject_id AS selection_subject_id,
    selection.tenant_id AS selection_tenant_id,
    selection.repository_id AS selection_repository_id,
    selection.selection_schema,
    selection.origin_registry_version,
    selection.origin_registry_digest,
    selection.origin_kind_code,
    selection.origin_kind_name,
    selection.origin_id,
    selection.event_name AS selection_event_name,
    selection.workflow_path AS selection_workflow_path,
    selection.source_revision AS selection_source_revision,
    selection.source_digest AS selection_source_digest,
    selection.authority_digest AS selection_authority_digest,
    selection.selected_at_ms,
    selection.selection_digest
";

const CONTROL_COLUMNS: &str = r"
    control.control_id,
    control.tenant_id AS control_tenant_id,
    control.subject_id AS control_subject_id,
    control.control_schema,
    control.selection_digest AS control_selection_digest,
    control.registered_at_ms,
    control.control_digest
";

const PROGRESS_COLUMNS: &str = r"
    progress.subject_id AS progress_subject_id,
    progress.tenant_id AS progress_tenant_id,
    progress.progress_schema,
    progress.selection_digest AS progress_selection_digest,
    progress.outcome_kind,
    progress.run_id AS progress_run_id,
    progress.reason AS progress_reason,
    progress.recorded_at_ms,
    progress.progress_digest
";

#[async_trait]
impl EventSubjectRepository for PostgresStore {
    async fn register_event_subject(
        &self,
        request: RegisterEventSubject,
    ) -> Result<EventSubjectRegistrationReceipt, EventSubjectStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let receipt = register_event_subject_in_transaction(&mut transaction, request).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn record_event_subject_progress(
        &self,
        progress: EventSubjectProgress,
    ) -> Result<EventSubjectProgressReceipt, EventSubjectStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let receipt =
            record_event_subject_progress_in_transaction(&mut transaction, progress).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn load_event_subject_selection(
        &self,
        tenant: &TenantScope,
        subject_id: EventSubjectId,
    ) -> Result<EventSubjectSelection, EventSubjectStoreError> {
        let query = format!(
            "SELECT {SELECTION_COLUMNS} FROM event_subject_selections AS selection \
             WHERE selection.tenant_id = $1 AND selection.subject_id = $2"
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(tenant.as_str())
            .bind(subject_id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .ok_or(EventSubjectStoreError::NotFound)?;
        decode_selection(&row)
    }

    async fn load_event_control_subject(
        &self,
        tenant: &TenantScope,
        subject_id: EventSubjectId,
    ) -> Result<EventControlSubject, EventSubjectStoreError> {
        let selection = self
            .load_event_subject_selection(tenant, subject_id)
            .await?;
        let query = format!(
            "SELECT {CONTROL_COLUMNS} FROM event_control_subjects AS control \
             WHERE control.tenant_id = $1 AND control.subject_id = $2"
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(tenant.as_str())
            .bind(subject_id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .ok_or(EventSubjectStoreError::CorruptData)?;
        decode_control(&row, &selection)
    }

    async fn load_event_subject_progress(
        &self,
        tenant: &TenantScope,
        subject_id: EventSubjectId,
    ) -> Result<Option<EventSubjectProgress>, EventSubjectStoreError> {
        let query = format!(
            "SELECT {SELECTION_COLUMNS} FROM event_subject_selections AS selection \
             WHERE selection.tenant_id = $1 AND selection.subject_id = $2"
        );
        let selection_row = sqlx::query(AssertSqlSafe(query))
            .bind(tenant.as_str())
            .bind(subject_id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .ok_or(EventSubjectStoreError::NotFound)?;
        let selection = decode_selection(&selection_row)?;

        let query = format!(
            "SELECT {PROGRESS_COLUMNS} FROM event_subject_progress AS progress \
             WHERE progress.tenant_id = $1 AND progress.subject_id = $2"
        );
        sqlx::query(AssertSqlSafe(query))
            .bind(tenant.as_str())
            .bind(subject_id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .map(|row| decode_progress(&row, &selection))
            .transpose()
    }
}

/// Registers an immutable selection and control root inside the caller's transaction.
pub(super) async fn register_event_subject_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: RegisterEventSubject,
) -> Result<EventSubjectRegistrationReceipt, EventSubjectStoreError> {
    let desired_selection = request.selection().clone();
    let desired_control = request.control().clone();
    let origin = desired_selection.origin();
    let inserted = sqlx::query(
        r"
        INSERT INTO event_subject_selections (
            subject_id, tenant_id, repository_id, selection_schema,
            origin_registry_version, origin_registry_digest,
            origin_kind_code, origin_kind_name, origin_id,
            event_name, workflow_path, source_revision, source_digest,
            authority_digest, selected_at_ms, selection_digest
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15, $16
        )
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(desired_selection.id().as_uuid())
    .bind(desired_selection.tenant().as_str())
    .bind(desired_selection.repository_id().as_uuid())
    .bind(schema_i16(EVENT_SUBJECT_SELECTION_SCHEMA))
    .bind(schema_i16(desired_selection.origin_registry_version()))
    .bind(
        desired_selection
            .origin_registry_digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(origin_code_i16(origin.kind()))
    .bind(origin.kind().as_durable_str())
    .bind(origin.as_uuid())
    .bind(desired_selection.event_name())
    .bind(desired_selection.workflow_path())
    .bind(desired_selection.source_revision().as_bytes())
    .bind(desired_selection.source_digest().as_bytes().as_slice())
    .bind(desired_selection.authority_digest().as_bytes().as_slice())
    .bind(desired_selection.selected_at().get())
    .bind(desired_selection.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(mutation_error)?;

    if inserted.rows_affected() == 1 {
        insert_control(transaction, &desired_control).await?;
        return automata_ci_store::adapter_spi::event_subject_registration_receipt(
            desired_selection,
            desired_control,
            false,
        )
        .map_err(|_| EventSubjectStoreError::CorruptData);
    }

    let query = format!(
        "SELECT {SELECTION_COLUMNS}, {CONTROL_COLUMNS} \
         FROM event_subject_selections AS selection \
         JOIN event_control_subjects AS control \
           ON control.tenant_id = selection.tenant_id \
          AND control.subject_id = selection.subject_id \
          AND control.selection_digest = selection.selection_digest \
         WHERE selection.subject_id = $1 \
         FOR SHARE OF selection, control"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(desired_selection.id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(EventSubjectStoreError::Conflict)?;
    let existing_selection = decode_selection(&row)?;
    let existing_control = decode_control(&row, &existing_selection)?;
    if existing_selection != desired_selection || existing_control != desired_control {
        return Err(EventSubjectStoreError::Conflict);
    }
    automata_ci_store::adapter_spi::event_subject_registration_receipt(
        existing_selection,
        existing_control,
        true,
    )
    .map_err(|_| EventSubjectStoreError::CorruptData)
}

/// Records terminal progress inside the caller's transaction.
pub(super) async fn record_event_subject_progress_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    desired: EventSubjectProgress,
) -> Result<EventSubjectProgressReceipt, EventSubjectStoreError> {
    let selection = load_selection_for_update(transaction, desired.subject_id()).await?;
    if desired.selection_digest() != selection.digest() {
        return Err(EventSubjectStoreError::Conflict);
    }
    let outcome = desired.outcome();
    let inserted = sqlx::query(
        r"
        INSERT INTO event_subject_progress (
            subject_id, tenant_id, progress_schema, selection_digest,
            outcome_kind, run_id, reason, recorded_at_ms, progress_digest
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (subject_id) DO NOTHING
        ",
    )
    .bind(desired.subject_id().as_uuid())
    .bind(selection.tenant().as_str())
    .bind(schema_i16(EVENT_SUBJECT_PROGRESS_SCHEMA))
    .bind(desired.selection_digest().as_bytes().as_slice())
    .bind(outcome.kind().as_durable_str())
    .bind(outcome.run_id().map(RunId::as_uuid))
    .bind(outcome.reason())
    .bind(desired.recorded_at().get())
    .bind(desired.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(mutation_error)?;
    if inserted.rows_affected() == 1 {
        return Ok(automata_ci_store::adapter_spi::event_subject_progress_receipt(desired, false));
    }

    let query = format!(
        "SELECT {PROGRESS_COLUMNS} FROM event_subject_progress AS progress \
         WHERE progress.subject_id = $1 FOR SHARE OF progress"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(desired.subject_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(EventSubjectStoreError::CorruptData)?;
    let existing = decode_progress(&row, &selection)?;
    if existing != desired {
        return Err(EventSubjectStoreError::Conflict);
    }
    Ok(automata_ci_store::adapter_spi::event_subject_progress_receipt(existing, true))
}

/// Loads immutable selection, control, and optional terminal progress under row locks.
pub(super) async fn load_event_subject_state_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: EventSubjectId,
) -> Result<
    Option<(
        EventSubjectSelection,
        EventControlSubject,
        Option<EventSubjectProgress>,
    )>,
    EventSubjectStoreError,
> {
    let selection_query = format!(
        "SELECT {SELECTION_COLUMNS} FROM event_subject_selections AS selection \
         WHERE selection.subject_id = $1 FOR SHARE OF selection"
    );
    let Some(selection_row) = sqlx::query(AssertSqlSafe(selection_query))
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
    else {
        return Ok(None);
    };
    let selection = decode_selection(&selection_row)?;

    let control_query = format!(
        "SELECT {CONTROL_COLUMNS} FROM event_control_subjects AS control \
         WHERE control.subject_id = $1 FOR SHARE OF control"
    );
    let control_row = sqlx::query(AssertSqlSafe(control_query))
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(EventSubjectStoreError::CorruptData)?;
    let control = decode_control(&control_row, &selection)?;

    let progress_query = format!(
        "SELECT {PROGRESS_COLUMNS} FROM event_subject_progress AS progress \
         WHERE progress.subject_id = $1 FOR SHARE OF progress"
    );
    let progress = sqlx::query(AssertSqlSafe(progress_query))
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .map(|row| decode_progress(&row, &selection))
        .transpose()?;
    Ok(Some((selection, control, progress)))
}

async fn insert_control(
    transaction: &mut Transaction<'_, Postgres>,
    control: &EventControlSubject,
) -> Result<(), EventSubjectStoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO event_control_subjects (
            control_id, tenant_id, subject_id, control_schema,
            selection_digest, registered_at_ms, control_digest
        )
        SELECT $1, selection.tenant_id, $2, $3, $4, $5, $6
        FROM event_subject_selections AS selection
        WHERE selection.subject_id = $2
          AND selection.selection_digest = $4
        ",
    )
    .bind(control.id().as_uuid())
    .bind(control.subject_id().as_uuid())
    .bind(schema_i16(EVENT_CONTROL_SUBJECT_SCHEMA))
    .bind(control.selection_digest().as_bytes().as_slice())
    .bind(control.registered_at().get())
    .bind(control.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(mutation_error)?;
    if inserted.rows_affected() != 1 {
        return Err(EventSubjectStoreError::Conflict);
    }
    Ok(())
}

async fn load_selection_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: EventSubjectId,
) -> Result<EventSubjectSelection, EventSubjectStoreError> {
    let query = format!(
        "SELECT {SELECTION_COLUMNS} FROM event_subject_selections AS selection \
         WHERE selection.subject_id = $1 FOR SHARE OF selection"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(EventSubjectStoreError::NotFound)?;
    decode_selection(&row)
}

fn decode_selection(row: &PgRow) -> Result<EventSubjectSelection, EventSubjectStoreError> {
    require_schema(row, "selection_schema", EVENT_SUBJECT_SELECTION_SCHEMA)?;
    require_schema(
        row,
        "origin_registry_version",
        EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
    )?;
    let registry_digest = digest_column(row, "origin_registry_digest")?;
    if registry_digest != EventSubjectOriginRegistry::current().digest() {
        return Err(EventSubjectStoreError::CorruptData);
    }
    let origin_code = u16::try_from(
        row.try_get::<i16, _>("origin_kind_code")
            .map_err(operation_error)?,
    )
    .map_err(|_| EventSubjectStoreError::CorruptData)?;
    let origin_name: String = row.try_get("origin_kind_name").map_err(operation_error)?;
    let origin_kind = EventSubjectOriginKind::from_durable_parts(origin_code, &origin_name)
        .map_err(|_| EventSubjectStoreError::CorruptData)?;
    let origin_id: Uuid = row.try_get("origin_id").map_err(operation_error)?;
    let origin = decode_origin(origin_kind, origin_id)?;
    EventSubjectSelection::from_durable_parts(
        EventSubjectId::from_uuid(
            row.try_get("selection_subject_id")
                .map_err(operation_error)?,
        )
        .map_err(|_| EventSubjectStoreError::CorruptData)?,
        TenantScope::from_authenticated_tenant_id(
            row.try_get::<String, _>("selection_tenant_id")
                .map_err(operation_error)?,
        )
        .map_err(|_| EventSubjectStoreError::CorruptData)?,
        RepositoryId::from_uuid(
            row.try_get("selection_repository_id")
                .map_err(operation_error)?,
        ),
        origin,
        row.try_get::<String, _>("selection_event_name")
            .map_err(operation_error)?,
        row.try_get::<String, _>("selection_workflow_path")
            .map_err(operation_error)?,
        GitObjectId::from_durable_bytes(
            &row.try_get::<Vec<u8>, _>("selection_source_revision")
                .map_err(operation_error)?,
        )
        .map_err(|_| EventSubjectStoreError::CorruptData)?,
        digest_column(row, "selection_source_digest")?,
        digest_column(row, "selection_authority_digest")?,
        UnixMillis::new(row.try_get("selected_at_ms").map_err(operation_error)?),
        digest_column(row, "selection_digest")?,
    )
    .map_err(|_| EventSubjectStoreError::CorruptData)
}

fn decode_control(
    row: &PgRow,
    selection: &EventSubjectSelection,
) -> Result<EventControlSubject, EventSubjectStoreError> {
    require_schema(row, "control_schema", EVENT_CONTROL_SUBJECT_SCHEMA)?;
    let tenant: String = row.try_get("control_tenant_id").map_err(operation_error)?;
    let subject_id: Uuid = row.try_get("control_subject_id").map_err(operation_error)?;
    if tenant != selection.tenant().as_str()
        || subject_id != selection.id().as_uuid()
        || digest_column(row, "control_selection_digest")? != selection.digest()
    {
        return Err(EventSubjectStoreError::CorruptData);
    }
    EventControlSubject::from_durable_parts(
        EventControlSubjectId::from_uuid(row.try_get("control_id").map_err(operation_error)?)
            .map_err(|_| EventSubjectStoreError::CorruptData)?,
        selection,
        UnixMillis::new(row.try_get("registered_at_ms").map_err(operation_error)?),
        digest_column(row, "control_digest")?,
    )
    .map_err(|_| EventSubjectStoreError::CorruptData)
}

fn decode_progress(
    row: &PgRow,
    selection: &EventSubjectSelection,
) -> Result<EventSubjectProgress, EventSubjectStoreError> {
    require_schema(row, "progress_schema", EVENT_SUBJECT_PROGRESS_SCHEMA)?;
    let tenant: String = row.try_get("progress_tenant_id").map_err(operation_error)?;
    let subject_id: Uuid = row
        .try_get("progress_subject_id")
        .map_err(operation_error)?;
    if tenant != selection.tenant().as_str()
        || subject_id != selection.id().as_uuid()
        || digest_column(row, "progress_selection_digest")? != selection.digest()
    {
        return Err(EventSubjectStoreError::CorruptData);
    }
    let kind: String = row.try_get("outcome_kind").map_err(operation_error)?;
    let run_id: Option<Uuid> = row.try_get("progress_run_id").map_err(operation_error)?;
    let reason: Option<String> = row.try_get("progress_reason").map_err(operation_error)?;
    let outcome = match (kind.as_str(), run_id, reason) {
        ("admitted", Some(run_id), None) => {
            EventSubjectTerminalOutcome::admitted(RunId::from_uuid(run_id))
        }
        ("skipped", None, Some(reason)) => EventSubjectTerminalOutcome::skipped(reason),
        ("failed", None, Some(reason)) => EventSubjectTerminalOutcome::failed(reason),
        _ => return Err(EventSubjectStoreError::CorruptData),
    }
    .map_err(|_| EventSubjectStoreError::CorruptData)?;
    EventSubjectProgress::from_durable_parts(
        selection,
        outcome,
        UnixMillis::new(row.try_get("recorded_at_ms").map_err(operation_error)?),
        digest_column(row, "progress_digest")?,
    )
    .map_err(|_| EventSubjectStoreError::CorruptData)
}

fn decode_origin(
    kind: EventSubjectOriginKind,
    id: Uuid,
) -> Result<EventSubjectOrigin, EventSubjectStoreError> {
    match kind {
        EventSubjectOriginKind::ProviderDelivery => ProviderDeliveryId::from_uuid(id)
            .map(EventSubjectOrigin::ProviderDelivery)
            .map_err(|_| EventSubjectStoreError::CorruptData),
        EventSubjectOriginKind::ScheduleFire => GithubScheduleFireId::from_uuid(id)
            .map(EventSubjectOrigin::ScheduleFire)
            .map_err(|_| EventSubjectStoreError::CorruptData),
        EventSubjectOriginKind::ManualOperation => Ok(EventSubjectOrigin::ManualOperation(
            OperationId::from_uuid(id),
        )),
        EventSubjectOriginKind::WorkflowRun => {
            Ok(EventSubjectOrigin::WorkflowRun(RunId::from_uuid(id)))
        }
    }
}

fn require_schema(row: &PgRow, column: &str, expected: u16) -> Result<(), EventSubjectStoreError> {
    let actual: i16 = row.try_get(column).map_err(operation_error)?;
    if actual != schema_i16(expected) {
        return Err(EventSubjectStoreError::CorruptData);
    }
    Ok(())
}

fn digest_column(row: &PgRow, column: &str) -> Result<Sha256Digest, EventSubjectStoreError> {
    let bytes: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EventSubjectStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn schema_i16(value: u16) -> i16 {
    i16::try_from(value).expect("current event-subject schemas fit PostgreSQL SMALLINT")
}

fn origin_code_i16(kind: EventSubjectOriginKind) -> i16 {
    schema_i16(kind.durable_code())
}

fn mutation_error(error: sqlx::Error) -> EventSubjectStoreError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code.starts_with("23"))
    {
        EventSubjectStoreError::Conflict
    } else {
        operation_error(error)
    }
}

fn operation_error(error: sqlx::Error) -> EventSubjectStoreError {
    EventSubjectStoreError::Operation(RepositoryOperationError::from_source(error))
}
