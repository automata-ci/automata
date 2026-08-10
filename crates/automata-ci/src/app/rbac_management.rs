//! Bounded native-form contract for browser RBAC management.

use std::fmt;

use automata_ci_auth::{
    authorization::{Permission, RepositoryResourceId, RoleName, RunnerGroupResourceId},
    management::{ManagedPrincipalId, ManagementRevision, MemberStatus, RoleBindingId, RoleId},
    secret::SecretString,
    time::UnixTimestamp,
};
use time::{Date, Month, PrimitiveDateTime, Time};

/// Maximum encoded bytes accepted from one RBAC browser form.
pub(crate) const MAX_RBAC_MANAGEMENT_FORM_BYTES: usize = 8 * 1_024;
const MAX_FORM_FIELDS: usize = 7;
const MAX_DISPLAY_NAME_BYTES: usize = 255;
const MAX_REASON_BYTES: usize = 1_024;

/// Resource selector admitted by the direct-binding form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RbacGrantScope {
    Tenant,
    Repository(RepositoryResourceId),
    RunnerGroup(RunnerGroupResourceId),
}

/// Exact non-secret business fields retained after independent CSRF verification.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum VerifiedRbacManagementForm {
    ChangeMemberStatus {
        principal_id: ManagedPrincipalId,
        expected_authorization_revision: ManagementRevision,
        expected_revision: ManagementRevision,
        status: MemberStatus,
        reason: Option<String>,
    },
    CreateRole {
        expected_authorization_revision: ManagementRevision,
        name: RoleName,
        display_name: String,
    },
    UpdateRole {
        role_id: RoleId,
        expected_authorization_revision: ManagementRevision,
        expected_revision: ManagementRevision,
        display_name: String,
    },
    DeleteRole {
        role_id: RoleId,
        expected_authorization_revision: ManagementRevision,
        expected_revision: ManagementRevision,
    },
    SetRolePermission {
        role_id: RoleId,
        permission: Permission,
        expected_authorization_revision: ManagementRevision,
        expected_revision: ManagementRevision,
        present: bool,
    },
    GrantRole {
        expected_authorization_revision: ManagementRevision,
        principal_id: ManagedPrincipalId,
        role_id: RoleId,
        scope: RbacGrantScope,
        valid_until: Option<UnixTimestamp>,
    },
    RevokeRole {
        binding_id: RoleBindingId,
        expected_authorization_revision: ManagementRevision,
        expected_revision: ManagementRevision,
        reason: String,
    },
}

impl VerifiedRbacManagementForm {
    pub(crate) const fn expected_authorization_revision(&self) -> ManagementRevision {
        match self {
            Self::ChangeMemberStatus {
                expected_authorization_revision,
                ..
            }
            | Self::CreateRole {
                expected_authorization_revision,
                ..
            }
            | Self::UpdateRole {
                expected_authorization_revision,
                ..
            }
            | Self::DeleteRole {
                expected_authorization_revision,
                ..
            }
            | Self::SetRolePermission {
                expected_authorization_revision,
                ..
            }
            | Self::GrantRole {
                expected_authorization_revision,
                ..
            }
            | Self::RevokeRole {
                expected_authorization_revision,
                ..
            } => *expected_authorization_revision,
        }
    }

    pub(crate) fn canonical_path(&self) -> String {
        match self {
            Self::ChangeMemberStatus { principal_id, .. } => {
                format!("/settings/access/users/{principal_id}/status")
            }
            Self::CreateRole { .. } => "/settings/access/roles".to_owned(),
            Self::UpdateRole { role_id, .. } => format!("/settings/access/roles/{role_id}"),
            Self::DeleteRole { role_id, .. } => {
                format!("/settings/access/roles/{role_id}/delete")
            }
            Self::SetRolePermission {
                role_id,
                permission,
                ..
            } => format!(
                "/settings/access/roles/{role_id}/permissions/{}",
                permission.as_str()
            ),
            Self::GrantRole { .. } => "/settings/access/direct-bindings".to_owned(),
            Self::RevokeRole { binding_id, .. } => {
                format!("/settings/access/direct-bindings/{binding_id}/revoke")
            }
        }
    }
}

impl fmt::Debug for VerifiedRbacManagementForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ChangeMemberStatus { .. } => "ChangeMemberStatus",
            Self::CreateRole { .. } => "CreateRole",
            Self::UpdateRole { .. } => "UpdateRole",
            Self::DeleteRole { .. } => "DeleteRole",
            Self::SetRolePermission { .. } => "SetRolePermission",
            Self::GrantRole { .. } => "GrantRole",
            Self::RevokeRole { .. } => "RevokeRole",
        })
    }
}

/// Business-field result injected only after the CSRF envelope passed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RbacManagementFormSubmission {
    Valid(VerifiedRbacManagementForm),
    Invalid,
}

/// Sanitized parser failure with no submitted field value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RbacManagementFormError;

/// Successful mutation identity used to select a closed PRG destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RbacMutationApplied {
    MemberStatus { principal_id: ManagedPrincipalId },
    RoleCreated { role_id: RoleId },
    RoleUpdated { role_id: RoleId },
    RoleDeleted,
    RolePermission { role_id: RoleId },
    BindingGranted { binding_id: RoleBindingId },
    BindingRevoked,
}

/// Closed result returned by the browser mutation adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RbacWebMutationOutcome {
    Applied(RbacMutationApplied),
    Forbidden,
    SessionStale,
    NotFound,
    Conflict,
}

/// Reports whether this exact method/path is one of the native RBAC forms.
pub(crate) fn is_rbac_management_form(method: &axum::http::Method, path: &str) -> bool {
    if method != axum::http::Method::POST {
        return false;
    }
    let segments = path
        .strip_prefix('/')
        .map(|path| path.split('/').collect::<Vec<_>>());
    matches!(segments.as_deref(),
        Some(["settings", "access", "users", principal_id, "status"])
            if !principal_id.is_empty()
    ) || matches!(segments.as_deref(), Some(["settings", "access", "roles"]))
        || matches!(segments.as_deref(),
            Some(["settings", "access", "roles", role_id]) if !role_id.is_empty()
        )
        || matches!(segments.as_deref(),
            Some(["settings", "access", "roles", role_id, "delete"])
                if !role_id.is_empty()
        )
        || matches!(segments.as_deref(),
            Some(["settings", "access", "roles", role_id, "permissions", permission])
                if !role_id.is_empty() && !permission.is_empty()
        )
        || matches!(
            segments.as_deref(),
            Some(["settings", "access", "direct-bindings"])
        )
        || matches!(segments.as_deref(),
            Some(["settings", "access", "direct-bindings", binding_id, "revoke"])
                if !binding_id.is_empty()
        )
}

/// Extracts only the CSRF envelope, independently of business-field validity.
pub(crate) fn rbac_management_csrf_token(
    body: &[u8],
) -> Result<SecretString, RbacManagementFormError> {
    validate_body_size(body)?;
    let mut csrf_token = None;
    for pair in body.split(|byte| *byte == b'&') {
        let Some(separator) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if &pair[..separator] != b"csrf_token" {
            continue;
        }
        let value = decode_form_component(&pair[separator + 1..])?;
        set_once(
            &mut csrf_token,
            SecretString::new(value).map_err(|_| RbacManagementFormError)?,
        )?;
    }
    csrf_token.ok_or(RbacManagementFormError)
}

/// Parses the exact current business form after CSRF and request authentication.
///
/// Expiring grants are anchored to the same observation used to authenticate
/// the request, so parsing never acquires a second, drifting wall-clock value.
pub(crate) fn parse_rbac_management_form(
    path: &str,
    body: &[u8],
    request_now: UnixTimestamp,
) -> Result<VerifiedRbacManagementForm, RbacManagementFormError> {
    let mut fields = parse_fields(body)?;
    let _csrf_token = fields.csrf_token.take().ok_or(RbacManagementFormError)?;
    let expected_authorization_revision =
        parse_revision(fields.expected_authorization_revision.take())?;
    let segments = path
        .strip_prefix('/')
        .ok_or(RbacManagementFormError)?
        .split('/')
        .collect::<Vec<_>>();
    let form = parse_path_form(
        segments.as_slice(),
        expected_authorization_revision,
        &mut fields,
        request_now,
    )?;
    if fields.has_business_field() {
        return Err(RbacManagementFormError);
    }
    Ok(form)
}

fn parse_fields(body: &[u8]) -> Result<Fields, RbacManagementFormError> {
    validate_body_size(body)?;
    let mut fields = Fields::default();
    let mut count = 0_usize;
    for pair in body.split(|byte| *byte == b'&') {
        if pair.is_empty() {
            return Err(RbacManagementFormError);
        }
        count = count.checked_add(1).ok_or(RbacManagementFormError)?;
        if count > MAX_FORM_FIELDS {
            return Err(RbacManagementFormError);
        }
        let separator = pair
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(RbacManagementFormError)?;
        let name = decode_form_component(&pair[..separator])?;
        let value = decode_form_component(&pair[separator + 1..])?;
        fields.insert(&name, value)?;
    }
    Ok(fields)
}

fn parse_path_form(
    segments: &[&str],
    expected_authorization_revision: ManagementRevision,
    fields: &mut Fields,
    request_now: UnixTimestamp,
) -> Result<VerifiedRbacManagementForm, RbacManagementFormError> {
    match segments {
        ["settings", "access", "users", principal_id, "status"] => {
            let principal_id =
                ManagedPrincipalId::new(principal_id).map_err(|_| RbacManagementFormError)?;
            let expected_revision = parse_advancing_revision(fields.expected_revision.take())?;
            let operation = required(fields.operation.take())?;
            let (status, reason) = match operation.as_str() {
                "disable" => (
                    MemberStatus::Suspended,
                    Some(bounded_text(fields.reason.take(), MAX_REASON_BYTES)?),
                ),
                "enable" if fields.reason.is_none() => (MemberStatus::Active, None),
                _ => return Err(RbacManagementFormError),
            };
            Ok(VerifiedRbacManagementForm::ChangeMemberStatus {
                principal_id,
                expected_authorization_revision,
                expected_revision,
                status,
                reason,
            })
        }
        ["settings", "access", "roles"] => Ok(VerifiedRbacManagementForm::CreateRole {
            expected_authorization_revision,
            name: RoleName::new(required(fields.name.take())?)
                .map_err(|_| RbacManagementFormError)?,
            display_name: bounded_text(fields.display_name.take(), MAX_DISPLAY_NAME_BYTES)?,
        }),
        ["settings", "access", "roles", role_id] => Ok(VerifiedRbacManagementForm::UpdateRole {
            role_id: RoleId::new(role_id).map_err(|_| RbacManagementFormError)?,
            expected_authorization_revision,
            expected_revision: parse_advancing_revision(fields.expected_revision.take())?,
            display_name: bounded_text(fields.display_name.take(), MAX_DISPLAY_NAME_BYTES)?,
        }),
        ["settings", "access", "roles", role_id, "delete"] => {
            Ok(VerifiedRbacManagementForm::DeleteRole {
                role_id: RoleId::new(role_id).map_err(|_| RbacManagementFormError)?,
                expected_authorization_revision,
                expected_revision: parse_revision(fields.expected_revision.take())?,
            })
        }
        [
            "settings",
            "access",
            "roles",
            role_id,
            "permissions",
            permission,
        ] => {
            let operation = required(fields.operation.take())?;
            let present = match operation.as_str() {
                "add" => true,
                "remove" => false,
                _ => return Err(RbacManagementFormError),
            };
            Ok(VerifiedRbacManagementForm::SetRolePermission {
                role_id: RoleId::new(role_id).map_err(|_| RbacManagementFormError)?,
                permission: Permission::new(*permission).map_err(|_| RbacManagementFormError)?,
                expected_authorization_revision,
                expected_revision: parse_advancing_revision(fields.expected_revision.take())?,
                present,
            })
        }
        ["settings", "access", "direct-bindings"] => Ok(VerifiedRbacManagementForm::GrantRole {
            expected_authorization_revision,
            principal_id: ManagedPrincipalId::new(required(fields.principal_id.take())?)
                .map_err(|_| RbacManagementFormError)?,
            role_id: RoleId::new(required(fields.role_id.take())?)
                .map_err(|_| RbacManagementFormError)?,
            scope: parse_scope(&required(fields.scope.take())?)?,
            valid_until: parse_optional_utc_minute(fields.valid_until.take(), request_now)?,
        }),
        [
            "settings",
            "access",
            "direct-bindings",
            binding_id,
            "revoke",
        ] => Ok(VerifiedRbacManagementForm::RevokeRole {
            binding_id: RoleBindingId::new(binding_id).map_err(|_| RbacManagementFormError)?,
            expected_authorization_revision,
            expected_revision: parse_advancing_revision(fields.expected_revision.take())?,
            reason: bounded_text(fields.reason.take(), MAX_REASON_BYTES)?,
        }),
        _ => Err(RbacManagementFormError),
    }
}

#[derive(Default)]
struct Fields {
    csrf_token: Option<SecretString>,
    expected_authorization_revision: Option<String>,
    expected_revision: Option<String>,
    operation: Option<String>,
    reason: Option<String>,
    name: Option<String>,
    display_name: Option<String>,
    principal_id: Option<String>,
    role_id: Option<String>,
    scope: Option<String>,
    valid_until: Option<String>,
}

impl Fields {
    fn insert(&mut self, name: &str, value: String) -> Result<(), RbacManagementFormError> {
        match name {
            "csrf_token" => set_once(
                &mut self.csrf_token,
                SecretString::new(value).map_err(|_| RbacManagementFormError)?,
            ),
            "expected_authorization_revision" => {
                set_once(&mut self.expected_authorization_revision, value)
            }
            "expected_revision" => set_once(&mut self.expected_revision, value),
            "operation" => set_once(&mut self.operation, value),
            "reason" => set_once(&mut self.reason, value),
            "name" => set_once(&mut self.name, value),
            "display_name" => set_once(&mut self.display_name, value),
            "principal_id" => set_once(&mut self.principal_id, value),
            "role_id" => set_once(&mut self.role_id, value),
            "scope" => set_once(&mut self.scope, value),
            "valid_until" => set_once(&mut self.valid_until, value),
            _ => Err(RbacManagementFormError),
        }
    }

    fn has_business_field(&self) -> bool {
        self.expected_revision.is_some()
            || self.operation.is_some()
            || self.reason.is_some()
            || self.name.is_some()
            || self.display_name.is_some()
            || self.principal_id.is_some()
            || self.role_id.is_some()
            || self.scope.is_some()
            || self.valid_until.is_some()
    }
}

fn validate_body_size(body: &[u8]) -> Result<(), RbacManagementFormError> {
    if body.is_empty() || body.len() > MAX_RBAC_MANAGEMENT_FORM_BYTES {
        return Err(RbacManagementFormError);
    }
    Ok(())
}

fn required(value: Option<String>) -> Result<String, RbacManagementFormError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or(RbacManagementFormError)
}

fn bounded_text(
    value: Option<String>,
    maximum_bytes: usize,
) -> Result<String, RbacManagementFormError> {
    required(value).and_then(|value| {
        if is_safe_form_text(&value, maximum_bytes) {
            Ok(value)
        } else {
            Err(RbacManagementFormError)
        }
    })
}

fn is_safe_form_text(value: &str, maximum_bytes: usize) -> bool {
    value.len() <= maximum_bytes
        && value
            .chars()
            .any(|character| !character.is_whitespace() && !is_default_ignorable(character))
        && !value.chars().any(is_forbidden_display_character)
}

const fn is_default_ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

const fn is_forbidden_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn parse_revision(value: Option<String>) -> Result<ManagementRevision, RbacManagementFormError> {
    let value = required(value)?;
    if (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RbacManagementFormError);
    }
    value
        .parse::<u64>()
        .ok()
        .and_then(|value| ManagementRevision::new(value).ok())
        .ok_or(RbacManagementFormError)
}

fn parse_advancing_revision(
    value: Option<String>,
) -> Result<ManagementRevision, RbacManagementFormError> {
    let revision = parse_revision(value)?;
    if revision.value() == i64::MAX as u64 {
        return Err(RbacManagementFormError);
    }
    Ok(revision)
}

fn parse_optional_utc_minute(
    value: Option<String>,
    request_now: UnixTimestamp,
) -> Result<Option<UnixTimestamp>, RbacManagementFormError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = value.as_bytes();
    if bytes.len() != 16
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7 | 10 | 13) && !byte.is_ascii_digit())
    {
        return Err(RbacManagementFormError);
    }
    let year = parse_ascii_number(&bytes[0..4])?;
    let month = parse_ascii_number(&bytes[5..7])?;
    let day = parse_ascii_number(&bytes[8..10])?;
    let hour = parse_ascii_number(&bytes[11..13])?;
    let minute = parse_ascii_number(&bytes[14..16])?;
    let month = Month::try_from(u8::try_from(month).map_err(|_| RbacManagementFormError)?)
        .map_err(|_| RbacManagementFormError)?;
    let date = Date::from_calendar_date(
        year,
        month,
        u8::try_from(day).map_err(|_| RbacManagementFormError)?,
    )
    .map_err(|_| RbacManagementFormError)?;
    let time = Time::from_hms(
        u8::try_from(hour).map_err(|_| RbacManagementFormError)?,
        u8::try_from(minute).map_err(|_| RbacManagementFormError)?,
        0,
    )
    .map_err(|_| RbacManagementFormError)?;
    let seconds = PrimitiveDateTime::new(date, time)
        .assume_utc()
        .unix_timestamp();
    let seconds = u64::try_from(seconds).map_err(|_| RbacManagementFormError)?;
    let valid_until = UnixTimestamp::from_seconds(seconds);
    if valid_until <= request_now {
        return Err(RbacManagementFormError);
    }
    Ok(Some(valid_until))
}

fn parse_ascii_number(bytes: &[u8]) -> Result<i32, RbacManagementFormError> {
    bytes.iter().try_fold(0_i32, |value, byte| {
        let digit = byte
            .checked_sub(b'0')
            .filter(|digit| *digit <= 9)
            .ok_or(RbacManagementFormError)?;
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(i32::from(digit)))
            .ok_or(RbacManagementFormError)
    })
}

fn parse_scope(value: &str) -> Result<RbacGrantScope, RbacManagementFormError> {
    if value == "tenant" {
        return Ok(RbacGrantScope::Tenant);
    }
    if let Some(id) = value.strip_prefix("repository:") {
        return RepositoryResourceId::new(id)
            .map(RbacGrantScope::Repository)
            .map_err(|_| RbacManagementFormError);
    }
    if let Some(id) = value.strip_prefix("runner-group:") {
        return RunnerGroupResourceId::new(id)
            .map(RbacGrantScope::RunnerGroup)
            .map_err(|_| RbacManagementFormError);
    }
    Err(RbacManagementFormError)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), RbacManagementFormError> {
    if slot.replace(value).is_some() {
        return Err(RbacManagementFormError);
    }
    Ok(())
}

fn decode_form_component(value: &[u8]) -> Result<String, RbacManagementFormError> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0_usize;
    while index < value.len() {
        match value[index] {
            b'%' if index + 2 < value.len() => {
                let high = hex(value[index + 1]).ok_or(RbacManagementFormError)?;
                let low = hex(value[index + 2]).ok_or(RbacManagementFormError)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return Err(RbacManagementFormError),
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| RbacManagementFormError)
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSRF: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const USER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const ROLE: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const BINDING: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const REQUEST_NOW: UnixTimestamp = UnixTimestamp::from_seconds(1_704_067_200);

    fn parse_form(
        path: &str,
        body: &[u8],
    ) -> Result<VerifiedRbacManagementForm, RbacManagementFormError> {
        parse_rbac_management_form(path, body, REQUEST_NOW)
    }

    #[test]
    fn exact_post_paths_are_classified_without_aliases() {
        for path in [
            format!("/settings/access/users/{USER}/status"),
            "/settings/access/roles".to_owned(),
            format!("/settings/access/roles/{ROLE}"),
            format!("/settings/access/roles/{ROLE}/delete"),
            format!("/settings/access/roles/{ROLE}/permissions/runs:read"),
            "/settings/access/direct-bindings".to_owned(),
            format!("/settings/access/direct-bindings/{BINDING}/revoke"),
        ] {
            assert!(is_rbac_management_form(&axum::http::Method::POST, &path));
            assert!(!is_rbac_management_form(&axum::http::Method::GET, &path));
        }
        for path in [
            "/settings/access/users",
            "/settings/access/roles/",
            "/settings/access/direct-bindings/x",
            "/settings/access/direct-bindings/x/delete",
        ] {
            assert!(!is_rbac_management_form(&axum::http::Method::POST, path));
        }
    }

    #[test]
    fn every_current_mutation_parses_to_its_exact_canonical_post_path() {
        let cases = [
            (
                format!("/settings/access/users/{USER}/status"),
                format!(
                    "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation=disable&reason=review"
                ),
                "ChangeMemberStatus",
            ),
            (
                "/settings/access/roles".to_owned(),
                format!(
                    "csrf_token={CSRF}&expected_authorization_revision=7&name=reviewer&display_name=Release+reviewer"
                ),
                "CreateRole",
            ),
            (
                format!("/settings/access/roles/{ROLE}"),
                format!(
                    "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&display_name=Release+reviewer"
                ),
                "UpdateRole",
            ),
            (
                format!("/settings/access/roles/{ROLE}/delete"),
                format!("csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9"),
                "DeleteRole",
            ),
            (
                format!("/settings/access/roles/{ROLE}/permissions/runs:read"),
                format!(
                    "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation=add"
                ),
                "SetRolePermission",
            ),
            (
                "/settings/access/direct-bindings".to_owned(),
                format!(
                    "csrf_token={CSRF}&expected_authorization_revision=7&principal_id={USER}&role_id={ROLE}&scope=tenant&valid_until="
                ),
                "GrantRole",
            ),
            (
                format!("/settings/access/direct-bindings/{BINDING}/revoke"),
                format!(
                    "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&reason=review"
                ),
                "RevokeRole",
            ),
        ];
        for (path, body, expected_kind) in cases {
            let form =
                parse_form(&path, body.as_bytes()).expect("current mutation form must parse");
            assert_eq!(form.canonical_path(), path);
            assert_eq!(format!("{form:?}"), expected_kind);
            assert!(!format!("{form:?}").contains(CSRF));
        }
    }

    #[test]
    fn exhausted_target_revisions_allow_only_non_advancing_role_deletion() {
        let maximum_revision = i64::MAX;
        for (path, business_fields) in [
            (
                format!("/settings/access/users/{USER}/status"),
                "operation=enable".to_owned(),
            ),
            (
                format!("/settings/access/roles/{ROLE}"),
                "display_name=Release+reviewer".to_owned(),
            ),
            (
                format!("/settings/access/roles/{ROLE}/permissions/runs:read"),
                "operation=add".to_owned(),
            ),
            (
                format!("/settings/access/direct-bindings/{BINDING}/revoke"),
                "reason=review".to_owned(),
            ),
        ] {
            let body = format!(
                "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision={maximum_revision}&{business_fields}"
            );
            assert_eq!(
                parse_form(&path, body.as_bytes()),
                Err(RbacManagementFormError),
                "revision-advancing form must reject an exhausted target revision"
            );
        }

        let delete_path = format!("/settings/access/roles/{ROLE}/delete");
        let delete_body = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision={maximum_revision}"
        );
        assert!(matches!(
            parse_form(&delete_path, delete_body.as_bytes()),
            Ok(VerifiedRbacManagementForm::DeleteRole {
                expected_revision,
                ..
            }) if expected_revision.value() == maximum_revision.cast_unsigned()
        ));
    }

    #[test]
    fn permission_operation_is_explicit_and_never_a_toggle() {
        let path = format!("/settings/access/roles/{ROLE}/permissions/runs:read");
        for (operation, expected) in [("add", true), ("remove", false)] {
            let body = format!(
                "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation={operation}"
            );
            let form = parse_form(&path, body.as_bytes()).expect("valid form");
            assert!(matches!(
                form,
                VerifiedRbacManagementForm::SetRolePermission { present, .. } if present == expected
            ));
        }
        let body = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation=toggle"
        );
        assert_eq!(
            parse_form(&path, body.as_bytes()),
            Err(RbacManagementFormError)
        );
    }

    #[test]
    fn parser_rejects_duplicates_unknowns_bad_revisions_and_cross_form_fields() {
        let path = format!("/settings/access/users/{USER}/status");
        let valid = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation=disable&reason=review"
        );
        assert!(parse_form(&path, valid.as_bytes()).is_ok());
        for body in [
            format!("{valid}&reason=again"),
            format!("{valid}&unknown=x"),
            valid.replace("expected_revision=9", "expected_revision=09"),
            valid.replace("operation=disable", "operation=enable"),
            valid.replace("reason=review", "display_name=review"),
            format!(
                "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation=toggle"
            ),
        ] {
            assert_eq!(
                parse_form(&path, body.as_bytes()),
                Err(RbacManagementFormError),
                "body should be rejected"
            );
        }
    }

    #[test]
    fn parser_rejects_attacker_controlled_text_before_domain_command_construction() {
        let create_path = "/settings/access/roles";
        for display_name in [
            "x".repeat(MAX_DISPLAY_NAME_BYTES + 1),
            "🚀".repeat(MAX_DISPLAY_NAME_BYTES / 4 + 1),
            "+%E2%80%8B".to_owned(),
            "%E2%80%8B".to_owned(),
            "review%E2%80%AErole".to_owned(),
            "line%0Abreak".to_owned(),
        ] {
            let body = format!(
                "csrf_token={CSRF}&expected_authorization_revision=7&name=reviewer&display_name={display_name}"
            );
            assert_eq!(
                parse_form(create_path, body.as_bytes()),
                Err(RbacManagementFormError)
            );
        }

        let revoke_path = format!("/settings/access/direct-bindings/{BINDING}/revoke");
        for reason in [
            "x".repeat(MAX_REASON_BYTES + 1),
            "🚀".repeat(MAX_REASON_BYTES / 4 + 1),
            "+%E2%80%8B".to_owned(),
            "%E2%80%8B".to_owned(),
            "review%E2%80%AErole".to_owned(),
            "line%0Abreak".to_owned(),
        ] {
            let body = format!(
                "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&reason={reason}"
            );
            assert_eq!(
                parse_form(&revoke_path, body.as_bytes()),
                Err(RbacManagementFormError)
            );
        }

        let multibyte_display_name = "🚀".repeat(MAX_DISPLAY_NAME_BYTES / 4);
        let body = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&name=reviewer&display_name={multibyte_display_name}"
        );
        assert!(parse_form(create_path, body.as_bytes()).is_ok());

        let multibyte_reason = "🚀".repeat(MAX_REASON_BYTES / 4);
        let body = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&reason={multibyte_reason}"
        );
        assert!(parse_form(&revoke_path, body.as_bytes()).is_ok());
    }

    #[test]
    fn csrf_envelope_is_independent_from_business_validity_and_redacted() {
        let malformed_business = format!("csrf_token={CSRF}&unknown=value");
        let token = rbac_management_csrf_token(malformed_business.as_bytes())
            .expect("independent CSRF token");
        assert!(!format!("{token:?}").contains(CSRF));
        assert!(
            rbac_management_csrf_token(format!("{malformed_business}&csrf_token=x").as_bytes())
                .is_err()
        );
    }

    #[test]
    fn direct_grant_accepts_only_canonical_bounded_scope_values() {
        let base = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&principal_id={USER}&role_id={ROLE}"
        );
        for scope in [
            "tenant".to_owned(),
            format!("repository:{BINDING}"),
            format!("runner-group:{BINDING}"),
        ] {
            let body = format!("{base}&scope={scope}&valid_until=2030-01-01T00%3A00");
            assert!(parse_form("/settings/access/direct-bindings", body.as_bytes()).is_ok());
        }
        for scope in ["repository", "tenant:x", "repository:NOT-A-UUID"] {
            let body = format!("{base}&scope={scope}");
            assert_eq!(
                parse_form("/settings/access/direct-bindings", body.as_bytes()),
                Err(RbacManagementFormError)
            );
        }
    }

    #[test]
    fn direct_grant_expiry_is_an_optional_strict_future_utc_minute() {
        let path = "/settings/access/direct-bindings";
        let base = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&principal_id={USER}&role_id={ROLE}&scope=tenant&valid_until="
        );
        for (encoded, expected_seconds) in [
            ("", None),
            ("2024-02-29T12%3A34", Some(1_709_210_040)),
            ("9999-12-31T23%3A59", Some(253_402_300_740)),
        ] {
            let form = parse_form(path, format!("{base}{encoded}").as_bytes())
                .expect("valid optional UTC minute");
            assert!(matches!(
                form,
                VerifiedRbacManagementForm::GrantRole { valid_until, .. }
                    if valid_until.map(UnixTimestamp::as_seconds) == expected_seconds
            ));
        }

        for encoded in [
            "1709210040",
            "1969-12-31T23%3A59",
            "2023-02-29T12%3A34",
            "2024-02-30T12%3A34",
            "2024-02-29T24%3A00",
            "2024-02-29T12%3A60",
            "2024-02-29T12%3A34%3A00",
            "2024-02-29T12%3A34.0",
            "2024-02-29T12%3A34Z",
            "2024-02-29T12%3A34%2B00%3A00",
            "2024-02-29+12%3A34",
            "+2024-02-29T12%3A34",
            "2024-02-29T12%3A34+",
            "%202024-02-29T12%3A34",
            "2024-02-29T12%3A34%20",
            "%EF%BC%92%EF%BC%90%EF%BC%92%EF%BC%94-02-29T12%3A34",
            "10000-01-01T00%3A00",
        ] {
            assert_eq!(
                parse_form(path, format!("{base}{encoded}").as_bytes()),
                Err(RbacManagementFormError),
                "expiry {encoded:?} must fail closed"
            );
        }

        let first_future_minute = format!("{base}1970-01-01T00%3A01");
        assert!(matches!(
            parse_rbac_management_form(
                path,
                first_future_minute.as_bytes(),
                UnixTimestamp::from_seconds(0),
            ),
            Ok(VerifiedRbacManagementForm::GrantRole {
                valid_until: Some(valid_until),
                ..
            }) if valid_until.as_seconds() == 60
        ));
    }

    #[test]
    fn direct_grant_expiry_must_be_later_than_the_authenticated_request_time() {
        let path = "/settings/access/direct-bindings";
        let body = format!(
            "csrf_token={CSRF}&expected_authorization_revision=7&principal_id={USER}&role_id={ROLE}&scope=tenant&valid_until=2024-02-29T12%3A34"
        );
        for now in [1_709_210_040, 1_709_210_041, 253_402_300_740] {
            assert_eq!(
                parse_rbac_management_form(path, body.as_bytes(), UnixTimestamp::from_seconds(now),),
                Err(RbacManagementFormError)
            );
        }
        assert!(
            parse_rbac_management_form(
                path,
                body.as_bytes(),
                UnixTimestamp::from_seconds(1_709_210_039),
            )
            .is_ok()
        );
    }

    #[test]
    fn parser_enforces_encoded_body_field_utf8_and_uuid_boundaries() {
        assert!(validate_body_size(&[b'x'; MAX_RBAC_MANAGEMENT_FORM_BYTES]).is_ok());
        assert_eq!(
            validate_body_size(&[b'x'; MAX_RBAC_MANAGEMENT_FORM_BYTES + 1]),
            Err(RbacManagementFormError)
        );

        let seven_fields = b"csrf_token=x&expected_authorization_revision=1&expected_revision=1&operation=add&reason=x&name=x&display_name=x";
        assert!(parse_fields(seven_fields).is_ok());
        let eight_fields = [seven_fields.as_slice(), b"&principal_id=x"].concat();
        assert_eq!(
            parse_fields(&eight_fields).err(),
            Some(RbacManagementFormError)
        );

        let path = format!("/settings/access/users/{USER}/status");
        for malformed in ["%", "%GG", "%FF"] {
            let body = format!(
                "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation=disable&reason={malformed}"
            );
            assert_eq!(
                parse_form(&path, body.as_bytes()),
                Err(RbacManagementFormError)
            );
        }
        for principal in [
            "00000000-0000-0000-0000-000000000000",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        ] {
            let body = format!(
                "csrf_token={CSRF}&expected_authorization_revision=7&expected_revision=9&operation=disable&reason=review"
            );
            assert_eq!(
                parse_form(
                    &format!("/settings/access/users/{principal}/status"),
                    body.as_bytes(),
                ),
                Err(RbacManagementFormError)
            );
        }
    }
}
