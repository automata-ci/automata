//! Shared semantic lowering helpers for the current logical workflow plan.

use automata_ci_core::{Located, PermissionGrant, WorkflowJobKey, WorkflowPermissions};
use automata_ci_github_permissions::{
    GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION, github_workflow_permission,
};

use crate::{Needs, PermissionLevel, Permissions, Spanned};

use super::CompileContext;

pub(super) fn compile_needs(
    needs: Option<&Needs>,
    context: &mut CompileContext<'_>,
) -> Vec<Located<WorkflowJobKey>> {
    let values: &[Spanned<String>] = match needs {
        None => return Vec::new(),
        Some(Needs::One(value)) => std::slice::from_ref(value),
        Some(Needs::Many(values)) => values,
    };
    values
        .iter()
        .filter_map(|value| match WorkflowJobKey::new(value.value()) {
            Ok(key) => context.located(key, value.span()),
            Err(error) => {
                context.semantic(
                    "github.compile.invalid_dependency_key",
                    error.to_string(),
                    value.span().clone(),
                );
                None
            }
        })
        .collect()
}

pub(super) fn compile_permissions(
    permissions: &Permissions,
    context: &mut CompileContext<'_>,
) -> Option<WorkflowPermissions> {
    match permissions {
        Permissions::ReadAll(span) => context.span(span).map(WorkflowPermissions::ReadAll),
        Permissions::WriteAll(span) => context.span(span).map(WorkflowPermissions::WriteAll),
        Permissions::Mapping { entries, .. } => {
            let grants = entries
                .iter()
                .filter_map(|entry| {
                    let Some(permission) = github_workflow_permission(entry.name().value()) else {
                        context.semantic(
                            "github.compile.unknown_permission",
                            format!(
                                "permission `{}` is not present in GitHub workflow permission catalog revision {GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION}",
                                entry.name().value()
                            ),
                            entry.name().span().clone(),
                        );
                        return None;
                    };
                    let permitted = match entry.level().value() {
                        PermissionLevel::Read => permission.allows_read(),
                        PermissionLevel::Write => permission.allows_write(),
                        PermissionLevel::None => true,
                    };
                    if !permitted {
                        context.semantic(
                            "github.compile.invalid_permission_level",
                            format!(
                                "permission `{}` uses a level unavailable in GitHub workflow permission catalog revision {GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION}",
                                entry.name().value()
                            ),
                            entry.level().span().clone(),
                        );
                        return None;
                    }
                    let name = located_text(entry.name(), context)?;
                    let level = match entry.level().value() {
                        PermissionLevel::Read => automata_ci_core::PermissionLevel::Read,
                        PermissionLevel::Write => automata_ci_core::PermissionLevel::Write,
                        PermissionLevel::None => automata_ci_core::PermissionLevel::None,
                    };
                    let level = context.located(level, entry.level().span())?;
                    Some(PermissionGrant::new(name, level))
                })
                .collect();
            Some(WorkflowPermissions::Mapping(grants))
        }
    }
}

pub(super) fn located_text(
    value: &Spanned<String>,
    context: &mut CompileContext<'_>,
) -> Option<Located<String>> {
    context.located(value.value().clone(), value.span())
}
