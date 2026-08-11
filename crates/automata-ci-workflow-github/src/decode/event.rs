use crate::{
    EventName, EventTrigger, MergeGroupFilter, PushPullRequestFilter, RepositoryDispatchFilter,
    Spanned, TriggerConfiguration, TriggerSet, YamlNode,
};

use super::{DecodeContext, field_name, sequence_text};

const OTHER_GITHUB_EVENTS: &[&str] = &[
    "branch_protection_rule",
    "check_run",
    "check_suite",
    "create",
    "delete",
    "deployment",
    "deployment_status",
    "discussion",
    "discussion_comment",
    "fork",
    "gollum",
    "issue_comment",
    "issues",
    "label",
    "milestone",
    "page_build",
    "public",
    "pull_request_review",
    "pull_request_review_comment",
    "pull_request_target",
    "registry_package",
    "release",
    "status",
    "watch",
    "workflow_run",
];

pub(super) fn triggers(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<TriggerSet> {
    let mut events = Vec::new();
    if node.as_scalar().is_some() {
        if let Some(name) = context.text(node, path) {
            events.push(event_without_configuration(name, context));
        }
    } else if let Some(items) = node.as_sequence() {
        for item in items {
            if context.is_exhausted() {
                break;
            }
            if let Some(name) = context.text(item, path) {
                events.push(event_without_configuration(name, context));
            }
        }
    } else if let Some(entries) = node.as_mapping() {
        for entry in entries {
            if context.is_exhausted() {
                break;
            }
            let Some(name_scalar) = entry.key.as_scalar() else {
                continue;
            };
            let name = Spanned::new(name_scalar.decoded.clone(), entry.key.span.clone());
            events.push(event_with_configuration(&name, &entry.value, context));
        }
    } else {
        context.semantic(
            "github.invalid_trigger",
            format!("`{path}` must be an event name, sequence, or mapping"),
            node.span.clone(),
        );
        return None;
    }

    if context.is_exhausted() {
        return None;
    }
    if events.is_empty() {
        context.semantic(
            "github.empty_trigger_set",
            "workflow must declare at least one trigger",
            node.span.clone(),
        );
    }
    Some(TriggerSet {
        events,
        span: node.span.clone(),
    })
}

fn event_without_configuration(
    name: Spanned<String>,
    context: &mut DecodeContext<'_>,
) -> EventTrigger {
    let event_name = parse_event_name(&name, context);
    EventTrigger {
        name: Spanned::new(event_name, name.span.clone()),
        configuration: TriggerConfiguration::Empty,
        span: name.span,
    }
}

fn event_with_configuration(
    name: &Spanned<String>,
    configuration: &YamlNode,
    context: &mut DecodeContext<'_>,
) -> EventTrigger {
    let event_name = parse_event_name(name, context);
    let empty = configuration
        .as_scalar()
        .is_some_and(crate::YamlScalar::is_null);
    let typed_configuration = if context.is_exhausted() {
        TriggerConfiguration::Empty
    } else {
        match &event_name {
            EventName::Push if empty => TriggerConfiguration::Push(PushPullRequestFilter::empty()),
            EventName::Push => TriggerConfiguration::Push(filter_configuration(
                configuration,
                "on.push",
                false,
                context,
            )),
            EventName::PullRequest if empty => {
                TriggerConfiguration::PullRequest(PushPullRequestFilter::empty())
            }
            EventName::PullRequest => TriggerConfiguration::PullRequest(filter_configuration(
                configuration,
                "on.pull_request",
                true,
                context,
            )),
            EventName::MergeGroup if empty => {
                TriggerConfiguration::MergeGroup(MergeGroupFilter::empty())
            }
            EventName::MergeGroup => {
                TriggerConfiguration::MergeGroup(merge_group_configuration(configuration, context))
            }
            EventName::RepositoryDispatch if empty => {
                TriggerConfiguration::RepositoryDispatch(RepositoryDispatchFilter::empty())
            }
            EventName::RepositoryDispatch => TriggerConfiguration::RepositoryDispatch(
                repository_dispatch_configuration(configuration, context),
            ),
            EventName::WorkflowDispatch if empty => TriggerConfiguration::WorkflowDispatch(None),
            EventName::WorkflowDispatch => {
                TriggerConfiguration::WorkflowDispatch(Some(configuration.clone()))
            }
            EventName::Schedule => TriggerConfiguration::Schedule(configuration.clone()),
            EventName::WorkflowCall => TriggerConfiguration::WorkflowCall(configuration.clone()),
            EventName::Other(_) if empty => TriggerConfiguration::Empty,
            EventName::Other(_) => {
                context.unsupported(
                "github.event_configuration",
                format!(
                    "configuration for event `{}` is preserved but not typed by this frontend version",
                    name.value
                ),
                configuration.span.clone(),
            );
                if context.is_exhausted() {
                    TriggerConfiguration::Empty
                } else {
                    TriggerConfiguration::Preserved(configuration.clone())
                }
            }
        }
    };
    EventTrigger {
        name: Spanned::new(event_name, name.span.clone()),
        configuration: typed_configuration,
        span: crate::SourceSpan::new(
            name.span.source_id.clone(),
            name.span.start,
            configuration.span.end,
        ),
    }
}

fn parse_event_name(name: &Spanned<String>, context: &mut DecodeContext<'_>) -> EventName {
    match name.value.as_str() {
        "push" => EventName::Push,
        "pull_request" => EventName::PullRequest,
        "merge_group" => EventName::MergeGroup,
        "repository_dispatch" => EventName::RepositoryDispatch,
        "workflow_dispatch" => EventName::WorkflowDispatch,
        "schedule" => EventName::Schedule,
        "workflow_call" => EventName::WorkflowCall,
        other if OTHER_GITHUB_EVENTS.contains(&other) => EventName::Other(other.to_owned()),
        other => {
            context.semantic(
                "github.unknown_event",
                format!("`{other}` is not a recognized GitHub Actions event"),
                name.span.clone(),
            );
            if context.is_exhausted() {
                EventName::Other(String::new())
            } else {
                EventName::Other(other.to_owned())
            }
        }
    }
}

fn merge_group_configuration(node: &YamlNode, context: &mut DecodeContext<'_>) -> MergeGroupFilter {
    const PATH: &str = "on.merge_group";
    let Some(entries) = context.expect_mapping(node, PATH) else {
        return MergeGroupFilter::empty();
    };
    let mut filter = MergeGroupFilter::empty();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        let name = field_name(entry);
        let entry_path = match name {
            Some(name) => context.child_path(PATH, name, &entry.key.span),
            None => None,
        };
        if name.is_some() && entry_path.is_none() {
            break;
        }
        match name {
            Some("types") if filter.types.is_none() => {
                filter.types = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    PATH,
                    context,
                ));
            }
            Some("types") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(PATH, entry) {
                    filter.extensions.push(extension);
                }
            }
        }
    }
    filter
}

fn repository_dispatch_configuration(
    node: &YamlNode,
    context: &mut DecodeContext<'_>,
) -> RepositoryDispatchFilter {
    const PATH: &str = "on.repository_dispatch";
    let Some(entries) = context.expect_mapping(node, PATH) else {
        return RepositoryDispatchFilter::empty();
    };
    let mut filter = RepositoryDispatchFilter::empty();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        let name = field_name(entry);
        let entry_path = match name {
            Some(name) => context.child_path(PATH, name, &entry.key.span),
            None => None,
        };
        if name.is_some() && entry_path.is_none() {
            break;
        }
        match name {
            Some("types") if filter.types.is_none() => {
                filter.types = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    PATH,
                    context,
                ));
            }
            Some("types") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(PATH, entry) {
                    filter.extensions.push(extension);
                }
            }
        }
    }
    filter
}

fn filter_configuration(
    node: &YamlNode,
    path: &str,
    allow_types: bool,
    context: &mut DecodeContext<'_>,
) -> PushPullRequestFilter {
    let Some(entries) = context.expect_mapping(node, path) else {
        return PushPullRequestFilter::empty();
    };
    let mut filter = PushPullRequestFilter::empty();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        let name = field_name(entry);
        let entry_path = match name {
            Some(name) => context.child_path(path, name, &entry.key.span),
            None => None,
        };
        if name.is_some() && entry_path.is_none() {
            break;
        }
        match name {
            Some("branches") if filter.branches.is_none() => {
                filter.branches = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    path,
                    context,
                ));
            }
            Some("branches-ignore") if filter.branches_ignore.is_none() => {
                filter.branches_ignore = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    path,
                    context,
                ));
            }
            Some("tags") if filter.tags.is_none() => {
                filter.tags = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    path,
                    context,
                ));
            }
            Some("tags-ignore") if filter.tags_ignore.is_none() => {
                filter.tags_ignore = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    path,
                    context,
                ));
            }
            Some("paths") if filter.paths.is_none() => {
                filter.paths = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    path,
                    context,
                ));
            }
            Some("paths-ignore") if filter.paths_ignore.is_none() => {
                filter.paths_ignore = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    path,
                    context,
                ));
            }
            Some("types") if allow_types && filter.types.is_none() => {
                filter.types = Some(filter_values(
                    &entry.value,
                    entry_path.as_deref(),
                    path,
                    context,
                ));
            }
            Some(
                "branches" | "branches-ignore" | "tags" | "tags-ignore" | "paths" | "paths-ignore",
            ) => {}
            Some("types") if allow_types => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    filter.extensions.push(extension);
                }
            }
        }
    }

    if context.is_exhausted() {
        return filter;
    }

    validate_mutually_exclusive_filters(&filter, path, node, context);
    filter
}

fn validate_mutually_exclusive_filters(
    filter: &PushPullRequestFilter,
    path: &str,
    node: &YamlNode,
    context: &mut DecodeContext<'_>,
) {
    for (included, excluded, included_name, excluded_name) in [
        (
            filter.branches.is_some(),
            filter.branches_ignore.is_some(),
            "branches",
            "branches-ignore",
        ),
        (
            filter.tags.is_some(),
            filter.tags_ignore.is_some(),
            "tags",
            "tags-ignore",
        ),
        (
            filter.paths.is_some(),
            filter.paths_ignore.is_some(),
            "paths",
            "paths-ignore",
        ),
    ] {
        if context.is_exhausted() {
            break;
        }
        mutually_exclusive(
            included,
            excluded,
            included_name,
            excluded_name,
            path,
            node,
            context,
        );
    }
}

fn mutually_exclusive(
    included_configured: bool,
    excluded_configured: bool,
    included_name: &str,
    excluded_name: &str,
    path: &str,
    node: &YamlNode,
    context: &mut DecodeContext<'_>,
) {
    if included_configured && excluded_configured {
        context.semantic(
            "github.mutually_exclusive_filters",
            format!("`{path}.{included_name}` and `{path}.{excluded_name}` cannot both be used"),
            node.span.clone(),
        );
    }
}

fn reject_empty_filter(
    values: &[Spanned<String>],
    node: &YamlNode,
    path: Option<&str>,
    context: &mut DecodeContext<'_>,
) {
    if context.is_exhausted() {
        return;
    }
    if node
        .as_sequence()
        .is_some_and(<[crate::YamlNode]>::is_empty)
    {
        context.semantic(
            "github.empty_event_filter",
            format!("`{}` must contain at least one value", path.unwrap_or("on")),
            node.span.clone(),
        );
    }
    for value in values.iter().filter(|value| value.value.is_empty()) {
        if context.is_exhausted() {
            break;
        }
        context.semantic(
            "github.empty_event_filter_value",
            format!("`{}` values must not be empty", path.unwrap_or("on")),
            value.span.clone(),
        );
    }
}

fn filter_values(
    node: &YamlNode,
    entry_path: Option<&str>,
    fallback_path: &str,
    context: &mut DecodeContext<'_>,
) -> Vec<Spanned<String>> {
    if context.is_exhausted() {
        return Vec::new();
    }
    let path = entry_path.unwrap_or(fallback_path);
    let values = sequence_text(node, path, context);
    if context.is_exhausted() {
        return Vec::new();
    }
    reject_empty_filter(&values, node, Some(path), context);
    values
}
