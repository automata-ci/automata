use crate::{
    EventName, EventTrigger, PushPullRequestFilter, Spanned, TriggerConfiguration, TriggerSet,
    YamlNode,
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
    "merge_group",
    "milestone",
    "page_build",
    "public",
    "pull_request_review",
    "pull_request_review_comment",
    "pull_request_target",
    "registry_package",
    "release",
    "repository_dispatch",
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
            if let Some(name) = context.text(item, path) {
                events.push(event_without_configuration(name, context));
            }
        }
    } else if let Some(entries) = node.as_mapping() {
        for entry in entries {
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
    let typed_configuration = match &event_name {
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
        EventName::WorkflowDispatch if empty => TriggerConfiguration::WorkflowDispatch(None),
        EventName::WorkflowDispatch => {
            context.unsupported(
                "github.workflow_dispatch_configuration",
                "`on.workflow_dispatch` inputs are preserved for a future typed decoder",
                configuration.span.clone(),
            );
            TriggerConfiguration::WorkflowDispatch(Some(configuration.clone()))
        }
        EventName::Schedule => {
            context.unsupported(
                "github.schedule_configuration",
                "`on.schedule` is preserved for a future cron and timezone decoder",
                configuration.span.clone(),
            );
            TriggerConfiguration::Schedule(configuration.clone())
        }
        EventName::WorkflowCall => {
            context.unsupported(
                "github.workflow_call_configuration",
                "`on.workflow_call` is preserved for the reusable-workflow frontend",
                configuration.span.clone(),
            );
            TriggerConfiguration::WorkflowCall(configuration.clone())
        }
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
            TriggerConfiguration::Preserved(configuration.clone())
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
            EventName::Other(other.to_owned())
        }
    }
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
        let entry_path = field_name(entry).map(|name| format!("{path}.{name}"));
        match field_name(entry) {
            Some("branches") if filter.branches.is_empty() => {
                filter.branches =
                    sequence_text(&entry.value, entry_path.as_deref().unwrap_or(path), context);
            }
            Some("branches-ignore") if filter.branches_ignore.is_empty() => {
                filter.branches_ignore =
                    sequence_text(&entry.value, entry_path.as_deref().unwrap_or(path), context);
            }
            Some("tags") if filter.tags.is_empty() => {
                filter.tags =
                    sequence_text(&entry.value, entry_path.as_deref().unwrap_or(path), context);
            }
            Some("tags-ignore") if filter.tags_ignore.is_empty() => {
                filter.tags_ignore =
                    sequence_text(&entry.value, entry_path.as_deref().unwrap_or(path), context);
            }
            Some("paths") if filter.paths.is_empty() => {
                filter.paths =
                    sequence_text(&entry.value, entry_path.as_deref().unwrap_or(path), context);
            }
            Some("paths-ignore") if filter.paths_ignore.is_empty() => {
                filter.paths_ignore =
                    sequence_text(&entry.value, entry_path.as_deref().unwrap_or(path), context);
            }
            Some("types") if allow_types && filter.types.is_empty() => {
                filter.types =
                    sequence_text(&entry.value, entry_path.as_deref().unwrap_or(path), context);
            }
            Some(
                "branches" | "branches-ignore" | "tags" | "tags-ignore" | "paths" | "paths-ignore",
            ) => {}
            Some("types") if allow_types => {}
            _ => filter
                .extensions
                .push(context.preserve_unknown(path, entry)),
        }
    }

    mutually_exclusive(
        &filter.branches,
        &filter.branches_ignore,
        "branches",
        "branches-ignore",
        path,
        node,
        context,
    );
    mutually_exclusive(
        &filter.tags,
        &filter.tags_ignore,
        "tags",
        "tags-ignore",
        path,
        node,
        context,
    );
    mutually_exclusive(
        &filter.paths,
        &filter.paths_ignore,
        "paths",
        "paths-ignore",
        path,
        node,
        context,
    );
    filter
}

fn mutually_exclusive(
    included: &[Spanned<String>],
    excluded: &[Spanned<String>],
    included_name: &str,
    excluded_name: &str,
    path: &str,
    node: &YamlNode,
    context: &mut DecodeContext<'_>,
) {
    if !included.is_empty() && !excluded.is_empty() {
        context.semantic(
            "github.mutually_exclusive_filters",
            format!("`{path}.{included_name}` and `{path}.{excluded_name}` cannot both be used"),
            node.span.clone(),
        );
    }
}
