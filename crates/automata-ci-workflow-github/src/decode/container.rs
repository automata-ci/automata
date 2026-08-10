use crate::{
    ContainerCredentials, ContainerEnvironment, ContainerSequence, DetailedContainer, JobContainer,
    JobService, JobServices, PreservedField, ScalarValue, Spanned, ValueMap, ValueMapEntry,
    YamlMappingEntry, YamlNode,
};

use super::{DecodeContext, field_name};

pub(super) fn job_container(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobContainer> {
    parse_container(node, path, ContainerKind::Job, context)
}

pub(super) fn job_services(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobServices> {
    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.expected_job_services",
            format!("`{path}` must be a mapping of service names to container definitions"),
            node.span.clone(),
        );
        return None;
    };

    let mut services = Vec::with_capacity(entries.len());
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        let Some(id) = entry.key.as_scalar() else {
            context.semantic(
                "github.expected_service_id",
                format!("service key at `{path}` must be a non-empty scalar name"),
                entry.key.span.clone(),
            );
            continue;
        };
        if id.is_null() || id.decoded.is_empty() {
            context.semantic(
                "github.expected_service_id",
                format!("service key at `{path}` must be a non-empty scalar name"),
                entry.key.span.clone(),
            );
            continue;
        }
        let Some(service_path) = context.child_path(path, &id.decoded, &entry.key.span) else {
            break;
        };
        let Some(container) =
            parse_container(&entry.value, &service_path, ContainerKind::Service, context)
        else {
            continue;
        };
        services.push(JobService {
            id: Spanned::new(id.decoded.clone(), entry.key.span.clone()),
            container,
            span: entry.span.clone(),
        });
    }
    if context.is_exhausted() {
        return None;
    }
    Some(JobServices {
        entries: services,
        span: node.span.clone(),
    })
}

#[derive(Clone, Copy)]
enum ContainerKind {
    Job,
    Service,
}

impl ContainerKind {
    const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::Job => "github.expected_job_container",
            Self::Service => "github.expected_service_container",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Job => "job container",
            Self::Service => "service container",
        }
    }
}

fn parse_container(
    node: &YamlNode,
    path: &str,
    kind: ContainerKind,
    context: &mut DecodeContext<'_>,
) -> Option<JobContainer> {
    if node.as_scalar().is_some() {
        return string_value(
            node,
            path,
            context,
            kind.diagnostic_code(),
            &format!("a scalar image or a {} mapping", kind.description()),
            false,
        )
        .map(JobContainer::Image);
    }

    let Some(entries) = node.as_mapping() else {
        context.semantic(
            kind.diagnostic_code(),
            format!(
                "`{path}` must be a scalar image or a {} mapping",
                kind.description()
            ),
            node.span.clone(),
        );
        return None;
    };

    detailed_container(entries, node, path, context)
}

fn detailed_container(
    entries: &[YamlMappingEntry],
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobContainer> {
    let mut fields = ContainerFields::default();
    for entry in entries {
        if context.is_exhausted() || !fields.decode_entry(entry, path, context) {
            break;
        }
    }
    if context.is_exhausted() {
        return None;
    }
    Some(fields.into_container(node))
}

const IMAGE_FIELD: u8 = 1 << 0;
const CREDENTIALS_FIELD: u8 = 1 << 1;
const ENVIRONMENT_FIELD: u8 = 1 << 2;
const PORTS_FIELD: u8 = 1 << 3;
const VOLUMES_FIELD: u8 = 1 << 4;
const OPTIONS_FIELD: u8 = 1 << 5;

#[derive(Default)]
struct ContainerFields {
    image: Option<ScalarValue>,
    credentials: Option<ContainerCredentials>,
    environment: Option<ContainerEnvironment>,
    ports: Option<ContainerSequence>,
    volumes: Option<ContainerSequence>,
    options: Option<ScalarValue>,
    extensions: Vec<PreservedField>,
    seen: u8,
}

impl ContainerFields {
    fn decode_entry(
        &mut self,
        entry: &YamlMappingEntry,
        path: &str,
        context: &mut DecodeContext<'_>,
    ) -> bool {
        match field_name(entry) {
            Some("image") if self.mark_first(IMAGE_FIELD) => {
                self.decode_image(entry, path, context)
            }
            Some("credentials") if self.mark_first(CREDENTIALS_FIELD) => {
                self.decode_credentials(entry, path, context)
            }
            Some("env") if self.mark_first(ENVIRONMENT_FIELD) => {
                self.decode_environment(entry, path, context)
            }
            Some("ports") if self.mark_first(PORTS_FIELD) => {
                self.decode_ports(entry, path, context)
            }
            Some("volumes") if self.mark_first(VOLUMES_FIELD) => {
                self.decode_volumes(entry, path, context)
            }
            Some("options") if self.mark_first(OPTIONS_FIELD) => {
                self.decode_options(entry, path, context)
            }
            Some("image" | "credentials" | "env" | "ports" | "volumes" | "options") => true,
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    self.extensions.push(extension);
                }
                !context.is_exhausted()
            }
        }
    }

    fn mark_first(&mut self, field: u8) -> bool {
        let first = self.seen & field == 0;
        self.seen |= field;
        first
    }

    fn decode_image(
        &mut self,
        entry: &YamlMappingEntry,
        path: &str,
        context: &mut DecodeContext<'_>,
    ) -> bool {
        let Some(field_path) = context.child_path(path, "image", &entry.key.span) else {
            return false;
        };
        self.image = string_value(
            &entry.value,
            &field_path,
            context,
            "github.expected_container_image",
            "a scalar image",
            false,
        );
        true
    }

    fn decode_credentials(
        &mut self,
        entry: &YamlMappingEntry,
        path: &str,
        context: &mut DecodeContext<'_>,
    ) -> bool {
        let Some(field_path) = context.child_path(path, "credentials", &entry.key.span) else {
            return false;
        };
        self.credentials = container_credentials(&entry.value, &field_path, context);
        true
    }

    fn decode_environment(
        &mut self,
        entry: &YamlMappingEntry,
        path: &str,
        context: &mut DecodeContext<'_>,
    ) -> bool {
        let Some(field_path) = context.child_path(path, "env", &entry.key.span) else {
            return false;
        };
        self.environment = container_environment(&entry.value, &field_path, context);
        true
    }

    fn decode_ports(
        &mut self,
        entry: &YamlMappingEntry,
        path: &str,
        context: &mut DecodeContext<'_>,
    ) -> bool {
        let Some(field_path) = context.child_path(path, "ports", &entry.key.span) else {
            return false;
        };
        self.ports = container_sequence(
            &entry.value,
            &field_path,
            context,
            "github.expected_container_ports",
            "port",
        );
        true
    }

    fn decode_volumes(
        &mut self,
        entry: &YamlMappingEntry,
        path: &str,
        context: &mut DecodeContext<'_>,
    ) -> bool {
        let Some(field_path) = context.child_path(path, "volumes", &entry.key.span) else {
            return false;
        };
        self.volumes = container_sequence(
            &entry.value,
            &field_path,
            context,
            "github.expected_container_volumes",
            "volume",
        );
        true
    }

    fn decode_options(
        &mut self,
        entry: &YamlMappingEntry,
        path: &str,
        context: &mut DecodeContext<'_>,
    ) -> bool {
        let Some(field_path) = context.child_path(path, "options", &entry.key.span) else {
            return false;
        };
        self.options = string_value(
            &entry.value,
            &field_path,
            context,
            "github.expected_container_options",
            "a scalar",
            false,
        );
        true
    }

    fn into_container(self, node: &YamlNode) -> JobContainer {
        JobContainer::Detailed(Box::new(DetailedContainer {
            image: self.image,
            credentials: self.credentials,
            environment: self.environment,
            ports: self.ports,
            volumes: self.volumes,
            options: self.options,
            extensions: self.extensions,
            span: node.span.clone(),
        }))
    }
}

fn container_credentials(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<ContainerCredentials> {
    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.expected_container_credentials",
            format!("`{path}` must be a mapping with `username` and `password` fields"),
            node.span.clone(),
        );
        return None;
    };

    let mut username = None;
    let mut username_seen = false;
    let mut password = None;
    let mut password_seen = false;
    let mut extensions: Vec<PreservedField> = Vec::new();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("username") if !username_seen => {
                let Some(field_path) = context.child_path(path, "username", &entry.key.span) else {
                    break;
                };
                username = string_value(
                    &entry.value,
                    &field_path,
                    context,
                    "github.expected_container_credential",
                    "a non-empty scalar",
                    true,
                );
                username_seen = true;
            }
            Some("password") if !password_seen => {
                let Some(field_path) = context.child_path(path, "password", &entry.key.span) else {
                    break;
                };
                password = string_value(
                    &entry.value,
                    &field_path,
                    context,
                    "github.expected_container_credential",
                    "a non-empty scalar",
                    true,
                );
                password_seen = true;
            }
            Some("username" | "password") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }
    if context.is_exhausted() {
        return None;
    }
    Some(ContainerCredentials {
        username,
        password,
        extensions,
        span: node.span.clone(),
    })
}

fn container_environment(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<ContainerEnvironment> {
    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.expected_container_environment",
            format!("`{path}` must be a mapping of non-empty variable names to scalar values"),
            node.span.clone(),
        );
        return None;
    };

    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        let Some(key) = entry.key.as_scalar() else {
            context.semantic(
                "github.expected_container_environment_name",
                format!("environment key at `{path}` must be a non-empty scalar name"),
                entry.key.span.clone(),
            );
            continue;
        };
        if key.is_null() || key.decoded.is_empty() {
            context.semantic(
                "github.expected_container_environment_name",
                format!("environment key at `{path}` must be a non-empty scalar name"),
                entry.key.span.clone(),
            );
            continue;
        }
        let Some(value_path) = context.child_path(path, &key.decoded, &entry.key.span) else {
            break;
        };
        let Some(value) = string_value(
            &entry.value,
            &value_path,
            context,
            "github.expected_container_environment_value",
            "a scalar",
            false,
        ) else {
            continue;
        };
        values.push(ValueMapEntry {
            key: Spanned::new(key.decoded.clone(), entry.key.span.clone()),
            value,
        });
    }
    if context.is_exhausted() {
        return None;
    }
    Some(ContainerEnvironment {
        values: ValueMap { entries: values },
        span: node.span.clone(),
    })
}

fn container_sequence(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
    code: &'static str,
    item_name: &'static str,
) -> Option<ContainerSequence> {
    let Some(items) = node.as_sequence() else {
        context.semantic(
            code,
            format!("`{path}` must be a sequence of non-empty scalar {item_name} values"),
            node.span.clone(),
        );
        return None;
    };

    let mut values = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if context.is_exhausted() {
            break;
        }
        let Some(item_path) = context.indexed_path(path, index, &item.span) else {
            break;
        };
        if let Some(value) = string_value(
            item,
            &item_path,
            context,
            code,
            &format!("a non-empty scalar {item_name}"),
            true,
        ) {
            values.push(value);
        }
    }
    if context.is_exhausted() {
        return None;
    }
    Some(ContainerSequence {
        values,
        span: node.span.clone(),
    })
}

fn string_value(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
    code: &str,
    expected: &str,
    require_non_empty: bool,
) -> Option<ScalarValue> {
    let Some(scalar) = node.as_scalar() else {
        context.semantic(
            code,
            format!("`{path}` must be {expected}"),
            node.span.clone(),
        );
        return None;
    };
    if require_non_empty && (scalar.is_null() || scalar.decoded.is_empty()) {
        context.semantic(
            code,
            format!("`{path}` must be {expected}"),
            node.span.clone(),
        );
        return None;
    }
    Some(ScalarValue::from_yaml(scalar, node.span.clone()))
}
