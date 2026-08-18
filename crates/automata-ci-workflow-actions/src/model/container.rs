use crate::{PreservedField, ScalarValue, SourceSpan, Spanned, ValueMap};

/// A job or service container as written in workflow source.
///
/// GitHub accepts either a scalar image shorthand or a detailed mapping. The
/// two forms remain distinct so callers can retain the source author's shape.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JobContainer {
    /// Scalar shorthand containing only the image expression or literal.
    Image(ScalarValue),
    /// Mapping form retaining image, credentials, environment, ports, and options.
    Detailed(Box<DetailedContainer>),
}

impl JobContainer {
    /// Returns the image value from either source form.
    pub fn image(&self) -> Option<&ScalarValue> {
        match self {
            Self::Image(image) => Some(image),
            Self::Detailed(container) => container.image(),
        }
    }

    /// Returns the detailed mapping, when the source used that form.
    pub fn detailed(&self) -> Option<&DetailedContainer> {
        match self {
            Self::Image(_) => None,
            Self::Detailed(container) => Some(container),
        }
    }

    /// Returns the exact source span covering either container form.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Image(image) => image.span(),
            Self::Detailed(container) => container.span(),
        }
    }
}

/// Mapping form shared by job and service containers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DetailedContainer {
    pub(crate) image: Option<ScalarValue>,
    pub(crate) credentials: Option<ContainerCredentials>,
    pub(crate) environment: Option<ContainerEnvironment>,
    pub(crate) ports: Option<ContainerSequence>,
    pub(crate) volumes: Option<ContainerSequence>,
    pub(crate) options: Option<ScalarValue>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl DetailedContainer {
    /// Returns the image expression or literal, if the mapping declared one.
    pub fn image(&self) -> Option<&ScalarValue> {
        self.image.as_ref()
    }

    /// Returns source-level registry credentials, if declared.
    ///
    /// This frontend preserves expressions but does not evaluate or resolve
    /// credential values.
    pub fn credentials(&self) -> Option<&ContainerCredentials> {
        self.credentials.as_ref()
    }

    /// Returns the container-specific environment mapping, if declared.
    pub fn environment(&self) -> Option<&ContainerEnvironment> {
        self.environment.as_ref()
    }

    /// Returns source-ordered published port specifications, if declared.
    pub fn ports(&self) -> Option<&ContainerSequence> {
        self.ports.as_ref()
    }

    /// Returns source-ordered volume specifications, if declared.
    pub fn volumes(&self) -> Option<&ContainerSequence> {
        self.volumes.as_ref()
    }

    /// Returns the source-level container runtime options, if declared.
    pub fn options(&self) -> Option<&ScalarValue> {
        self.options.as_ref()
    }

    /// Returns fields preserved by parsing but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the detailed mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Registry credentials attached to a container image pull.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ContainerCredentials {
    pub(crate) username: Option<ScalarValue>,
    pub(crate) password: Option<ScalarValue>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl ContainerCredentials {
    /// Returns the source-level registry username, if declared.
    pub fn username(&self) -> Option<&ScalarValue> {
        self.username.as_ref()
    }

    /// Returns the source-level registry password expression, if declared.
    ///
    /// The value is unevaluated source syntax; callers must not copy it into
    /// diagnostics or logs.
    pub fn password(&self) -> Option<&ScalarValue> {
        self.password.as_ref()
    }

    /// Returns preserved credential fields unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the credentials mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Environment mapping attached to one container.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ContainerEnvironment {
    pub(crate) values: ValueMap,
    pub(crate) span: SourceSpan,
}

impl ContainerEnvironment {
    /// Returns source-ordered environment variable entries.
    pub const fn values(&self) -> &ValueMap {
        &self.values
    }

    /// Returns the exact source span covering the environment mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Source-ordered scalar values used by `ports` and `volumes`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ContainerSequence {
    pub(crate) values: Vec<ScalarValue>,
    pub(crate) span: SourceSpan,
}

impl ContainerSequence {
    /// Returns the source-ordered scalar specifications.
    pub fn values(&self) -> &[ScalarValue] {
        &self.values
    }

    /// Returns the exact source span covering the sequence.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// One named service container attached to a step-based job.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct JobService {
    pub(crate) id: Spanned<String>,
    pub(crate) container: JobContainer,
    pub(crate) span: SourceSpan,
}

impl JobService {
    /// Returns the source-bound service identifier used as its network alias.
    pub fn id(&self) -> &Spanned<String> {
        &self.id
    }

    /// Returns the service container source model.
    pub const fn container(&self) -> &JobContainer {
        &self.container
    }

    /// Returns the exact source span covering this service entry.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Source-ordered service containers attached to a job.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct JobServices {
    pub(crate) entries: Vec<JobService>,
    pub(crate) span: SourceSpan,
}

impl JobServices {
    /// Returns service containers in source order.
    pub fn entries(&self) -> &[JobService] {
        &self.entries
    }

    /// Returns whether the job declares no service containers.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of declared service containers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the exact source span covering the services mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}
