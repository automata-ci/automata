#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyError {
    Usage,
    Configuration,
    Bind,
    Runtime,
    Status,
}

impl ProxyError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Usage => "usage-invalid",
            Self::Configuration => "configuration-invalid",
            Self::Bind => "bind-failed",
            Self::Runtime => "runtime-failed",
            Self::Status => "status-failed",
        }
    }
}
