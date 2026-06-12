//! Task execution infrastructure.

/// Error type for task execution failures.
#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    /// The action itself returned an error.
    #[error("task error: {0}")]
    ActionFailed(String),
    /// A capability was required but could not be obtained.
    #[error("capability error: {0}")]
    Capability(#[from] typesec_core::policy::CapabilityError),
    /// The supplied capability has expired.
    #[error("capability expired: {0}")]
    CapabilityExpired(#[from] typesec_core::CapabilityUseError),
    /// The supplied capability does not cover this agent or resource instance.
    #[error("capability mismatch: {0}")]
    CapabilityMismatch(String),
}

/// The result type for task execution.
pub type TaskResult<T = ()> = Result<T, TaskError>;
