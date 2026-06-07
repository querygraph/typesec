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
}

/// The result type for task execution.
pub type TaskResult<T = ()> = Result<T, TaskError>;
