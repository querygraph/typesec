//! Errors from capability acquisition.

use std::error::Error;
use std::fmt;

/// Error type for capability acquisition failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CapabilityError {
    /// Policy explicitly denied the request.
    #[error("access denied: {reason}")]
    Denied {
        /// The denial reason from the policy engine.
        reason: String,
    },
    /// The engine delegated but no upstream engine was configured.
    #[error("policy delegation without an upstream engine")]
    UnhandledDelegation,
    /// An internal engine error (I/O, parse failure, etc.).
    #[error("policy engine error: {0}")]
    EngineError(#[source] Box<dyn Error + Send + Sync>),
}

impl CapabilityError {
    /// Wrap a human-readable engine failure while preserving an error source.
    pub fn engine_error(message: impl Into<String>) -> Self {
        Self::EngineError(Box::new(EngineMessageError(message.into())))
    }

    /// Wrap an existing engine failure source.
    pub fn engine_error_source(error: impl Error + Send + Sync + 'static) -> Self {
        Self::EngineError(Box::new(error))
    }
}

#[derive(Debug)]
struct EngineMessageError(String);

impl fmt::Display for EngineMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for EngineMessageError {}
