//! # typesec
//!
//! Type-level security capabilities for Rust agents.
//!
//! This facade crate re-exports the core capability model by default and exposes
//! the policy engines, agent API, and macros behind feature flags.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub use typesec_core::*;

/// Agent executor API.
#[cfg(feature = "agent")]
pub mod agent {
    pub use typesec_agent::*;
}

/// ODRL policy engine.
#[cfg(feature = "odrl")]
pub mod odrl {
    pub use typesec_odrl::*;
}

/// RBAC policy engine.
#[cfg(feature = "rbac")]
pub mod rbac {
    pub use typesec_rbac::*;
}

/// Procedural macros.
#[cfg(feature = "macros")]
pub mod macros {
    pub use typesec_macro::*;
}

#[cfg(feature = "agent")]
pub use typesec_agent::{AgentBuilder, SecureAgent, TaskResult};
#[cfg(feature = "odrl")]
pub use typesec_odrl::OdrlEngine;
#[cfg(feature = "rbac")]
pub use typesec_rbac::RbacEngine;
