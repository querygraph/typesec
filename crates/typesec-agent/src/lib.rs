//! # typesec-agent
//!
//! Agent executor: typestate + capability-based access control in action.
//!
//! This crate provides the high-level [`SecureAgent`] API that ties together:
//! - The typestate machine from `typesec-core` (unauthenticated → authenticated).
//! - Runtime policy checking via any [`PolicyEngine`].
//! - Typed capability acquisition: the *only* way to get a `Capability<P, R>` is
//!   through a successful policy check.
//! - Async task execution: the `execute` method requires a capability as proof.
//!
//! ## Usage Pattern
//!
//! ```rust,ignore
//! // 1. Create agent with an engine — starts Unauthenticated.
//! let agent = SecureAgent::new(Arc::new(rbac_engine));
//!
//! // 2. Authenticate — type transitions to Authenticated.
//! let agent = agent.authenticate_unverified(Credentials::new("agent:bot", "token"))?;
//!
//! // 3. Request a capability — policy checked at runtime, cap minted on success.
//! let report = Report::new("reports/q1");
//! let cap: Capability<CanRead, Report> = agent.request_capability(&report).await?;
//!
//! // 4. Execute — cap is required proof. No cap? Won't compile.
//! agent.execute(&cap, &report, |r| Box::pin(async move {
//!     println!("reading: {}", r.id);
//!     Ok(())
//! })).await?;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod agent;
pub mod executor;
pub mod tool;

pub use agent::{AgentBuilder, SecureAgent};
pub use executor::TaskResult;
pub use tool::{ProtectedTool, ToolFuture, ToolSpec};

// Re-export core types for convenience.
pub use typesec_core::{
    CanDelete, CanExecute, CanRead, CanReadInternal, CanWrite, Capability, Credentials, Permission,
    Resource,
};
