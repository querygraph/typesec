//! # typesec-core
//!
//! Foundational trait library for type-level security enforcement.
//!
//! ## The Core Idea
//!
//! Security policies encoded in types are enforced by the *compiler*, not by
//! conditional checks at runtime. If an agent type doesn't carry the trait bound
//! `HasCapability<CanWrite, Report>`, the method simply doesn't exist in its API.
//! There is no path to a runtime permission error — the program won't compile.
//!
//! This is fundamentally different from guard-based approaches:
//!
//! ```text
//! // Guard-based (runtime check — can be forgotten, bypassed, skipped):
//! if acl.check(user, "write", resource) {
//!     resource.write(data)
//! }
//!
//! // Type-level (compile-time check — impossible to bypass):
//! fn write<P: HasPermission<CanWrite>>(agent: &Agent<P>, cap: Capability<CanWrite, R>) {
//!     // cap's existence IS the proof. No check needed.
//! }
//! ```
//!
//! ## Key Abstractions
//!
//! - [`Permission`] — zero-sized marker trait; each permission is a distinct type.
//! - [`Capability`] — unforgeable proof token: `Capability<P, R>` proves the bearer
//!   holds permission `P` on resource `R`. The phantom types make
//!   `Capability<CanRead, Report>` and `Capability<CanWrite, Report>` *different types*.
//! - [`Agent`] — typestate machine: `Agent<Unauthenticated>` → `Agent<Authenticated>`.
//!   Authenticated methods are literally absent on the unauthenticated state.
//! - [`PolicyEngine`] — the runtime bridge: dynamic policies (RBAC, ODRL) evaluated
//!   once, their result minted into an unforgeable [`Capability`].

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod capability;
pub mod combinator;
pub mod lattice;
pub mod permissions;
pub mod policy;
pub mod resource;
pub mod role;
pub mod typestate;

// Re-export the most important types at crate root.
pub use capability::Capability;
pub use combinator::{CombineStrategy, ComposedEngine, PolicyEngineBuilder};
pub use lattice::{Implies, LatticeEngine};
pub use permissions::{
    AiCanExfiltrate, AiCanInfer, AiCanTrain, CanDelegate, CanDelete, CanExecute, CanRead,
    CanReadSensitive, CanWrite, CanWriteSensitive, Permission,
};
pub use policy::{AuditEvent, FallbackEngine, PolicyEngine, PolicyResult, mint_capability};
pub use resource::Resource;
pub use role::Role;
pub use typestate::{Agent, AgentState, Authenticated, Credentials, Unauthenticated};
