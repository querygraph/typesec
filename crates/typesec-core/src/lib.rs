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
//! - [`SecureValue`] — an opaque labeled value that supports safe transformations
//!   while requiring typed authority to reveal or declassify protected data.
//! - [`Agent`] — typestate machine: `Agent<Unauthenticated>` → `Agent<Authenticated>`.
//!   Authenticated methods are literally absent on the unauthenticated state.
//! - [`PolicyEngine`] — the runtime bridge: dynamic policies (RBAC, ODRL) evaluated
//!   once, their result minted into an unforgeable [`Capability`].

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod capability;
pub mod combinator;
pub mod glob;
pub mod lattice;
pub mod permissions;
pub mod policy;
pub mod resource;
pub mod role;
pub mod secure_value;
mod string_id;
pub mod typestate;

// Re-export the most important types at crate root.
pub use capability::{
    Capability, CapabilityId, CapabilityRevocationList, CapabilityUseError, DEFAULT_CAPABILITY_TTL,
    RevocationEpoch,
};
pub use combinator::{CombineStrategy, ComposedEngine, PolicyEngineBuilder};
pub use glob::{GlobPattern, is_glob_pattern};
pub use lattice::{Implies, LatticeEngine};
pub use permissions::{
    AiCanExfiltrate, AiCanInfer, AiCanTrain, CanDeclassify, CanDelegate, CanDelete, CanExecute,
    CanRead, CanReadInternal, CanReadSensitive, CanWrite, CanWriteSensitive, Permission,
};
pub use policy::{
    AsyncPolicyEngine, AuditEvent, AuditFuture, AuditSink, AuditTimestamp, CapabilityError,
    DelegationReason, FallbackEngine, MintOptions, PolicyEngine, PolicyFuture, PolicyResult,
    RequestContext, SubjectId, TracingAuditSink, format_audit_timestamp, mint_capability,
    mint_capability_async, mint_capability_for_id, mint_capability_for_id_async,
    mint_capability_with, mint_capability_with_async, set_audit_sink,
};
pub use resource::{GenericResource, Resource, ResourceId};
pub use role::Role;
pub use secure_value::{
    Internal, Join, PrivacyLevel, Public, Secret, SecureAccessError, SecureValue, SecureValueError,
    Sensitive,
};
pub use typestate::{
    Agent, AgentError, AgentState, Authenticated, Authenticator, Credentials, Token,
    Unauthenticated,
};
