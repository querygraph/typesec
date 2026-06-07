//! # typesec-rbac
//!
//! Role-Based Access Control from YAML → typed policy enforcement.
//!
//! ## YAML → Types → Compile-time Safety
//!
//! The pipeline has two phases:
//!
//! 1. **Runtime**: Parse the YAML policy, build an [`RbacEngine`] that implements
//!    [`PolicyEngine`]. This handles *dynamic* role assignments and resource globs
//!    that can't be known at compile time.
//!
//! 2. **Codegen** (optional, via `typesec generate`): Emit Rust source code with
//!    concrete role structs and `Permission` impls. These let the compiler verify
//!    that your code uses permissions that actually exist in the policy file.
//!
//! ## YAML Schema
//!
//! ```yaml
//! roles:
//!   - name: analyst
//!     permissions: [read, read_sensitive]
//!     resources: ["reports/*", "metrics/*"]
//!   - name: admin
//!     inherits: [analyst]
//!     permissions: [write, delete, delegate]
//!     resources: ["*"]
//!
//! assignments:
//!   - subject: "agent:data-pipeline"
//!     roles: [analyst]
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod codegen;
pub mod engine;
pub mod model;

pub use engine::RbacEngine;
pub use model::{Assignment, RbacPolicy, RoleDefinition};
