//! # typesec-macro
//!
//! Procedural macros for the typesec ecosystem.
//!
//! ## `#[derive(TypesecRole)]`
//!
//! Derive the [`Role`][typesec_core::role::Role] trait for a struct, pulling
//! permissions and resource patterns from the `#[role(...)]` attribute:
//!
//! ```rust,ignore
//! use typesec_macro::TypesecRole;
//!
//! #[derive(TypesecRole)]
//! #[role(permissions = "read,write", resources = "code/*,infra/*")]
//! pub struct Engineer;
//! ```
//!
//! Expands to:
//!
//! ```rust,ignore
//! impl typesec_core::role::Role for Engineer {
//!     fn name() -> &'static str { "engineer" }
//!     fn permission_names() -> &'static [&'static str] { &["read", "write"] }
//!     fn resource_patterns() -> &'static [&'static str] { &["code/*", "infra/*"] }
//! }
//! ```
//!
//! ## `policy!` macro
//!
//! Inline role definitions without a YAML file:
//!
//! ```rust,ignore
//! use typesec_macro::policy;
//!
//! policy! {
//!     role Analyst {
//!         can [read, read_sensitive] on ["reports/*", "metrics/*"];
//!     }
//!     role LeadAnalyst extends Analyst {
//!         can [write] on ["reports/drafts/*"];
//!     }
//! }
//! ```
//!
//! The macro internals are split across [`shared`] (permission validation and
//! name casing), [`role_derive`] (the derive expansion), and [`policy_dsl`] (the
//! `policy!` parser and codegen).

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod policy_dsl;
mod role_derive;
mod shared;

/// Derive the `typesec_core::role::Role` trait.
///
/// Requires a `#[role(permissions = "...", resources = "...")]` attribute.
#[proc_macro_derive(TypesecRole, attributes(role))]
pub fn derive_typesec_role(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match role_derive::derive_typesec_role_impl(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Inline policy macro.
///
/// ```rust,ignore
/// policy! {
///     role Analyst {
///         can [read, read_sensitive] on ["reports/*"];
///     }
///     role Engineer extends Analyst {
///         can [write, execute] on ["code/*"];
///     }
/// }
/// ```
///
/// Expands each `role X { ... }` block to a struct + `Role` impl.
#[proc_macro]
pub fn policy(input: TokenStream) -> TokenStream {
    match policy_dsl::policy_impl(input.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[cfg(test)]
mod tests;
