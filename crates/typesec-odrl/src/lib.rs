//! # typesec-odrl
//!
//! ODRL (Open Digital Rights Language, W3C) policy engine.
//!
//! ODRL is a richer policy model than RBAC — rules can carry *constraints*
//! that are evaluated at check time (e.g., "only allowed before 2027-01-01",
//! "only for purpose=analytics"). This makes ODRL well-suited to AI agent
//! scenarios where access is conditional on context, not just identity.
//!
//! ## ODRL Concepts
//!
//! - **Policy** — container, has a UID and type (`Set`, `Offer`, `Agreement`).
//! - **Rule** — a `permission`, `prohibition`, or `duty`.
//! - **Action** — what the rule applies to (maps to our `Permission::name()`).
//! - **Constraint** — a runtime condition that must hold for the rule to apply.
//!
//! ## Audit Trail
//!
//! Every `check()` call emits a structured `tracing::info!` event with the
//! policy UID, rule type, constraint evaluation results, and final verdict.
//! This gives a full audit trail for compliance and forensics.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod audit;
pub mod constraint;
pub mod engine;
pub mod model;

pub use engine::OdrlEngine;
pub use model::{
    ConstraintOperand, OdrlConstraint, OdrlPolicy, OdrlRule, OdrlRuleType, RuleAction,
};
