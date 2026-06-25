//! Policy engine trait and audit trail types.
//!
//! [`PolicyEngine`] is the *runtime bridge* between dynamic policies (YAML files,
//! database records, external services) and compile-time type safety.
//!
//! ## Flow
//!
//! ```text
//! Agent::request_capability::<CanWrite, Report>(&report)
//!   │
//!   ├─ engine.check(subject, "write", resource_id)
//!   │     └─ RbacEngine / OdrlEngine evaluates rules
//!   │
//!   ├─ PolicyResult::Allow
//!   │     └─ Capability::new_minted(...)   ← only path to a valid cap
//!   │
//!   └─ PolicyResult::Deny(reason)
//!         └─ Err(CapabilityError::Denied { reason })
//! ```
//!
//! Every `check()` call is recorded as an [`AuditEvent`] through the configured
//! [`AuditSink`]. The default sink emits via `tracing` — attach a structured
//! subscriber to ship these to any SIEM, or install a custom sink with
//! [`set_audit_sink`] for a guaranteed write path.
//!
//! This module is split into focused submodules — [`result`], [`error`],
//! [`audit`], [`mint`], [`fallback`], and the subject newtype — re-exported here
//! so the public surface stays at `typesec_core::policy::*`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::ResourceId;

mod audit;
mod error;
mod fallback;
mod mint;
mod result;
mod subject;

pub use audit::{
    AuditEvent, AuditSink, AuditTimestamp, TracingAuditSink, format_audit_timestamp, set_audit_sink,
};
// Crate-internal: used by the mint path and the policy tests.
pub(crate) use audit::{now_utc, record_audit, record_audit_async};
pub use error::CapabilityError;
pub use fallback::FallbackEngine;
pub use mint::{
    MintOptions, mint_capability, mint_capability_async, mint_capability_for_id,
    mint_capability_for_id_async, mint_capability_with, mint_capability_with_async,
};
pub use result::{DelegationReason, PolicyResult, RequestContext};
pub use subject::SubjectId;

/// Boxed async policy-decision future.
pub type PolicyFuture<'a> = Pin<Box<dyn Future<Output = PolicyResult> + Send + 'a>>;

/// Boxed async audit-recording future.
pub type AuditFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// The core runtime policy interface.
///
/// Implementors (e.g., `RbacEngine`, `OdrlEngine`) evaluate a
/// (subject, action, resource, context) request against their policy set and
/// return a [`PolicyResult`].
///
/// Every implementation *must* emit an [`AuditEvent`] via `tracing` for every check.
///
/// # Object safety
///
/// `PolicyEngine` is object-safe (`dyn PolicyEngine` is valid). Generic helpers
/// such as [`mint_capability`] are provided as free functions rather than trait
/// methods to preserve object safety.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate whether `subject` may perform `action` on `resource`.
    ///
    /// # Arguments
    ///
    /// * `subject` — agent identity, e.g., `"agent:summarizer"`.
    /// * `action` — permission name, e.g., `"read"` (matches
    ///   [`Permission::name`][crate::Permission::name]).
    /// * `resource` — resource identifier, e.g., `"reports/q1"`.
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult;

    /// Evaluate whether `subject` may perform `action` on `resource`
    /// asynchronously.
    ///
    /// The default implementation calls the synchronous [`check`][Self::check]
    /// method. IO-bound engines can override this method to avoid blocking an
    /// async executor.
    fn check_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
    ) -> PolicyFuture<'a> {
        Box::pin(async move { self.check(subject, action, resource) })
    }

    /// Evaluate a request with runtime context.
    ///
    /// Engines that do not use contextual constraints can rely on this default.
    fn check_with_context(
        &self,
        subject: &SubjectId,
        action: &str,
        resource: &ResourceId,
        _ctx: &RequestContext,
    ) -> PolicyResult {
        self.check(subject, action, resource)
    }

    /// Evaluate a request with runtime context asynchronously.
    ///
    /// The default implementation calls the synchronous
    /// [`check_with_context`][Self::check_with_context] method. Context-aware
    /// IO-bound engines can override this method directly.
    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a> {
        Box::pin(async move { self.check_with_context(subject, action, resource, ctx) })
    }

    /// Compose this engine with a fallback.
    ///
    /// If this engine returns [`PolicyResult::Delegate`], the fallback is tried.
    fn with_fallback(self, fallback: Arc<dyn PolicyEngine>) -> FallbackEngine<Self>
    where
        Self: Sized,
    {
        FallbackEngine {
            primary: self,
            fallback,
        }
    }
}

/// Async companion interface for policy engines.
///
/// Every [`PolicyEngine`] implements this trait through a blanket
/// implementation. It is useful for generic code that wants to name the async
/// policy surface explicitly.
pub trait AsyncPolicyEngine: Send + Sync {
    /// Evaluate whether `subject` may perform `action` on `resource`
    /// asynchronously.
    fn check_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
    ) -> PolicyFuture<'a>;

    /// Evaluate a request with runtime context asynchronously.
    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a>;
}

impl<T: PolicyEngine + ?Sized> AsyncPolicyEngine for T {
    fn check_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
    ) -> PolicyFuture<'a> {
        PolicyEngine::check_async(self, subject, action, resource)
    }

    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a SubjectId,
        action: &'a str,
        resource: &'a ResourceId,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a> {
        PolicyEngine::check_with_context_async(self, subject, action, resource, ctx)
    }
}

#[cfg(test)]
mod tests;
