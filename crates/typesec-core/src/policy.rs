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
//!   │     └─ Capability::new_unchecked(...)   ← only path to a valid cap
//!   │
//!   └─ PolicyResult::Deny(reason)
//!         └─ Err(CapabilityError::Denied { reason })
//! ```
//!
//! Every `check()` call is recorded as an [`AuditEvent`] through the configured
//! [`AuditSink`]. The default sink emits via `tracing` — attach a structured
//! subscriber to ship these to any SIEM, or install a custom sink with
//! [`set_audit_sink`] for a guaranteed write path.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use tracing::{info, warn};

use crate::capability::{DEFAULT_CAPABILITY_TTL, RevocationEpoch};
use crate::{Capability, Permission, Resource};

/// Boxed async policy-decision future.
pub type PolicyFuture<'a> = Pin<Box<dyn Future<Output = PolicyResult> + Send + 'a>>;

/// Boxed async audit-recording future.
pub type AuditFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// The verdict returned by a policy engine.
#[must_use = "policy decisions must be checked; an ignored result is a silent allow/deny"]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyResult {
    /// The action is allowed. The engine may provide a rationale.
    Allow,
    /// The action is denied. The string explains why (for audit logs / UX).
    Deny(String),
    /// The engine cannot make a decision; defer to another engine.
    ///
    /// Used in policy composition: e.g., an ODRL engine delegates to RBAC
    /// for actions not covered by any ODRL rule.
    Delegate(DelegationReason),
}

impl PolicyResult {
    /// Build a structured delegation decision.
    pub fn delegate(engine: &'static str, reason: impl Into<String>) -> Self {
        Self::Delegate(DelegationReason::new(engine, reason))
    }
}

/// Structured explanation for an unresolved policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationReason {
    /// Engine that delegated.
    pub engine: &'static str,
    /// Why this engine could not decide.
    pub reason: String,
    /// Optional extra context about the delegation path.
    pub context: Option<String>,
}

impl DelegationReason {
    /// Create a delegation reason without extra context.
    pub fn new(engine: &'static str, reason: impl Into<String>) -> Self {
        Self {
            engine,
            reason: reason.into(),
            context: None,
        }
    }

    /// Attach additional path/context detail.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

impl fmt::Display for DelegationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            Some(context) => write!(f, "{}: {} ({context})", self.engine, self.reason),
            None => write!(f, "{}: {}", self.engine, self.reason),
        }
    }
}

impl std::fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny(reason) => write!(f, "deny: {reason}"),
            Self::Delegate(reason) => write!(f, "delegate: {reason}"),
        }
    }
}

/// Runtime context attached to a policy decision request.
///
/// Plain RBAC-style engines can ignore this. Constraint-aware engines, such as
/// ODRL, use it for values that are only known at request time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestContext {
    /// Purpose for this access request, such as `"analytics"` or `"audit"`.
    pub purpose: Option<String>,
    /// Custom context values keyed by constraint operand name.
    pub custom: HashMap<String, String>,
}

impl RequestContext {
    /// Create an empty request context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add purpose context.
    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Add a custom key-value pair.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

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

/// UTC timestamp used in audit records.
pub type AuditTimestamp = DateTime<Utc>;

/// Format an audit timestamp as RFC 3339 with millisecond precision.
pub fn format_audit_timestamp(timestamp: &AuditTimestamp) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// A structured record of every policy decision.
///
/// Emitted via `tracing::info!` so it integrates with any structured log pipeline.
#[derive(Debug)]
pub struct AuditEvent {
    /// The agent making the request.
    pub subject: String,
    /// The action being requested (e.g., `"write"`).
    pub action: String,
    /// The resource being accessed.
    pub resource: String,
    /// The engine's verdict.
    pub result: PolicyResult,
    /// UTC timestamp.
    pub timestamp: AuditTimestamp,
}

impl AuditEvent {
    /// Log this event via `tracing::info!`.
    pub fn log(&self) {
        match &self.result {
            PolicyResult::Allow => info!(
                subject = %self.subject,
                action = %self.action,
                resource = %self.resource,
                verdict = "allow",
                ts = %format_audit_timestamp(&self.timestamp),
                "policy decision"
            ),
            PolicyResult::Deny(reason) => info!(
                subject = %self.subject,
                action = %self.action,
                resource = %self.resource,
                verdict = "deny",
                reason = %reason,
                ts = %format_audit_timestamp(&self.timestamp),
                "policy decision"
            ),
            PolicyResult::Delegate(to) => info!(
                subject = %self.subject,
                action = %self.action,
                resource = %self.resource,
                verdict = "delegate",
                engine = %to.engine,
                reason = %to.reason,
                context = ?to.context,
                ts = %format_audit_timestamp(&self.timestamp),
                "policy decision"
            ),
        }
    }
}

/// Destination for audit events.
///
/// The default sink ([`TracingAuditSink`]) logs through `tracing`, which is
/// best-effort: with no subscriber installed the trail silently vanishes.
/// Security-sensitive deployments should install a sink with a durable write
/// path (file, database, SIEM forwarder) via [`set_audit_sink`].
pub trait AuditSink: Send + Sync {
    /// Record one policy decision.
    fn record(&self, event: &AuditEvent);

    /// Record one policy decision asynchronously.
    ///
    /// The default implementation delegates to [`record`][Self::record], so
    /// existing synchronous sinks remain valid. Durable sinks that write to an
    /// async database, queue, or HTTP client can override this method.
    fn record_async<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
        Box::pin(async move {
            self.record(event);
        })
    }
}

/// Default [`AuditSink`] that emits events via `tracing::info!`.
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: &AuditEvent) {
        event.log();
    }
}

fn audit_sink_cell() -> &'static RwLock<Arc<dyn AuditSink>> {
    static SINK: OnceLock<RwLock<Arc<dyn AuditSink>>> = OnceLock::new();
    SINK.get_or_init(|| RwLock::new(Arc::new(TracingAuditSink)))
}

/// Install a process-wide audit sink, replacing the previous one.
///
/// All subsequent [`mint_capability`] decisions are recorded through `sink`.
pub fn set_audit_sink(sink: Arc<dyn AuditSink>) {
    let mut guard = audit_sink_cell().write().unwrap_or_else(|poisoned| {
        warn!("audit sink lock was poisoned; recovering inner sink");
        poisoned.into_inner()
    });
    *guard = sink;
}

/// Record an event through the configured audit sink.
pub(crate) fn record_audit(event: &AuditEvent) {
    let guard = audit_sink_cell().read().unwrap_or_else(|poisoned| {
        warn!("audit sink lock was poisoned; recovering inner sink");
        poisoned.into_inner()
    });
    guard.record(event);
}

/// Record an event asynchronously through the configured audit sink.
pub(crate) async fn record_audit_async(event: &AuditEvent) {
    let sink = {
        let guard = audit_sink_cell().read().unwrap_or_else(|poisoned| {
            warn!("audit sink lock was poisoned; recovering inner sink");
            poisoned.into_inner()
        });
        Arc::clone(&guard)
    };
    sink.record_async(event).await;
}

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
    /// * `action` — permission name, e.g., `"read"` (matches [`Permission::name()`]).
    /// * `resource` — resource identifier, e.g., `"reports/q1"`.
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult;

    /// Evaluate whether `subject` may perform `action` on `resource`
    /// asynchronously.
    ///
    /// The default implementation calls the synchronous [`check`][Self::check]
    /// method. IO-bound engines can override this method to avoid blocking an
    /// async executor.
    fn check_async<'a>(
        &'a self,
        subject: &'a str,
        action: &'a str,
        resource: &'a str,
    ) -> PolicyFuture<'a> {
        Box::pin(async move { self.check(subject, action, resource) })
    }

    /// Evaluate a request with runtime context.
    ///
    /// Engines that do not use contextual constraints can rely on this default.
    fn check_with_context(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
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
        subject: &'a str,
        action: &'a str,
        resource: &'a str,
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
        subject: &'a str,
        action: &'a str,
        resource: &'a str,
    ) -> PolicyFuture<'a>;

    /// Evaluate a request with runtime context asynchronously.
    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a str,
        action: &'a str,
        resource: &'a str,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a>;
}

impl<T: PolicyEngine + ?Sized> AsyncPolicyEngine for T {
    fn check_async<'a>(
        &'a self,
        subject: &'a str,
        action: &'a str,
        resource: &'a str,
    ) -> PolicyFuture<'a> {
        PolicyEngine::check_async(self, subject, action, resource)
    }

    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a str,
        action: &'a str,
        resource: &'a str,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a> {
        PolicyEngine::check_with_context_async(self, subject, action, resource, ctx)
    }
}

/// Mint a [`Capability`] by running a policy check.
///
/// This is the *only* public way to obtain a `Capability` outside `typesec-core`'s
/// test module. The engine performs the check, logs the decision, and either
/// returns a typed capability or an error.
///
/// Implemented as a free function (not a trait method) so that `PolicyEngine`
/// remains object-safe (`dyn PolicyEngine` is valid).
///
/// # Why is this the only path?
///
/// `Capability::new_unchecked` is `pub(crate)`. Only code inside `typesec-core`
/// can call it. This function is that single gated path — it calls the policy
/// engine, logs the verdict, and only creates a capability on `Allow`.
#[must_use = "capability minting can fail and the returned proof should be used"]
pub fn mint_capability<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: &str,
    resource: &R,
) -> Result<Capability<P, R>, CapabilityError> {
    mint_capability_for_id(
        engine,
        subject,
        resource.resource_id(),
        &MintOptions::default(),
    )
}

/// Async variant of [`mint_capability`].
#[must_use = "capability minting can fail and the returned proof should be used"]
pub async fn mint_capability_async<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: &str,
    resource: &R,
) -> Result<Capability<P, R>, CapabilityError> {
    let resource_id = resource.resource_id().to_owned();
    mint_capability_for_id_async(engine, subject, &resource_id, &MintOptions::default()).await
}

/// Lease parameters for capability minting.
///
/// Defaults match plain [`mint_capability`]: the
/// [`DEFAULT_CAPABILITY_TTL`] lease and no revocation binding.
#[derive(Clone, Debug)]
pub struct MintOptions {
    /// How long the minted capability stays usable. Pick per risk: a
    /// `CanDeclassify` capability warrants seconds; a low-risk read can hold
    /// the default 5 minutes or longer.
    pub ttl: Duration,
    /// Optional shared revocation epoch. Capabilities minted with one can be
    /// invalidated mid-lease by calling [`RevocationEpoch::revoke_all`]
    /// (e.g. after a policy reload).
    pub revocation: Option<RevocationEpoch>,
    /// Runtime context to pass into the policy engine while minting.
    pub context: RequestContext,
}

impl Default for MintOptions {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_CAPABILITY_TTL,
            revocation: None,
            context: RequestContext::default(),
        }
    }
}

/// Like [`mint_capability`], but with explicit lease parameters.
#[must_use = "capability minting can fail and the returned proof should be used"]
pub fn mint_capability_with<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: &str,
    resource: &R,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    mint_capability_for_id(engine, subject, resource.resource_id(), options)
}

/// Async variant of [`mint_capability_with`].
#[must_use = "capability minting can fail and the returned proof should be used"]
pub async fn mint_capability_with_async<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: &str,
    resource: &R,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    let resource_id = resource.resource_id().to_owned();
    mint_capability_for_id_async(engine, subject, &resource_id, options).await
}

/// Mint a capability for a resource identified only by its id string.
///
/// This exists for callers that only have a stable resource identifier. The
/// resulting capability is bound to `resource_id` exactly as if the `&R` form
/// had been used: every consumption site (`execute`, `reveal`, `declassify`)
/// still compares ids at use time, so naming a mismatched `R` type buys an
/// attacker nothing — the capability only covers the id the engine approved.
#[must_use = "capability minting can fail and the returned proof should be used"]
pub fn mint_capability_for_id<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: &str,
    resource_id: &str,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    let action = P::name();

    let result = engine.check_with_context(subject, action, resource_id, &options.context);

    // Emit the structured audit event for every decision, allow or deny.
    let event = AuditEvent {
        subject: subject.to_owned(),
        action: action.to_owned(),
        resource: resource_id.to_owned(),
        result: result.clone(),
        timestamp: now_utc(),
    };
    record_audit(&event);

    match result {
        PolicyResult::Allow => Ok(Capability::new_minted(
            subject,
            resource_id,
            SystemTime::now(),
            options.ttl,
            options.revocation.clone(),
        )),
        PolicyResult::Deny(reason) => Err(CapabilityError::Denied { reason }),
        PolicyResult::Delegate(_) => Err(CapabilityError::UnhandledDelegation),
    }
}

/// Async variant of [`mint_capability_for_id`].
#[must_use = "capability minting can fail and the returned proof should be used"]
pub async fn mint_capability_for_id_async<P: Permission, R: Resource>(
    engine: &dyn PolicyEngine,
    subject: &str,
    resource_id: &str,
    options: &MintOptions,
) -> Result<Capability<P, R>, CapabilityError> {
    let action = P::name();

    let result = engine
        .check_with_context_async(subject, action, resource_id, &options.context)
        .await;

    let event = AuditEvent {
        subject: subject.to_owned(),
        action: action.to_owned(),
        resource: resource_id.to_owned(),
        result: result.clone(),
        timestamp: now_utc(),
    };
    record_audit_async(&event).await;

    match result {
        PolicyResult::Allow => Ok(Capability::new_minted(
            subject,
            resource_id,
            SystemTime::now(),
            options.ttl,
            options.revocation.clone(),
        )),
        PolicyResult::Deny(reason) => Err(CapabilityError::Denied { reason }),
        PolicyResult::Delegate(_) => Err(CapabilityError::UnhandledDelegation),
    }
}

/// A two-engine fallback: tries `primary` first, then `fallback` on delegation.
///
/// Created via [`PolicyEngine::with_fallback`].
/// For multi-engine composition with configurable strategies, use
/// [`crate::combinator::ComposedEngine`] and [`crate::combinator::PolicyEngineBuilder`].
pub struct FallbackEngine<P: PolicyEngine> {
    primary: P,
    fallback: Arc<dyn PolicyEngine>,
}

impl<P: PolicyEngine> PolicyEngine for FallbackEngine<P> {
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
        self.check_with_context(subject, action, resource, &RequestContext::default())
    }

    fn check_with_context(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        ctx: &RequestContext,
    ) -> PolicyResult {
        match self
            .primary
            .check_with_context(subject, action, resource, ctx)
        {
            PolicyResult::Delegate(_) => self
                .fallback
                .check_with_context(subject, action, resource, ctx),
            other => other,
        }
    }

    fn check_with_context_async<'a>(
        &'a self,
        subject: &'a str,
        action: &'a str,
        resource: &'a str,
        ctx: &'a RequestContext,
    ) -> PolicyFuture<'a> {
        Box::pin(async move {
            match self
                .primary
                .check_with_context_async(subject, action, resource, ctx)
                .await
            {
                PolicyResult::Delegate(_) => {
                    self.fallback
                        .check_with_context_async(subject, action, resource, ctx)
                        .await
                }
                other => other,
            }
        })
    }
}

fn now_utc() -> AuditTimestamp {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{permissions::CanRead, resource::GenericResource};

    struct AllowAll;
    impl PolicyEngine for AllowAll {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
            PolicyResult::Allow
        }
    }

    struct DenyAll;
    impl PolicyEngine for DenyAll {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
            PolicyResult::Deny("DenyAll engine".into())
        }
    }

    struct AsyncAllowOnly;
    impl PolicyEngine for AsyncAllowOnly {
        fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
            PolicyResult::Deny("sync path should not be used".into())
        }

        fn check_with_context_async<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a str,
            _: &'a RequestContext,
        ) -> PolicyFuture<'a> {
            Box::pin(async { PolicyResult::Allow })
        }
    }

    #[test]
    fn allow_all_mints_capability() {
        let engine = AllowAll;
        let resource = GenericResource::new("reports/q1", "report");
        let cap: Capability<CanRead, GenericResource> =
            mint_capability(&engine, "agent:test", &resource).expect("should allow");
        assert_eq!(cap.subject(), "agent:test");
    }

    #[test]
    fn deny_all_returns_error() {
        let engine = DenyAll;
        let resource = GenericResource::new("reports/q1", "report");
        let result: Result<Capability<CanRead, GenericResource>, _> =
            mint_capability(&engine, "agent:test", &resource);
        assert!(matches!(result, Err(CapabilityError::Denied { .. })));
    }

    #[test]
    fn async_mint_uses_async_policy_path() {
        let engine = AsyncAllowOnly;
        let resource = GenericResource::new("reports/q1", "report");

        let sync_result: Result<Capability<CanRead, GenericResource>, _> =
            mint_capability(&engine, "agent:test", &resource);
        assert!(matches!(sync_result, Err(CapabilityError::Denied { .. })));

        let async_result: Result<Capability<CanRead, GenericResource>, _> =
            futures::executor::block_on(mint_capability_async(&engine, "agent:test", &resource));
        let cap = async_result.expect("async policy path should allow");
        assert_eq!(cap.subject(), "agent:test");
        assert_eq!(cap.resource_id(), "reports/q1");
    }

    #[test]
    fn audit_sink_can_override_async_recording() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct AsyncOnlySink {
            sync_records: AtomicUsize,
            async_records: AtomicUsize,
        }

        impl AuditSink for AsyncOnlySink {
            fn record(&self, _: &AuditEvent) {
                self.sync_records.fetch_add(1, Ordering::Relaxed);
            }

            fn record_async<'a>(&'a self, _: &'a AuditEvent) -> AuditFuture<'a> {
                Box::pin(async move {
                    self.async_records.fetch_add(1, Ordering::Relaxed);
                })
            }
        }

        let sink = AsyncOnlySink {
            sync_records: AtomicUsize::new(0),
            async_records: AtomicUsize::new(0),
        };
        let event = AuditEvent {
            subject: "agent:test".into(),
            action: "read".into(),
            resource: "reports/q1".into(),
            result: PolicyResult::Allow,
            timestamp: now_utc(),
        };

        futures::executor::block_on(sink.record_async(&event));
        assert_eq!(sink.sync_records.load(Ordering::Relaxed), 0);
        assert_eq!(sink.async_records.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn mint_with_revocation_epoch_supports_mid_lease_revocation() {
        let engine = AllowAll;
        let resource = GenericResource::new("reports/q1", "report");
        let epoch = RevocationEpoch::new();
        let options = MintOptions {
            revocation: Some(epoch.clone()),
            ..MintOptions::default()
        };
        let cap: Capability<CanRead, GenericResource> =
            mint_capability_with(&engine, "agent:test", &resource, &options).expect("allow");

        cap.ensure_active().expect("active before revocation");
        epoch.revoke_all();
        assert!(cap.ensure_active().is_err());
    }

    #[test]
    fn mint_with_short_ttl_expires() {
        let engine = AllowAll;
        let resource = GenericResource::new("reports/q1", "report");
        let options = MintOptions {
            ttl: Duration::ZERO,
            ..MintOptions::default()
        };
        let cap: Capability<CanRead, GenericResource> =
            mint_capability_with(&engine, "agent:test", &resource, &options).expect("allow");
        assert!(cap.is_expired());
    }

    #[test]
    fn audit_timestamp_is_typed_and_formats_as_rfc3339() {
        let event = AuditEvent {
            subject: "agent:test".to_owned(),
            action: "read".to_owned(),
            resource: "reports/q1".to_owned(),
            result: PolicyResult::Allow,
            timestamp: Utc::now(),
        };

        let rendered = format_audit_timestamp(&event.timestamp);

        assert!(rendered.ends_with('Z'));
        assert!(rendered.contains('T'));
    }

    #[test]
    fn engine_error_preserves_source() {
        let err = CapabilityError::engine_error_source(std::io::Error::other("join failed"));

        assert!(err.source().is_some());
        assert_eq!(
            err.source().map(ToString::to_string).as_deref(),
            Some("join failed")
        );
    }

    #[test]
    fn mint_with_request_context_passes_context_to_engine() {
        struct PurposeEngine;
        impl PolicyEngine for PurposeEngine {
            fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
                PolicyResult::Deny("missing context".into())
            }

            fn check_with_context(
                &self,
                _: &str,
                _: &str,
                _: &str,
                ctx: &RequestContext,
            ) -> PolicyResult {
                if ctx.purpose.as_deref() == Some("analytics") {
                    PolicyResult::Allow
                } else {
                    PolicyResult::Deny("wrong purpose".into())
                }
            }
        }

        let resource = GenericResource::new("reports/q1", "report");
        let options = MintOptions {
            context: RequestContext::default().with_purpose("analytics"),
            ..MintOptions::default()
        };
        let cap: Capability<CanRead, GenericResource> =
            mint_capability_with(&PurposeEngine, "agent:test", &resource, &options)
                .expect("context should allow");

        assert_eq!(cap.resource_id(), "reports/q1");
    }

    #[test]
    fn composed_engine_falls_back() {
        struct DelegateAlways;
        impl PolicyEngine for DelegateAlways {
            fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
                PolicyResult::delegate("test", "fallback")
            }
        }

        let engine = DelegateAlways.with_fallback(Arc::new(AllowAll));
        let result = engine.check("agent:x", "read", "reports/q1");
        assert_eq!(result, PolicyResult::Allow);
    }
}
