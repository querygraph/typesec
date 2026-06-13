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

use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use tracing::{info, warn};

use crate::capability::{DEFAULT_CAPABILITY_TTL, RevocationEpoch};
use crate::{Capability, Permission, Resource};

/// The verdict returned by a policy engine.
#[must_use = "policy decisions must be checked; an ignored result is a silent allow/deny"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyResult {
    /// The action is allowed. The engine may provide a rationale.
    Allow,
    /// The action is denied. The string explains why (for audit logs / UX).
    Deny(String),
    /// The engine cannot make a decision; defer to another engine.
    ///
    /// Used in policy composition: e.g., an ODRL engine delegates to RBAC
    /// for actions not covered by any ODRL rule.
    Delegate(String),
}

impl std::fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny(reason) => write!(f, "deny: {reason}"),
            Self::Delegate(to) => write!(f, "delegate to {to}"),
        }
    }
}

/// Error type for capability acquisition failures.
#[derive(Debug, thiserror::Error)]
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
    EngineError(String),
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
    /// ISO-8601 timestamp.
    pub timestamp: String,
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
                ts = %self.timestamp,
                "policy decision"
            ),
            PolicyResult::Deny(reason) => info!(
                subject = %self.subject,
                action = %self.action,
                resource = %self.resource,
                verdict = "deny",
                reason = %reason,
                ts = %self.timestamp,
                "policy decision"
            ),
            PolicyResult::Delegate(to) => info!(
                subject = %self.subject,
                action = %self.action,
                resource = %self.resource,
                verdict = "delegate",
                to = %to,
                ts = %self.timestamp,
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

/// The core runtime policy interface.
///
/// Implementors (e.g., `RbacEngine`, `OdrlEngine`) evaluate a (subject, action,
/// resource) triple against their policy set and return a [`PolicyResult`].
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
}

impl Default for MintOptions {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_CAPABILITY_TTL,
            revocation: None,
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

/// Mint a capability for a resource identified only by its id string.
///
/// This exists so async callers can move owned strings onto a blocking thread
/// (the policy check may do I/O — see `SecureAgent::request_capability`)
/// without needing `R: Send` or a reference that outlives the spawn. The
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

    let result = engine.check(subject, action, resource_id);

    // Emit the structured audit event for every decision, allow or deny.
    let event = AuditEvent {
        subject: subject.to_owned(),
        action: action.to_owned(),
        resource: resource_id.to_owned(),
        result: result.clone(),
        timestamp: now_iso8601(),
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
        match self.primary.check(subject, action, resource) {
            PolicyResult::Delegate(_) => self.fallback.check(subject, action, resource),
            other => other,
        }
    }
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
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
    fn composed_engine_falls_back() {
        struct DelegateAlways;
        impl PolicyEngine for DelegateAlways {
            fn check(&self, _: &str, _: &str, _: &str) -> PolicyResult {
                PolicyResult::Delegate("fallback".into())
            }
        }

        let engine = DelegateAlways.with_fallback(Arc::new(AllowAll));
        let result = engine.check("agent:x", "read", "reports/q1");
        assert_eq!(result, PolicyResult::Allow);
    }
}
