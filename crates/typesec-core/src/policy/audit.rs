//! The audit trail: structured records of every policy decision.

use std::sync::{Arc, OnceLock, RwLock};

use chrono::{DateTime, SecondsFormat, Utc};
use tracing::{info, warn};

use crate::{ResourceId, SubjectId};

use super::{AuditFuture, PolicyResult};

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
    pub subject: SubjectId,
    /// The action being requested (e.g., `"write"`).
    pub action: String,
    /// The resource being accessed.
    pub resource: ResourceId,
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
/// All subsequent [`mint_capability`][crate::mint_capability] decisions are
/// recorded through `sink`.
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

/// The current UTC time, used to stamp audit events at mint time.
pub(crate) fn now_utc() -> AuditTimestamp {
    Utc::now()
}
