//! Shared harness and fixtures for the typesec integration tests.
//!
//! Holds the audit-capture tracing harness, the YAML policy fixtures, and the
//! `check_engine` helpers used across the themed integration test files.

use std::sync::{Arc, Mutex, OnceLock};

use tracing::{Event, Subscriber};
use tracing_subscriber::{
    Layer, Registry,
    layer::{Context, SubscriberExt},
};
use typesec_core::{PolicyEngine, RequestContext, ResourceId, SubjectId, policy::PolicyResult};

pub fn check_engine<E: PolicyEngine + ?Sized>(
    engine: &E,
    subject: &str,
    action: &str,
    resource: &str,
) -> PolicyResult {
    engine.check(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
    )
}

pub fn check_engine_with_context<E: PolicyEngine + ?Sized>(
    engine: &E,
    subject: &str,
    action: &str,
    resource: &str,
    context: &RequestContext,
) -> PolicyResult {
    engine.check_with_context(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
        context,
    )
}

// ── RBAC policy for tests 1-3 ─────────────────────────────────────────────────

/// RBAC policy: `agent:analyst` can read `reports/*`.
pub const RBAC_ANALYST: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

/// RBAC policy: `agent:writer` can write (but NOT read directly) `data/*`.
pub const RBAC_WRITER_ONLY: &str = r#"
roles:
  - name: writer
    permissions: [write]
    resources: ["data/*"]
assignments:
  - subject: "agent:writer"
    roles: [writer]
"#;

// ── ODRL policies for tests 4-7 ──────────────────────────────────────────────

/// ODRL: `agent:reader` may read `reports/q1` before `expiry_date`.
pub fn odrl_with_expiry(expiry_date: &str) -> String {
    format!(
        r#"
policies:
  - uid: "policy:timed-read"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:reader"
        action: read
        target: "reports/q1"
        constraints:
          - leftOperand: dateTime
            operator: lt
            rightOperand: "{expiry_date}"
"#
    )
}

/// ODRL: `agent:analyst` may read `reports/q1` only with purpose=analytics.
pub const ODRL_PURPOSE: &str = r#"
policies:
  - uid: "policy:purpose-read"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:analyst"
        action: read
        target: "reports/q1"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "analytics"
"#;

/// RBAC: `agent:combinator` can read `shared/data`.
pub const RBAC_ALLOW_READ: &str = r#"
roles:
  - name: reader
    permissions: [read]
    resources: ["shared/*"]
assignments:
  - subject: "agent:combinator"
    roles: [reader]
"#;

/// ODRL: `agent:combinator` is PROHIBITED from reading `shared/data`.
pub const ODRL_PROHIBIT_READ: &str = r#"
policies:
  - uid: "policy:prohibit-read"
    type: Set
    rules:
      - type: prohibition
        assignee: "agent:combinator"
        action: read
        target: "shared/data"
"#;

/// ODRL: `agent:odrl-only` is permitted to read `private/data`.
pub const ODRL_PERMIT_READ: &str = r#"
policies:
  - uid: "policy:odrl-permit"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:odrl-only"
        action: read
        target: "private/data"
"#;

/// ODRL: `agent:combinator` may read `shared/data`.
pub const ODRL_ALLOW_SHARED_READ: &str = r#"
policies:
  - uid: "policy:shared-permit"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:combinator"
        action: read
        target: "shared/data"
"#;

/// ODRL: `agent:combinator` is prohibited from training-purpose reads.
pub const ODRL_PROHIBIT_TRAINING_READ: &str = r#"
policies:
  - uid: "policy:training-prohibit"
    type: Set
    rules:
      - type: prohibition
        assignee: "agent:combinator"
        action: read
        target: "shared/data"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "training"
"#;

/// RBAC: has no rules for `agent:odrl-only` (they're not assigned any role).
pub const RBAC_NO_RULES: &str = r#"
roles: []
assignments: []
"#;

// ── Audit capture helpers ─────────────────────────────────────────────────────

/// A captured tracing event as a flat string `"field=value;field=value"`.
pub type EventRecord = String;

/// Thread-safe store for captured tracing events.
#[derive(Default, Clone)]
pub struct AuditCapture(Arc<Mutex<Vec<EventRecord>>>);

impl AuditCapture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<EventRecord> {
        self.0.lock().unwrap().clone()
    }

    /// True if any captured event contains `key=value` in its fields.
    pub fn has_field(&self, key: &str, value: &str) -> bool {
        let target = format!("{key}={value}");
        self.records().iter().any(|r| r.contains(&target))
    }
}

/// Tracing [`Layer`] that appends a flat field-string per event to `AuditCapture`.
pub struct CaptureLayer(pub AuditCapture);

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        struct Visitor(Vec<(String, String)>);
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push((f.name().to_owned(), format!("{v:?}")));
            }
            fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                self.0.push((f.name().to_owned(), v.to_owned()));
            }
        }
        let mut vis = Visitor(vec![]);
        event.record(&mut vis);
        let record = vis
            .0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";");
        self.0.0.lock().unwrap().push(record);
    }
}

/// Install a per-test tracing subscriber that captures audit events.
///
/// Returns the `AuditCapture` store and a `DefaultGuard` that must be held for
/// the duration of the test (dropped at end of scope).
pub fn install_capture_subscriber() -> AuditCapture {
    static CAPTURE: OnceLock<AuditCapture> = OnceLock::new();

    let capture = CAPTURE
        .get_or_init(|| {
            let capture = AuditCapture::new();
            let layer = CaptureLayer(capture.clone());
            let subscriber = Registry::default().with(layer);
            let _ = tracing::subscriber::set_global_default(subscriber);
            tracing::callsite::rebuild_interest_cache();
            capture
        })
        .clone();

    capture.0.lock().unwrap().clear();
    capture
}
