//! Integration test suite for typesec.
//!
//! Covers all major scenarios end-to-end:
//!
//! 1. RBAC allow path — analyst reads reports/q1
//! 2. RBAC deny path  — analyst tries to write reports/q1
//! 3. Lattice promotion — write grant satisfies read requirement
//! 4. ODRL time constraint — future expiry allows, past expiry denies
//! 5. ODRL purpose constraint — matching purpose allows, wrong purpose delegates
//! 6. Combinator DenyOverrides — RBAC allow + ODRL prohibition → Deny
//! 7. Combinator AllowIfAny — RBAC deny + ODRL permission → Allow
//! 8. Typestate enforcement — documented via API design (no compile_fail harness needed)
//! 9. Audit log — structured events captured and verified per decision

use std::sync::{Arc, Mutex, OnceLock};

use chrono::{Duration, Utc};
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    Layer, Registry,
    layer::{Context, SubscriberExt},
};
use typesec_agent::SecureAgent;
use typesec_core::{
    Capability, Credentials, PolicyEngine,
    combinator::{CombineStrategy, PolicyEngineBuilder},
    lattice::LatticeEngine,
    permissions::{CanRead, CanWrite},
    policy::{PolicyResult, mint_capability},
    resource::GenericResource,
};
use typesec_odrl::{OdrlEngine, constraint::ConstraintContext};
use typesec_rbac::RbacEngine;

// ── RBAC policy for tests 1-3 ─────────────────────────────────────────────────

/// RBAC policy: `agent:analyst` can read `reports/*`.
const RBAC_ANALYST: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

/// RBAC policy: `agent:writer` can write (but NOT read directly) `data/*`.
const RBAC_WRITER_ONLY: &str = r#"
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
fn odrl_with_expiry(expiry_date: &str) -> String {
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
const ODRL_PURPOSE: &str = r#"
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
const RBAC_ALLOW_READ: &str = r#"
roles:
  - name: reader
    permissions: [read]
    resources: ["shared/*"]
assignments:
  - subject: "agent:combinator"
    roles: [reader]
"#;

/// ODRL: `agent:combinator` is PROHIBITED from reading `shared/data`.
const ODRL_PROHIBIT_READ: &str = r#"
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
const ODRL_PERMIT_READ: &str = r#"
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

/// RBAC: has no rules for `agent:odrl-only` (they're not assigned any role).
const RBAC_NO_RULES: &str = r#"
roles: []
assignments: []
"#;

// ── Audit capture helpers ─────────────────────────────────────────────────────

/// A captured tracing event as a flat string `"field=value;field=value"`.
type EventRecord = String;

/// Thread-safe store for captured tracing events.
#[derive(Default, Clone)]
struct AuditCapture(Arc<Mutex<Vec<EventRecord>>>);

impl AuditCapture {
    fn new() -> Self {
        Self::default()
    }

    fn records(&self) -> Vec<EventRecord> {
        self.0.lock().unwrap().clone()
    }

    /// True if any captured event contains `key=value` in its fields.
    fn has_field(&self, key: &str, value: &str) -> bool {
        let target = format!("{key}={value}");
        self.records().iter().any(|r| r.contains(&target))
    }
}

/// Tracing [`Layer`] that appends a flat field-string per event to `AuditCapture`.
struct CaptureLayer(AuditCapture);

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
fn install_capture_subscriber() -> AuditCapture {
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

// ── Test 1: RBAC allow ────────────────────────────────────────────────────────

/// An analyst agent reading a report they are authorised for succeeds.
#[tokio::test]
async fn test_01_rbac_allow_analyst_reads_report() {
    let engine = Arc::new(RbacEngine::from_yaml(RBAC_ANALYST).expect("parse rbac"));
    let agent = SecureAgent::new(engine)
        .authenticate_unverified(Credentials::new("agent:analyst", "tok"))
        .expect("auth ok");

    let resource = GenericResource::new("reports/q1", "report");
    let cap = agent
        .request_capability::<CanRead, _>(&resource)
        .await
        .expect("analyst should be allowed to read reports/q1");

    assert_eq!(cap.subject(), "agent:analyst");
    assert_eq!(cap.resource_id(), "reports/q1");
}

// ── Test 2: RBAC deny ─────────────────────────────────────────────────────────

/// An analyst agent trying to WRITE to a report they can only read is denied.
#[tokio::test]
async fn test_02_rbac_deny_analyst_writes_report() {
    let engine = Arc::new(RbacEngine::from_yaml(RBAC_ANALYST).expect("parse rbac"));
    let agent = SecureAgent::new(engine)
        .authenticate_unverified(Credentials::new("agent:analyst", "tok"))
        .expect("auth ok");

    let resource = GenericResource::new("reports/q1", "report");
    let result = agent.request_capability::<CanWrite, _>(&resource).await;

    assert!(
        result.is_err(),
        "analyst should NOT be allowed to write reports/q1"
    );
}

// ── Test 3: Lattice promotion ─────────────────────────────────────────────────

/// Agent has `write` grant but requests `read` — LatticeEngine promotes it.
#[tokio::test]
async fn test_03_lattice_promotes_write_to_read() {
    // Inner engine: only grants `write`, never `read` directly.
    let inner = Arc::new(RbacEngine::from_yaml(RBAC_WRITER_ONLY).expect("parse rbac"));
    let lattice_engine: Arc<dyn typesec_core::PolicyEngine> = Arc::new(LatticeEngine::new(inner));

    let agent = SecureAgent::new(lattice_engine)
        .authenticate_unverified(Credentials::new("agent:writer", "tok"))
        .expect("auth ok");

    let resource = GenericResource::new("data/file.csv", "data");

    // Reading is denied by the raw RBAC engine (no `read` rule).
    // The LatticeEngine promotes: `write` implies `read` → Allow.
    let cap = agent
        .request_capability::<CanRead, _>(&resource)
        .await
        .expect("lattice should grant read because write is allowed");

    assert_eq!(cap.subject(), "agent:writer");
    assert_eq!(
        Capability::<CanRead, GenericResource>::permission_name(),
        "read"
    );
}

// ── Test 4: ODRL time constraint ──────────────────────────────────────────────

/// Future expiry → Allow; past expiry → Deny (via constraint context override).
#[tokio::test]
async fn test_04_odrl_time_constraint() {
    // Expiry one year in the future.
    let future_expiry = (Utc::now() + Duration::days(365))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let yaml = odrl_with_expiry(&future_expiry);
    let engine = OdrlEngine::from_yaml(&yaml).expect("parse odrl");

    // Simulate "now" = well within the valid window.
    let now_ok = ConstraintContext::default().with_time(Utc::now() - Duration::days(1));
    let result = engine.check_with_context("agent:reader", "read", "reports/q1", &now_ok);
    assert_eq!(result, PolicyResult::Allow, "should allow before expiry");

    // Simulate "now" = well past the expiry date.
    let now_expired = ConstraintContext::default().with_time(Utc::now() + Duration::days(730)); // 2 years in the future
    let result_expired =
        engine.check_with_context("agent:reader", "read", "reports/q1", &now_expired);
    assert!(
        !matches!(result_expired, PolicyResult::Allow),
        "should not allow after expiry"
    );
}

// ── Test 5: ODRL purpose constraint ──────────────────────────────────────────

/// Correct purpose → Allow. Wrong purpose → the permission rule doesn't fire
/// (Delegate — no explicit deny, but the grant is not issued).
#[tokio::test]
async fn test_05_odrl_purpose_constraint() {
    let engine = OdrlEngine::from_yaml(ODRL_PURPOSE).expect("parse odrl");

    // Correct purpose.
    let ctx_ok = ConstraintContext::default().with_purpose("analytics");
    let result_ok = engine.check_with_context("agent:analyst", "read", "reports/q1", &ctx_ok);
    assert_eq!(
        result_ok,
        PolicyResult::Allow,
        "correct purpose should allow"
    );

    // Wrong purpose.
    let ctx_bad = ConstraintContext::default().with_purpose("billing");
    let result_bad = engine.check_with_context("agent:analyst", "read", "reports/q1", &ctx_bad);
    assert!(
        !matches!(result_bad, PolicyResult::Allow),
        "wrong purpose must not allow"
    );
}

// ── Test 6: Combinator — DenyOverrides ───────────────────────────────────────

/// RBAC says Allow; ODRL has a Prohibition → DenyOverrides yields Deny.
#[tokio::test]
async fn test_06_combinator_deny_overrides() {
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_ALLOW_READ).expect("rbac"));
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PROHIBIT_READ).expect("odrl"));

    let composed = PolicyEngineBuilder::new()
        .add_engine(rbac)
        .add_engine(odrl)
        .strategy(CombineStrategy::DenyOverrides)
        .build();

    // RBAC → Allow; ODRL → Deny (prohibition); DenyOverrides → Deny
    let result = composed.check("agent:combinator", "read", "shared/data");
    assert!(
        matches!(result, PolicyResult::Deny(_)),
        "DenyOverrides must yield Deny when any engine prohibits: {result:?}"
    );
}

// ── Test 7: Combinator — AllowIfAny ──────────────────────────────────────────

/// RBAC denies (no rules); ODRL permits → AllowIfAny yields Allow.
#[tokio::test]
async fn test_07_combinator_allow_if_any() {
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_NO_RULES).expect("rbac"));
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PERMIT_READ).expect("odrl"));

    let composed = PolicyEngineBuilder::new()
        .add_engine(rbac)
        .add_engine(odrl)
        .strategy(CombineStrategy::AllowIfAny)
        .build();

    // RBAC → Deny (no assignment); ODRL → Allow; AllowIfAny → Allow
    let result = composed.check("agent:odrl-only", "read", "private/data");
    assert_eq!(
        result,
        PolicyResult::Allow,
        "AllowIfAny must yield Allow when at least one engine permits: {result:?}"
    );
}

// ── Test 8: Typestate enforcement ─────────────────────────────────────────────

/// # Compile-time typestate enforcement
///
/// This test documents (but cannot mechanically verify) that the type system
/// prevents executing actions without a corresponding capability.
///
/// The `SecureAgent::execute` signature is:
///
/// ```text
/// pub async fn execute<P, R, F, Fut>(
///     &self,
///     cap: &Capability<P, R>,   ← required: you MUST hold this
///     resource: &R,
///     action: F,
/// ) -> Result<(), TaskError>
/// ```
///
/// There is no `execute` variant that skips the `cap` argument.
/// If you don't have a `Capability<P, R>`, you simply cannot call `execute`.
///
/// Similarly, `Agent<Unauthenticated>` has no `request_capability` method —
/// it only exists on `Agent<Authenticated>`. Calling it on the wrong state
/// is a compile error, not a runtime error.
///
/// The typestate pattern guarantees:
/// - You can't request capabilities before authenticating.
/// - You can't execute actions without proof of a capability.
/// - You can't coerce a `Capability<CanRead, R>` to `Capability<CanWrite, R>`
///   (no `Implies<CanWrite> for CanRead` impl exists).
#[test]
fn test_08_typestate_enforcement_is_compile_time() {
    // This test passes trivially at runtime.
    // The real enforcement is in the type signatures above.
    //
    // To see it fail at compile time, try:
    //   let agent: SecureAgent<Unauthenticated> = SecureAgent::new(engine);
    //   agent.request_capability::<CanRead, _>(&r).await; // ERROR: no method on Unauthenticated
    //
    //   let read_cap: Capability<CanRead, _> = ...;
    //   let write_cap: Capability<CanWrite, _> = read_cap.coerce(); // ERROR: CanRead: !Implies<CanWrite>
    println!("Typestate enforcement is guaranteed by the type system — see doc comment above.");
}

// ── Test 9: Audit log ─────────────────────────────────────────────────────────

/// Every `mint_capability` call emits a structured `tracing::info!` event.
/// We install a capture layer, run allow + deny operations, then assert
/// that "allow" and "deny" verdicts were both recorded.
#[test]
fn test_09_audit_log_captures_decisions() {
    let capture = install_capture_subscriber();

    let engine = Arc::new(RbacEngine::from_yaml(RBAC_ANALYST).expect("rbac"));
    let resource = GenericResource::new("reports/q1", "report");

    // Allow path — should emit verdict=allow
    let _ = mint_capability::<CanRead, _>(engine.as_ref(), "agent:analyst", &resource);

    // Deny path — should emit verdict=deny
    let _ = mint_capability::<CanWrite, _>(engine.as_ref(), "agent:analyst", &resource);

    let records = capture.records();
    assert!(!records.is_empty(), "expected audit events to be captured");

    // At least one allow verdict must be recorded.
    assert!(
        capture.has_field("verdict", "allow"),
        "no 'allow' verdict found in audit records:\n{records:#?}"
    );

    // At least one deny verdict must be recorded.
    assert!(
        capture.has_field("verdict", "deny"),
        "no 'deny' verdict found in audit records:\n{records:#?}"
    );

    // The subject and action must appear.
    assert!(
        records.iter().any(|r| r.contains("agent:analyst")),
        "subject not found in audit records"
    );
    assert!(
        records.iter().any(|r| r.contains("read")),
        "action 'read' not found in audit records"
    );
}
