//! Compile-time typestate enforcement (documented) and audit-log capture of
//! allow/deny decisions emitted by `mint_capability`.

mod common;

use std::sync::Arc;

use typesec_core::{
    permissions::{CanRead, CanWrite},
    policy::mint_capability,
    resource::GenericResource,
};
use typesec_rbac::RbacEngine;

use common::{RBAC_ANALYST, install_capture_subscriber};

/// # Compile-time typestate enforcement
///
/// This test documents that the type system prevents executing actions without
/// a corresponding capability. The compile-fail harness in `typesec-core`
/// mechanically verifies the lower-level sealed-trait and coercion guarantees.
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
fn typestate_enforcement_is_compile_time() {
    // This test passes trivially at runtime.
    // This agent-level enforcement is in the type signatures above.
    //
    // To see it fail at compile time, try:
    //   let agent: SecureAgent<Unauthenticated> = SecureAgent::new(engine);
    //   agent.request_capability::<CanRead, _>(&r).await; // ERROR: no method on Unauthenticated
    //
    //   let read_cap: Capability<CanRead, _> = ...;
    //   let write_cap: Capability<CanWrite, _> = read_cap.coerce(); // ERROR: CanRead: !Implies<CanWrite>
    println!("Typestate enforcement is guaranteed by the type system — see doc comment above.");
}

/// Every `mint_capability` call emits a structured `tracing::info!` event.
/// We install a capture layer, run allow + deny operations, then assert
/// that "allow" and "deny" verdicts were both recorded.
#[test]
fn audit_log_captures_decisions() {
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
