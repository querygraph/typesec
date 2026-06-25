//! ODRL time and purpose constraint evaluation.

mod common;

use chrono::{Duration, Utc};
use typesec_core::PolicyResult;
use typesec_odrl::{OdrlEngine, constraint::ConstraintContext};

use common::{ODRL_PURPOSE, odrl_with_expiry};

/// Future expiry → Allow; past expiry → Deny (via constraint context override).
#[tokio::test]
async fn odrl_time_constraint() {
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

/// Correct purpose → Allow. Wrong purpose → the permission rule doesn't fire
/// (Delegate — no explicit deny, but the grant is not issued).
#[tokio::test]
async fn odrl_purpose_constraint() {
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
