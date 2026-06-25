use super::*;

const YAML: &str = r#"
policies:
  - uid: "policy:ai-agent-001"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "analytics"
          - leftOperand: dateTime
            operator: lt
            rightOperand: "2099-01-01T00:00:00Z"
      - type: prohibition
        assignee: "agent:summarizer"
        action: exfiltrate
        target: "asset:customer-data"
"#;

fn engine() -> OdrlEngine {
    OdrlEngine::from_yaml(YAML).expect("engine build ok")
}

#[test]
fn read_allowed_with_correct_purpose() {
    let e = engine();
    let ctx = ConstraintContext::default().with_purpose("analytics");
    let result = e.check_with_context("agent:summarizer", "read", "customer-data", &ctx);
    assert_eq!(result, PolicyResult::Allow);
}

#[test]
fn read_denied_wrong_purpose() {
    let e = engine();
    let ctx = ConstraintContext::default().with_purpose("billing");
    let result = e.check_with_context("agent:summarizer", "read", "customer-data", &ctx);
    // No permission matched (purpose constraint failed) → delegate
    assert!(matches!(result, PolicyResult::Delegate(_)));
}

#[test]
fn exfiltrate_is_prohibited() {
    let e = engine();
    let ctx = ConstraintContext::default();
    let result = e.check_with_context("agent:summarizer", "ai:exfiltrate", "customer-data", &ctx);
    assert!(matches!(result, PolicyResult::Deny(_)));
}

#[test]
fn unknown_subject_delegates() {
    let e = engine();
    let ctx = ConstraintContext::default().with_purpose("analytics");
    let result = e.check_with_context("agent:unknown", "read", "customer-data", &ctx);
    assert!(matches!(result, PolicyResult::Delegate(_)));
}

#[test]
fn exact_rule_index_is_built_at_construction() {
    let e = engine();
    assert_eq!(
        e.exact_rules
            .get(&("agent:summarizer".to_owned(), "read".to_owned()))
            .expect("read rule indexed")
            .len(),
        1
    );
    assert_eq!(
        e.exact_rules
            .get(&("agent:summarizer".to_owned(), "ai:exfiltrate".to_owned()))
            .expect("exfiltrate rule indexed")
            .len(),
        1
    );
}

#[test]
fn indexed_use_action_matches_any_action() {
    let yaml = r#"
policies:
  - uid: "policy:any-action"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:operator"
        action: use
        target: "asset:ops/*"
"#;
    let e = OdrlEngine::from_yaml(yaml).expect("engine build ok");
    assert_eq!(
        e.wildcard_action_rules
            .get("agent:operator")
            .expect("use rule indexed")
            .len(),
        1
    );

    let ctx = ConstraintContext::default();
    let result = e.check_with_context("agent:operator", "execute", "ops/restart", &ctx);
    assert_eq!(result, PolicyResult::Allow);
}

#[test]
fn indexed_exact_action_still_checks_target_globs() {
    let yaml = r#"
policies:
  - uid: "policy:reports"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:analyst"
        action: read
        target: "asset:reports/**"
"#;
    let e = OdrlEngine::from_yaml(yaml).expect("engine build ok");
    let ctx = ConstraintContext::default();

    assert_eq!(
        e.check_with_context("agent:analyst", "read", "reports/2026/q1", &ctx),
        PolicyResult::Allow
    );
    assert!(matches!(
        e.check_with_context("agent:analyst", "read", "metrics/q1", &ctx),
        PolicyResult::Delegate(_)
    ));
}

#[test]
fn prohibition_does_not_stop_later_permission_scan() {
    let yaml = r#"
policies:
  - uid: "policy:block"
    type: Set
    rules:
      - type: prohibition
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
  - uid: "policy:allow"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
"#;
    let e = OdrlEngine::from_yaml(yaml).expect("engine build ok");
    let ctx = ConstraintContext::default();
    let result = e.check_with_context("agent:summarizer", "read", "customer-data", &ctx);
    assert!(matches!(result, PolicyResult::Deny(_)));
}
