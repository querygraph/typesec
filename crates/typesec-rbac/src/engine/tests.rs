use super::*;

const YAML: &str = r#"
roles:
  - name: analyst
    permissions: [read, read_sensitive]
    resources: ["reports/*", "metrics/*"]
  - name: engineer
    permissions: [read, write, execute]
    resources: ["code/*", "infra/*"]
  - name: admin
    inherits: [analyst, engineer]
    permissions: [delete, delegate]
    resources: ["*"]

assignments:
  - subject: "agent:data-pipeline"
    roles: [analyst]
  - subject: "agent:deploy-bot"
    roles: [engineer]
  - subject: "agent:superuser"
    roles: [admin]
"#;

fn engine() -> RbacEngine {
    RbacEngine::from_yaml(YAML).expect("engine build should succeed")
}

fn check(e: &RbacEngine, subject: &str, action: &str, resource: &str) -> PolicyResult {
    e.check(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
    )
}

#[test]
fn analyst_can_read_reports() {
    let e = engine();
    assert_eq!(
        check(&e, "agent:data-pipeline", "read", "reports/q1"),
        PolicyResult::Allow
    );
}

#[test]
fn analyst_cannot_write() {
    let e = engine();
    assert!(matches!(
        check(&e, "agent:data-pipeline", "write", "reports/q1"),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn engineer_can_write_code() {
    let e = engine();
    assert_eq!(
        check(&e, "agent:deploy-bot", "write", "code/main.rs"),
        PolicyResult::Allow
    );
}

#[test]
fn engineer_cannot_access_reports() {
    let e = engine();
    assert!(matches!(
        check(&e, "agent:deploy-bot", "read", "reports/q1"),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn admin_inherits_analyst_and_engineer() {
    let e = engine();
    // Inherited from analyst:
    assert_eq!(
        check(&e, "agent:superuser", "read_sensitive", "reports/q1"),
        PolicyResult::Allow
    );
    // Inherited from engineer:
    assert_eq!(
        check(&e, "agent:superuser", "execute", "code/deploy.sh"),
        PolicyResult::Allow
    );
    // Own permissions:
    assert_eq!(
        check(&e, "agent:superuser", "delete", "anything"),
        PolicyResult::Allow
    );
}

#[test]
fn invalid_resource_pattern_fails_policy_load() {
    let yaml = r#"
roles:
  - name: broken
    permissions: [read]
    resources: ["reports/[unclosed"]

assignments:
  - subject: "agent:x"
    roles: [broken]
"#;
    let result = RbacEngine::from_yaml(yaml);
    assert!(
        result.is_err(),
        "malformed glob must fail at load, not silently deny"
    );
}

#[test]
fn unknown_subject_is_denied() {
    let e = engine();
    assert!(matches!(
        check(&e, "agent:ghost", "read", "reports/q1"),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn wildcard_subject_assignment_matches_globbed_agents() {
    let yaml = r#"
roles:
  - name: deployer
    permissions: [execute]
    resources: ["infra/*"]

assignments:
  - subject: "agent:deploy-*"
    roles: [deployer]
"#;
    let e = RbacEngine::from_yaml(yaml).expect("engine build should succeed");
    assert_eq!(
        check(&e, "agent:deploy-prod", "execute", "infra/restart"),
        PolicyResult::Allow
    );
    assert!(matches!(
        check(&e, "agent:build-prod", "execute", "infra/restart"),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn exact_subject_and_wildcard_subject_grants_are_combined() {
    let yaml = r#"
roles:
  - name: reader
    permissions: [read]
    resources: ["reports/*"]
  - name: writer
    permissions: [write]
    resources: ["reports/*"]

assignments:
  - subject: "agent:report-*"
    roles: [reader]
  - subject: "agent:report-prod"
    roles: [writer]
"#;
    let e = RbacEngine::from_yaml(yaml).expect("engine build should succeed");
    assert_eq!(
        check(&e, "agent:report-prod", "read", "reports/q1"),
        PolicyResult::Allow
    );
    assert_eq!(
        check(&e, "agent:report-prod", "write", "reports/q1"),
        PolicyResult::Allow
    );
}

#[test]
fn invalid_subject_pattern_fails_policy_load() {
    let yaml = r#"
roles:
  - name: reader
    permissions: [read]
    resources: ["*"]

assignments:
  - subject: "agent:[broken"
    roles: [reader]
"#;
    let result = RbacEngine::from_yaml(yaml);
    assert!(
        result.is_err(),
        "malformed subject glob must fail at load, not silently deny"
    );
}

#[test]
fn cyclic_role_inheritance_fails_engine_construction() {
    let yaml = r#"
roles:
  - name: a
    inherits: [b]
    permissions: [read]
    resources: ["*"]
  - name: b
    inherits: [a]
    permissions: [write]
    resources: ["*"]

assignments:
  - subject: "agent:x"
    roles: [a]
"#;

    assert!(RbacEngine::from_yaml(yaml).is_err());
}
