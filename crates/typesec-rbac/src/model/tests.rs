use super::*;

const VALID_YAML: &str = r#"
roles:
  - name: analyst
    permissions: [read, read_sensitive]
    resources: ["reports/*"]
  - name: admin
    inherits: [analyst]
    permissions: [write, delete]
    resources: ["*"]

assignments:
  - subject: "agent:pipeline"
    roles: [analyst]
"#;

#[test]
fn parses_valid_yaml() {
    let policy = RbacPolicy::from_yaml(VALID_YAML).expect("parse should succeed");
    assert_eq!(policy.roles.len(), 2);
    assert_eq!(policy.assignments.len(), 1);
    assert!(policy.validate().is_ok());
}

#[test]
fn detects_unknown_parent() {
    let yaml = r#"
roles:
  - name: engineer
    inherits: [nonexistent]
assignments: []
"#;
    let policy = RbacPolicy::from_yaml(yaml).expect("parse ok");
    assert!(policy.validate().is_err());
}

#[test]
fn detects_cycle() {
    let yaml = r#"
roles:
  - name: a
    inherits: [b]
  - name: b
    inherits: [a]
assignments: []
"#;
    let policy = RbacPolicy::from_yaml(yaml).expect("parse ok");
    assert!(policy.validate().is_err());
}
