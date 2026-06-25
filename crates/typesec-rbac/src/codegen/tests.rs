use super::*;
use crate::model::RbacPolicy;

const YAML: &str = r#"
roles:
  - name: analyst
    permissions: [read, read_sensitive]
    resources: ["reports/*"]
  - name: admin
    inherits: [analyst]
    permissions: [write, delete]
    resources: ["*"]
assignments: []
"#;

#[test]
fn generates_rust_structs() {
    let policy = RbacPolicy::from_yaml(YAML).expect("parse ok");
    let code = generate_rust(&policy);
    assert!(code.contains("pub struct Analyst"));
    assert!(code.contains("pub struct Admin"));
    assert!(code.contains("fn name() -> &'static str { \"analyst\" }"));
    // Admin should inherit analyst's permissions
    assert!(code.contains("read_sensitive"));
}

#[test]
fn pascal_case_conversion() {
    assert_eq!(super::to_pascal_case("data_analyst"), "DataAnalyst");
    assert_eq!(super::to_pascal_case("deploy-bot"), "DeployBot");
    assert_eq!(super::to_pascal_case("admin"), "Admin");
}
