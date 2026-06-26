use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult},
};

use super::{GraphPolicyDocument, GraphPolicyEngine};

const YAML: &str = r#"
graph_policy:
  graph:
    nodes:
      - id: agent:hr-onboarding
        label: Agent
      - id: agent:employee-nia
        label: Agent
      - id: role:hr_graph_writer
        label: Role
      - id: employee:evelyn
        label: Employee
        props:
          name: Evelyn Chen
          title: Chief Executive Officer
          department: Executive
          level: Executive
          compensation_band: exec-1
      - id: employee:marco
        label: Employee
        props:
          name: Marco Silva
          title: Engineering Manager
          department: Engineering
          level: M2
          compensation_band: m2-3
      - id: employee:nia
        label: Employee
        props:
          name: Nia Patel
          title: Senior Software Engineer
          department: Engineering
          level: IC4
          compensation_band: ic4-4
    edges:
      - label: HAS_ROLE
        from: agent:hr-onboarding
        to: role:hr_graph_writer
      - label: REPORTS_TO
        from: employee:marco
        to: employee:evelyn
      - label: REPORTS_TO
        from: employee:nia
        to: employee:marco
  rules:
    - subject_has_role: role:hr_graph_writer
      action: write
      resource: employee/private/*
      where:
        target:
          resource_prefix: employee/private/
          label: Employee
          property_not_equals:
            level: Executive
    - subject_has_role: role:hr_graph_writer
      action: write
      resource: relationship/reports_to/*/*
      where:
        relationship:
          resource_prefix: relationship/reports_to/
          edge_label: REPORTS_TO
          from_label: Employee
          to_label: Employee
          no_cycle: true
"#;

fn engine() -> GraphPolicyEngine {
    GraphPolicyEngine::from_yaml(YAML).expect("graph policy should load")
}

fn check(subject: &str, action: &str, resource: &str) -> PolicyResult {
    engine().check(
        &SubjectId::from(subject),
        action,
        &ResourceId::from(resource),
    )
}

#[test]
fn role_can_write_non_executive_employee_node() {
    assert_eq!(
        check(
            "agent:hr-onboarding",
            "write",
            "employee/private/employee:nia"
        ),
        PolicyResult::Allow
    );
}

#[test]
fn role_cannot_write_executive_employee_node() {
    assert!(matches!(
        check(
            "agent:hr-onboarding",
            "write",
            "employee/private/employee:evelyn"
        ),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn unknown_role_assignment_is_denied() {
    assert!(matches!(
        check(
            "agent:employee-nia",
            "write",
            "employee/private/employee:nia"
        ),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn relationship_write_rejects_cycles() {
    assert!(matches!(
        check(
            "agent:hr-onboarding",
            "write",
            "relationship/reports_to/employee:evelyn/employee:nia"
        ),
        PolicyResult::Deny(_)
    ));
}

#[test]
fn relationship_write_allows_tree_extension() {
    assert_eq!(
        check(
            "agent:hr-onboarding",
            "write",
            "relationship/reports_to/employee:nia/employee:evelyn"
        ),
        PolicyResult::Allow
    );
}

#[test]
fn graph_policy_loads_from_json() {
    let json = r#"
{
  "graph_policy": {
    "graph": {
      "nodes": [
        { "id": "agent:hr-onboarding", "label": "Agent" },
        { "id": "role:hr_graph_writer", "label": "Role" },
        {
          "id": "employee:nia",
          "label": "Employee",
          "props": {
            "name": "Nia Patel",
            "title": "Senior Software Engineer",
            "department": "Engineering",
            "level": "IC4",
            "compensation_band": "ic4-4"
          }
        }
      ],
      "edges": [
        {
          "label": "HAS_ROLE",
          "from": "agent:hr-onboarding",
          "to": "role:hr_graph_writer"
        }
      ]
    },
    "rules": [
      {
        "subject_has_role": "role:hr_graph_writer",
        "action": "write",
        "resource": "employee/private/*",
        "where": {
          "target": {
            "resource_prefix": "employee/private/",
            "label": "Employee",
            "property_equals": { "level": "IC4" }
          }
        }
      }
    ]
  }
}
"#;
    let doc = GraphPolicyDocument::from_json(json).expect("JSON graph policy should load");
    assert_eq!(doc.graph_policy.graph.nodes.len(), 3);
    assert_eq!(doc.graph_policy.graph.edges.len(), 1);
}

#[test]
fn exported_company_graph_schema_validates_policy_graph() {
    let doc = GraphPolicyDocument::from_yaml(YAML).expect("graph policy should load");
    let schema = doc.graph_schema();
    schema
        .validate_graph(&doc.graph_policy.graph)
        .expect("schema should validate graph policy graph");
}

#[test]
fn graph_policy_rejects_unknown_node_label() {
    let yaml = YAML.replace("label: Role", "label: Group");
    let err = GraphPolicyDocument::from_yaml(&yaml).expect_err("unknown label should fail");
    assert!(err.contains("unknown graph node label 'Group'"));
}

#[test]
fn graph_policy_rejects_extra_employee_property() {
    let yaml = YAML.replace(
        "compensation_band: ic4-4",
        "compensation_band: ic4-4\n          clearance: confidential",
    );
    let err = GraphPolicyDocument::from_yaml(&yaml).expect_err("strict schema should fail");
    assert!(err.contains("Employee node 'employee:nia' validation failed"));
}

#[test]
fn graph_policy_rejects_invalid_edge_endpoint_types() {
    let yaml = YAML.replace(
        "from: agent:hr-onboarding\n        to: role:hr_graph_writer",
        "from: employee:nia\n        to: role:hr_graph_writer",
    );
    let err = GraphPolicyDocument::from_yaml(&yaml).expect_err("endpoint type should fail");
    assert!(err.contains("HAS_ROLE edge from node 'employee:nia' must have label 'Agent'"));
}

const DENY_OVERRIDE_GRAPH: &str = r#"
graph_policy:
  graph:
    nodes:
      - id: agent:a
        label: Agent
      - id: role:writer
        label: Role
    edges:
      - label: HAS_ROLE
        from: agent:a
        to: role:writer
  rules:
    - subject_has_role: role:writer
      action: write
      resource: doc/*
      effect: allow
    - subject_has_role: role:writer
      action: write
      resource: doc/*
      effect: deny
"#;

#[test]
fn deny_rule_overrides_matching_allow_regardless_of_order() {
    // Both an allow and a deny rule match the same (subject, action, resource);
    // deny must win. Then prove it's order-independent by swapping the rules.
    let engine = GraphPolicyEngine::from_yaml(DENY_OVERRIDE_GRAPH).expect("load");
    assert!(matches!(
        engine.check(
            &SubjectId::from("agent:a"),
            "write",
            &ResourceId::from("doc/readme")
        ),
        PolicyResult::Deny(_)
    ));

    let swapped = DENY_OVERRIDE_GRAPH
        .replace("effect: allow", "effect: TEMP")
        .replace("effect: deny", "effect: allow")
        .replace("effect: TEMP", "effect: deny");
    let engine = GraphPolicyEngine::from_yaml(&swapped).expect("load swapped");
    assert!(
        matches!(
            engine.check(
                &SubjectId::from("agent:a"),
                "write",
                &ResourceId::from("doc/readme")
            ),
            PolicyResult::Deny(_)
        ),
        "deny must override allow even when the allow rule is listed last"
    );
}

#[test]
fn load_rejects_graph_that_violates_company_schema() {
    // A REPORTS_TO edge between two Agents (not Employees) passes the typed-graph
    // build's per-edge endpoint check only if mislabeled; here we point it at a
    // Role to trip grust's schema cross-check wired into validate().
    let yaml = YAML.replace(
        "      - label: REPORTS_TO\n        from: employee:marco\n        to: employee:evelyn",
        "      - label: REPORTS_TO\n        from: role:hr_graph_writer\n        to: employee:evelyn",
    );
    assert!(
        GraphPolicyDocument::from_yaml(&yaml).is_err(),
        "a schema-violating endpoint label must be rejected at load"
    );
}
