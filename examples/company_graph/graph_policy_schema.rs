//! Demonstrate the typed Grust + Zod policy boundary for graph policies.
//!
//! This example does not need a graph backend. It shows that Typesec accepts the
//! author-friendly YAML policy, accepts the same shape as JSON, and rejects
//! graph facts that do not match the typed policy model.

use typesec_core::policy::{PolicyEngine, PolicyResult};
use typesec_rbac::graph_policy::{GraphPolicyDocument, GraphPolicyEngine};

const POLICY_YAML: &str = include_str!("../../policies/graph-corporate-example.yaml");

const POLICY_JSON: &str = r#"
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let yaml_doc = GraphPolicyDocument::from_yaml(POLICY_YAML)?;
    println!(
        "YAML policy accepted: {} typed nodes, {} typed edges, {} rules",
        yaml_doc.graph_policy.graph.nodes.len(),
        yaml_doc.graph_policy.graph.edges.len(),
        yaml_doc.graph_policy.rules.len()
    );

    let json_doc = GraphPolicyDocument::from_json(POLICY_JSON)?;
    println!(
        "JSON policy accepted with the same typed loader: {} nodes, {} edges",
        json_doc.graph_policy.graph.nodes.len(),
        json_doc.graph_policy.graph.edges.len()
    );

    let engine = GraphPolicyEngine::new(json_doc)?;
    let decision = engine.check(
        "agent:hr-onboarding",
        "write",
        "employee/private/employee:nia",
    );
    assert_eq!(decision, PolicyResult::Allow);
    println!("typed JSON policy grants HR write access to Nia's private employee node");

    expect_error(
        "unknown node label",
        &POLICY_YAML.replace("label: Role", "label: Group"),
        "unknown graph node label 'Group'",
    );
    expect_error(
        "extra employee property",
        &POLICY_YAML.replace(
            "compensation_band: ic4-4",
            "compensation_band: ic4-4\n          clearance: confidential",
        ),
        "Employee node 'employee:nia' validation failed",
    );
    expect_error(
        "invalid HAS_ROLE endpoint",
        &POLICY_YAML.replace(
            "from: agent:hr-onboarding\n        to: role:hr_graph_writer",
            "from: employee:nia\n        to: role:hr_graph_writer",
        ),
        "HAS_ROLE edge from node 'employee:nia' must have label 'Agent'",
    );

    Ok(())
}

fn expect_error(name: &str, yaml: &str, expected: &str) {
    let err = GraphPolicyDocument::from_yaml(yaml).expect_err("policy should be rejected");
    assert!(
        err.contains(expected),
        "expected {name} error to contain '{expected}', got '{err}'"
    );
    println!("{name} rejected: {err}");
}
