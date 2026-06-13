//! Demonstrate the typed Grust + Zod policy boundary for graph policies.
//!
//! This example does not need an external graph backend. It shows that Typesec
//! accepts the author-friendly YAML policy, accepts the same shape as JSON,
//! rejects graph facts that do not match the typed policy model, and can persist
//! the validated graph through Grust's typed backend path.

use grust::prelude::{GraphStore, MemoryGraphStore};
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult},
};
use typesec_rbac::graph_policy::{GraphPolicyDocument, GraphPolicyEngine, company_graph_schema};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let yaml_doc = GraphPolicyDocument::from_yaml(POLICY_YAML)?;
    let schema = yaml_doc.graph_schema();
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
        &SubjectId::from("agent:hr-onboarding"),
        "write",
        &ResourceId::from("employee/private/employee:nia"),
    );
    assert_eq!(decision, PolicyResult::Allow);
    println!("typed JSON policy grants HR write access to Nia's private employee node");

    let store = MemoryGraphStore::new();
    let report = store
        .put_typed_graph(&schema, &yaml_doc.graph_policy.graph)
        .await?;
    println!(
        "typed memory backend accepted the policy graph: {} nodes, {} edges",
        report.nodes, report.edges
    );

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

    let mut invalid_graph = yaml_doc.graph_policy.graph.clone();
    if let Some(edge) = invalid_graph
        .edges
        .iter_mut()
        .find(|edge| edge.label.as_str() == "HAS_ROLE")
    {
        edge.from = "employee:nia".into();
    }
    let err = company_graph_schema()
        .validate_graph(&invalid_graph)
        .expect_err("typed backend schema should reject invalid edge endpoint");
    assert!(
        err.to_string()
            .contains("edge 'HAS_ROLE' cannot start from node label 'Employee'"),
        "unexpected schema error: {err}"
    );
    println!("typed backend schema rejected invalid graph: {err}");

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
