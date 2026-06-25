//! Grust typed-node/edge bindings and the authored → typed graph lowering.

use std::collections::BTreeMap;

use grust::prelude::{
    Graph, NodeId, TypedEdge, TypedGraphBuilder, TypedNode, garde,
    zod_rs::prelude::{object, string},
};
use serde::{Deserialize, Serialize};

use super::authored::{AuthoredGraph, edge_value, flattened_node_value};

#[derive(Debug, Clone, Deserialize, Serialize, garde::Validate)]
#[garde(allow_unvalidated)]
struct AgentNode {
    #[garde(length(min = 1))]
    id: String,
}

impl TypedNode for AgentNode {
    const LABEL: &'static str = "Agent";

    fn node_id(&self) -> NodeId {
        self.id.clone().into()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, garde::Validate)]
#[garde(allow_unvalidated)]
struct RoleNode {
    #[garde(length(min = 1))]
    id: String,
}

impl TypedNode for RoleNode {
    const LABEL: &'static str = "Role";

    fn node_id(&self) -> NodeId {
        self.id.clone().into()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, garde::Validate)]
#[garde(allow_unvalidated)]
struct EmployeeNode {
    #[garde(length(min = 1))]
    id: String,
    #[garde(length(min = 1))]
    name: String,
    #[garde(length(min = 1))]
    title: String,
    #[garde(length(min = 1))]
    department: String,
    #[garde(length(min = 1))]
    level: String,
    #[garde(length(min = 1))]
    compensation_band: String,
}

impl TypedNode for EmployeeNode {
    const LABEL: &'static str = "Employee";

    fn node_id(&self) -> NodeId {
        self.id.clone().into()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, garde::Validate)]
#[garde(allow_unvalidated)]
struct HasRoleEdge {
    #[garde(length(min = 1))]
    from: String,
    #[garde(length(min = 1))]
    to: String,
}

impl TypedEdge for HasRoleEdge {
    const LABEL: &'static str = "HAS_ROLE";

    fn source_node_id(&self) -> NodeId {
        self.from.clone().into()
    }

    fn target_node_id(&self) -> NodeId {
        self.to.clone().into()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, garde::Validate)]
#[garde(allow_unvalidated)]
struct ReportsToEdge {
    #[garde(length(min = 1))]
    from: String,
    #[garde(length(min = 1))]
    to: String,
}

impl TypedEdge for ReportsToEdge {
    const LABEL: &'static str = "REPORTS_TO";

    fn source_node_id(&self) -> NodeId {
        self.from.clone().into()
    }

    fn target_node_id(&self) -> NodeId {
        self.to.clone().into()
    }
}

pub(crate) fn build_typed_graph(graph: &AuthoredGraph) -> Result<Graph, String> {
    let mut builder = TypedGraphBuilder::new();
    let mut labels = BTreeMap::new();

    for node in &graph.nodes {
        if labels.insert(node.id.clone(), node.label.clone()).is_some() {
            return Err(format!("duplicate graph node '{}'", node.id));
        }

        let value = flattened_node_value(node)?;
        match node.label.as_str() {
            "Agent" => {
                let schema = object().field("id", string().min(1)).strict();
                builder
                    .add_node_from_json::<AgentNode, _>(&schema, &value)
                    .map_err(|err| format!("Agent node '{}' validation failed: {err}", node.id))?;
            }
            "Role" => {
                let schema = object().field("id", string().min(1)).strict();
                builder
                    .add_node_from_json::<RoleNode, _>(&schema, &value)
                    .map_err(|err| format!("Role node '{}' validation failed: {err}", node.id))?;
            }
            "Employee" => {
                let schema = object()
                    .field("id", string().min(1))
                    .field("name", string().min(1))
                    .field("title", string().min(1))
                    .field("department", string().min(1))
                    .field("level", string().min(1))
                    .field("compensation_band", string().min(1))
                    .strict();
                builder
                    .add_node_from_json::<EmployeeNode, _>(&schema, &value)
                    .map_err(|err| {
                        format!("Employee node '{}' validation failed: {err}", node.id)
                    })?;
            }
            other => return Err(format!("unknown graph node label '{other}'")),
        }
    }

    for edge in &graph.edges {
        if !edge.props.is_empty() {
            return Err(format!(
                "edge '{}' from '{}' to '{}' does not allow props",
                edge.label, edge.from, edge.to
            ));
        }
        match edge.label.as_str() {
            "HAS_ROLE" => {
                validate_endpoint_label(&labels, &edge.from, "Agent", &edge.label, "from")?;
                validate_endpoint_label(&labels, &edge.to, "Role", &edge.label, "to")?;
                let schema = object()
                    .field("from", string().min(1))
                    .field("to", string().min(1))
                    .strict();
                builder
                    .add_edge_from_json::<HasRoleEdge, _>(&schema, &edge_value(edge))
                    .map_err(|err| {
                        format!(
                            "HAS_ROLE edge '{}' -> '{}' validation failed: {err}",
                            edge.from, edge.to
                        )
                    })?;
            }
            "REPORTS_TO" => {
                validate_endpoint_label(&labels, &edge.from, "Employee", &edge.label, "from")?;
                validate_endpoint_label(&labels, &edge.to, "Employee", &edge.label, "to")?;
                let schema = object()
                    .field("from", string().min(1))
                    .field("to", string().min(1))
                    .strict();
                builder
                    .add_edge_from_json::<ReportsToEdge, _>(&schema, &edge_value(edge))
                    .map_err(|err| {
                        format!(
                            "REPORTS_TO edge '{}' -> '{}' validation failed: {err}",
                            edge.from, edge.to
                        )
                    })?;
            }
            other => return Err(format!("unknown graph edge label '{other}'")),
        }
    }

    Ok(builder.build())
}

fn validate_endpoint_label(
    labels: &BTreeMap<String, String>,
    id: &str,
    expected: &str,
    edge_label: &str,
    endpoint: &str,
) -> Result<(), String> {
    let Some(actual) = labels.get(id) else {
        return Err(format!(
            "{edge_label} edge references unknown {endpoint} node '{id}'"
        ));
    };
    if actual != expected {
        return Err(format!(
            "{edge_label} edge {endpoint} node '{id}' must have label '{expected}', found '{actual}'"
        ));
    }
    Ok(())
}
