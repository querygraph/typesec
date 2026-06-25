//! Raw/serde DTO layer for authored graph policies.
//!
//! These types mirror the on-disk YAML/JSON shape before it is validated and
//! lowered into a typed [`grust`] graph by [`super::typed_graph`].

use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue};

use super::rule::GraphRule;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawGraphPolicyDocument {
    pub(crate) graph_policy: RawGraphPolicy,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawGraphPolicy {
    pub(crate) graph: AuthoredGraph,
    #[serde(default)]
    pub(crate) rules: Vec<GraphRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AuthoredGraph {
    #[serde(default)]
    pub(crate) nodes: Vec<AuthoredNode>,
    #[serde(default)]
    pub(crate) edges: Vec<AuthoredEdge>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AuthoredNode {
    pub(crate) id: String,
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) props: JsonMap<String, JsonValue>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AuthoredEdge {
    pub(crate) label: String,
    pub(crate) from: String,
    pub(crate) to: String,
    #[serde(default)]
    pub(crate) props: JsonMap<String, JsonValue>,
}

pub(crate) fn flattened_node_value(node: &AuthoredNode) -> Result<JsonValue, String> {
    let mut fields = JsonMap::new();
    fields.insert("id".to_string(), JsonValue::String(node.id.clone()));
    for (key, value) in &node.props {
        if key == "id" {
            return Err(format!(
                "node '{}' must use top-level id, not props.id",
                node.id
            ));
        }
        fields.insert(key.clone(), value.clone());
    }
    Ok(JsonValue::Object(fields))
}

pub(crate) fn edge_value(edge: &AuthoredEdge) -> JsonValue {
    let mut fields = JsonMap::new();
    fields.insert("from".to_string(), JsonValue::String(edge.from.clone()));
    fields.insert("to".to_string(), JsonValue::String(edge.to.clone()));
    JsonValue::Object(fields)
}
