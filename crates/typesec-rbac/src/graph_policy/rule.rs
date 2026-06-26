//! The graph-policy rule and condition AST.

use std::collections::BTreeMap;

use grust::prelude::{Graph, Value};
use serde::{Deserialize, Deserializer, Serialize};

/// Deserialize a Grust [`Graph`] from an inline YAML/JSON `nodes`/`edges` map.
pub fn deserialize_graph<'de, D>(deserializer: D) -> Result<Graph, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    let yaml = serde_yaml::to_string(&value).map_err(serde::de::Error::custom)?;
    Graph::from_yaml(&yaml).map_err(serde::de::Error::custom)
}

/// One authored graph-policy rule: a subject/action/resource match plus optional
/// graph-shaped conditions, yielding an allow or deny effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRule {
    /// Whether a match grants (`allow`, the default) or forbids (`deny`).
    #[serde(default = "allow_effect")]
    pub effect: RuleEffect,
    /// Match a literal subject id. Mutually informative with `subject_has_role`.
    #[serde(default)]
    pub subject: Option<String>,
    /// Match any subject holding this role (via a `HAS_ROLE` edge in the graph).
    #[serde(default)]
    pub subject_has_role: Option<String>,
    /// Action this rule governs (e.g. `write`).
    pub action: String,
    /// Resource glob this rule governs (e.g. `employee/private/*`).
    pub resource: String,
    /// Optional graph-shaped conditions (the `where` block) that must also hold.
    #[serde(default, rename = "where")]
    pub conditions: GraphConditions,
}

/// Whether a matching [`GraphRule`] grants or forbids the action.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Grant the action.
    Allow,
    /// Forbid the action; deny overrides any matching allow.
    Deny,
}

fn allow_effect() -> RuleEffect {
    RuleEffect::Allow
}

/// The `where` block: graph-shaped conditions that must all hold for a rule to
/// match. An empty block always holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphConditions {
    /// Constrain the resource node being acted on.
    #[serde(default)]
    pub target: Option<TargetCondition>,
    /// Constrain a relationship (edge) the resource encodes.
    #[serde(default)]
    pub relationship: Option<RelationshipCondition>,
    /// Require a path between two nodes in the graph.
    #[serde(default)]
    pub path_exists: Option<PathCondition>,
}

/// Constraints on the target resource node identified by `resource_prefix`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCondition {
    /// Resource-id prefix that selects the node id from the request resource.
    pub resource_prefix: String,
    /// Required node label, if any.
    #[serde(default)]
    pub label: Option<String>,
    /// Node properties that must equal these values.
    #[serde(default)]
    pub property_equals: BTreeMap<String, Scalar>,
    /// Node properties that must not equal these values.
    #[serde(default)]
    pub property_not_equals: BTreeMap<String, Scalar>,
}

/// Constraints on a relationship (edge) addressed by `resource_prefix`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipCondition {
    /// Resource-id prefix that selects the `from`/`to` endpoints from the request.
    pub resource_prefix: String,
    /// Required edge label (e.g. `REPORTS_TO`).
    pub edge_label: String,
    /// Required label of the `from` endpoint, if any.
    #[serde(default)]
    pub from_label: Option<String>,
    /// Required label of the `to` endpoint, if any.
    #[serde(default)]
    pub to_label: Option<String>,
    /// Reject the write if it would introduce a cycle along `edge_label`.
    #[serde(default)]
    pub no_cycle: bool,
    /// `from`-endpoint properties that must equal these values.
    #[serde(default)]
    pub from_property_equals: BTreeMap<String, Scalar>,
    /// `to`-endpoint properties that must equal these values.
    #[serde(default)]
    pub to_property_equals: BTreeMap<String, Scalar>,
    /// `from`-endpoint properties that must not equal these values.
    #[serde(default)]
    pub from_property_not_equals: BTreeMap<String, Scalar>,
    /// `to`-endpoint properties that must not equal these values.
    #[serde(default)]
    pub to_property_not_equals: BTreeMap<String, Scalar>,
}

/// Require a path from `from` to `to` along `edge` in the given `direction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCondition {
    /// Source node id (supports `$subject` expansion).
    pub from: String,
    /// Destination node id.
    pub to: String,
    /// Edge label to traverse.
    pub edge: String,
    /// Traversal direction (default `out`).
    #[serde(default)]
    pub direction: PathDirection,
}

/// Direction in which a [`PathCondition`] traverses its edge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathDirection {
    /// Follow edges in their stored `from → to` direction.
    #[default]
    Out,
    /// Follow edges against their stored direction.
    In,
    /// Follow edges in either direction.
    Both,
}

/// A scalar property value in a condition, matching the graph's value types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// Floating-point value.
    Float(f64),
    /// String value.
    String(String),
}

impl Scalar {
    pub(crate) fn as_value(&self) -> Value {
        match self {
            Self::Bool(value) => Value::from(*value),
            Self::Int(value) => Value::from(*value),
            Self::Float(value) => Value::from(*value),
            Self::String(value) => Value::from(value),
        }
    }
}
