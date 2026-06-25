//! The graph-policy rule and condition AST.

use std::collections::BTreeMap;

use grust::prelude::{Graph, Value};
use serde::{Deserialize, Deserializer, Serialize};

pub fn deserialize_graph<'de, D>(deserializer: D) -> Result<Graph, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    let yaml = serde_yaml::to_string(&value).map_err(serde::de::Error::custom)?;
    Graph::from_yaml(&yaml).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRule {
    #[serde(default = "allow_effect")]
    pub effect: RuleEffect,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub subject_has_role: Option<String>,
    pub action: String,
    pub resource: String,
    #[serde(default, rename = "where")]
    pub conditions: GraphConditions,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Deny,
}

fn allow_effect() -> RuleEffect {
    RuleEffect::Allow
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphConditions {
    #[serde(default)]
    pub target: Option<TargetCondition>,
    #[serde(default)]
    pub relationship: Option<RelationshipCondition>,
    #[serde(default)]
    pub path_exists: Option<PathCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCondition {
    pub resource_prefix: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub property_equals: BTreeMap<String, Scalar>,
    #[serde(default)]
    pub property_not_equals: BTreeMap<String, Scalar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipCondition {
    pub resource_prefix: String,
    pub edge_label: String,
    #[serde(default)]
    pub from_label: Option<String>,
    #[serde(default)]
    pub to_label: Option<String>,
    #[serde(default)]
    pub no_cycle: bool,
    #[serde(default)]
    pub from_property_equals: BTreeMap<String, Scalar>,
    #[serde(default)]
    pub to_property_equals: BTreeMap<String, Scalar>,
    #[serde(default)]
    pub from_property_not_equals: BTreeMap<String, Scalar>,
    #[serde(default)]
    pub to_property_not_equals: BTreeMap<String, Scalar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCondition {
    pub from: String,
    pub to: String,
    pub edge: String,
    #[serde(default)]
    pub direction: PathDirection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathDirection {
    #[default]
    Out,
    In,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    Bool(bool),
    Int(i64),
    Float(f64),
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
