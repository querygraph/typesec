//! The graph-policy document, engine, and [`PolicyEngine`] implementation.

use glob::Pattern;
use grust::prelude::{Graph, GraphSchema};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult},
};

use super::authored::RawGraphPolicyDocument;
use super::eval::{rule_matches, validate_graph};
use super::rule::{GraphRule, RuleEffect, deserialize_graph};
use super::schema::company_graph_schema;
use super::typed_graph::build_typed_graph;

#[derive(Debug, Clone, Deserialize)]
pub struct GraphPolicyDocument {
    pub graph_policy: GraphPolicy,
}

impl GraphPolicyDocument {
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let value: serde_yaml::Value =
            serde_yaml::from_str(yaml).map_err(|err| format!("YAML parse error: {err}"))?;
        let value =
            serde_json::to_value(value).map_err(|err| format!("YAML conversion error: {err}"))?;
        Self::from_json_value(value)
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        let value = serde_json::from_str(json).map_err(|err| format!("JSON parse error: {err}"))?;
        Self::from_json_value(value)
    }

    pub fn from_json_value(value: JsonValue) -> Result<Self, String> {
        let raw: RawGraphPolicyDocument = serde_json::from_value(value)
            .map_err(|err| format!("Graph policy schema error: {err}"))?;
        let graph = build_typed_graph(&raw.graph_policy.graph)?;
        Ok(Self {
            graph_policy: GraphPolicy {
                graph,
                rules: raw.graph_policy.rules,
            },
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_graph(&self.graph_policy.graph)?;
        if self.graph_policy.rules.is_empty() {
            return Err("graph policy must contain at least one rule".to_string());
        }
        for rule in &self.graph_policy.rules {
            Pattern::new(&rule.resource)
                .map_err(|err| format!("invalid resource pattern '{}': {err}", rule.resource))?;
        }
        Ok(())
    }

    pub fn graph_schema(&self) -> GraphSchema {
        company_graph_schema()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphPolicy {
    #[serde(deserialize_with = "deserialize_graph")]
    pub graph: Graph,
    #[serde(default)]
    pub rules: Vec<GraphRule>,
}

pub struct GraphPolicyEngine {
    doc: GraphPolicyDocument,
}

impl GraphPolicyEngine {
    pub fn new(doc: GraphPolicyDocument) -> Result<Self, String> {
        doc.validate()?;
        Ok(Self { doc })
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let doc = GraphPolicyDocument::from_yaml(yaml)
            .map_err(|err| format!("Graph policy YAML parse error: {err}"))?;
        Self::new(doc)
    }
}

impl PolicyEngine for GraphPolicyEngine {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        debug!(subject, action, resource, "graph policy check");

        let graph = &self.doc.graph_policy.graph;
        let mut allow = None;

        for rule in &self.doc.graph_policy.rules {
            if !rule_matches(graph, rule, subject, action, resource) {
                continue;
            }

            match rule.effect {
                RuleEffect::Deny => {
                    return PolicyResult::Deny(format!(
                        "graph policy deny rule matched '{action}' on '{resource}'"
                    ));
                }
                RuleEffect::Allow => {
                    allow = Some(PolicyResult::Allow);
                }
            }
        }

        allow.unwrap_or_else(|| {
            PolicyResult::Deny(format!(
                "no graph rule grants '{subject}' permission '{action}' on '{resource}'"
            ))
        })
    }
}
