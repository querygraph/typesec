//! The graph-policy document, engine, and [`PolicyEngine`] implementation.

use grust::prelude::{Graph, GraphSchema};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    glob::GlobPattern,
    policy::{PolicyEngine, PolicyResult},
};

use super::authored::RawGraphPolicyDocument;
use super::eval::{rule_matches, validate_graph};
use super::rule::{GraphRule, RuleEffect, deserialize_graph};
use super::schema::company_graph_schema;
use super::typed_graph::build_typed_graph;

/// A parsed graph-policy document: the typed graph plus its authored rules.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphPolicyDocument {
    /// The `graph_policy` block (graph + rules).
    pub graph_policy: GraphPolicy,
}

impl GraphPolicyDocument {
    /// Parse a document from YAML, building and type-checking the graph.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let value: serde_yaml::Value =
            serde_yaml::from_str(yaml).map_err(|err| format!("YAML parse error: {err}"))?;
        let value =
            serde_json::to_value(value).map_err(|err| format!("YAML conversion error: {err}"))?;
        Self::from_json_value(value)
    }

    /// Parse a document from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let value = serde_json::from_str(json).map_err(|err| format!("JSON parse error: {err}"))?;
        Self::from_json_value(value)
    }

    /// Build a document from an already-parsed JSON value.
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

    /// Validate the graph and rules: graph integrity, the company-schema
    /// cross-check, at least one rule, and well-formed resource globs.
    pub fn validate(&self) -> Result<(), String> {
        validate_graph(&self.graph_policy.graph)?;
        // Cross-check the built graph against the declarative company schema (the
        // same schema that drives the Cypher DDL constraints) using grust's
        // graph-type validation. This ties the schema to the load path so the two
        // can't silently drift, and adds declared-property typing, edge
        // endpoint-label, and uniqueness checks on top of the typed-graph build.
        company_graph_schema()
            .validate_graph(&self.graph_policy.graph)
            .map_err(|err| err.to_string())?;
        if self.graph_policy.rules.is_empty() {
            return Err("graph policy must contain at least one rule".to_string());
        }
        for rule in &self.graph_policy.rules {
            GlobPattern::compile(&rule.resource, "resource")?;
        }
        Ok(())
    }

    /// The declarative company [`GraphSchema`] this document is validated against.
    pub fn graph_schema(&self) -> GraphSchema {
        company_graph_schema()
    }
}

/// The `graph_policy` block: a typed graph and the rules evaluated over it.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphPolicy {
    /// The typed Grust graph (people, roles, relationships).
    #[serde(deserialize_with = "deserialize_graph")]
    pub graph: Graph,
    /// Authored rules, evaluated with deny-overrides semantics.
    #[serde(default)]
    pub rules: Vec<GraphRule>,
}

/// A graph-policy engine: a validated document plus the [`PolicyEngine`] impl.
pub struct GraphPolicyEngine {
    doc: GraphPolicyDocument,
}

impl GraphPolicyEngine {
    /// Build an engine from a document, validating it first.
    pub fn new(doc: GraphPolicyDocument) -> Result<Self, String> {
        doc.validate()?;
        Ok(Self { doc })
    }

    /// Parse and validate an engine from YAML.
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
