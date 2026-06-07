//! Graph-aware policy definitions backed by Grust graphs.

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use glob::Pattern;
use grust::prelude::{Direction, Graph, Label, Node, NodeId, Value};
use serde::{Deserialize, Deserializer, Serialize};
use tracing::debug;
use typesec_core::policy::{PolicyEngine, PolicyResult};

#[derive(Debug, Clone, Deserialize)]
pub struct GraphPolicyDocument {
    pub graph_policy: GraphPolicy,
}

impl GraphPolicyDocument {
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphPolicy {
    #[serde(deserialize_with = "deserialize_graph")]
    pub graph: Graph,
    #[serde(default)]
    pub rules: Vec<GraphRule>,
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

fn deserialize_graph<'de, D>(deserializer: D) -> Result<Graph, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    let yaml = serde_yaml::to_string(&value).map_err(serde::de::Error::custom)?;
    Graph::from_yaml(&yaml).map_err(serde::de::Error::custom)
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
    fn as_value(&self) -> Value {
        match self {
            Self::Bool(value) => Value::from(*value),
            Self::Int(value) => Value::from(*value),
            Self::Float(value) => Value::from(*value),
            Self::String(value) => Value::from(value),
        }
    }
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
    fn check(&self, subject: &str, action: &str, resource: &str) -> PolicyResult {
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

fn rule_matches(
    graph: &Graph,
    rule: &GraphRule,
    subject: &str,
    action: &str,
    resource: &str,
) -> bool {
    if rule.action != action {
        return false;
    }
    if !matches_glob(&rule.resource, resource) {
        return false;
    }
    if let Some(expected) = &rule.subject
        && expected != subject
    {
        return false;
    }
    if let Some(role) = &rule.subject_has_role
        && !has_labeled_edge(graph, subject, role, "HAS_ROLE")
    {
        return false;
    }

    conditions_match(graph, &rule.conditions, subject, resource)
}

fn conditions_match(
    graph: &Graph,
    conditions: &GraphConditions,
    subject: &str,
    resource: &str,
) -> bool {
    if let Some(target) = &conditions.target
        && !target_matches(graph, target, resource)
    {
        return false;
    }
    if let Some(relationship) = &conditions.relationship
        && !relationship_matches(graph, relationship, resource)
    {
        return false;
    }
    if let Some(path) = &conditions.path_exists
        && !path_matches(graph, path, subject)
    {
        return false;
    }
    true
}

fn target_matches(graph: &Graph, condition: &TargetCondition, resource: &str) -> bool {
    let node_id = match resource.strip_prefix(&condition.resource_prefix) {
        Some(id) => id,
        None => return false,
    };
    let node = match node_by_id(graph, node_id) {
        Some(node) => node,
        None => return false,
    };

    node_matches(
        node,
        condition.label.as_deref(),
        &condition.property_equals,
        &condition.property_not_equals,
    )
}

fn relationship_matches(graph: &Graph, condition: &RelationshipCondition, resource: &str) -> bool {
    let endpoints = match resource.strip_prefix(&condition.resource_prefix) {
        Some(value) => value,
        None => return false,
    };
    let Some((from, to)) = endpoints.split_once('/') else {
        return false;
    };

    let from_node = match node_by_id(graph, from) {
        Some(node) => node,
        None => return false,
    };
    let to_node = match node_by_id(graph, to) {
        Some(node) => node,
        None => return false,
    };

    if !node_matches(
        from_node,
        condition.from_label.as_deref(),
        &condition.from_property_equals,
        &condition.from_property_not_equals,
    ) {
        return false;
    }
    if !node_matches(
        to_node,
        condition.to_label.as_deref(),
        &condition.to_property_equals,
        &condition.to_property_not_equals,
    ) {
        return false;
    }
    if condition.no_cycle && path_exists(graph, to, from, &condition.edge_label, Direction::Out) {
        return false;
    }

    true
}

fn path_matches(graph: &Graph, condition: &PathCondition, subject: &str) -> bool {
    let from = expand_subject(&condition.from, subject);
    let to = expand_subject(&condition.to, subject);
    path_exists(
        graph,
        &from,
        &to,
        &condition.edge,
        match condition.direction {
            PathDirection::Out => Direction::Out,
            PathDirection::In => Direction::In,
            PathDirection::Both => Direction::Both,
        },
    )
}

fn node_matches(
    node: &Node,
    label: Option<&str>,
    property_equals: &BTreeMap<String, Scalar>,
    property_not_equals: &BTreeMap<String, Scalar>,
) -> bool {
    if let Some(label) = label
        && node.label != Label::from(label)
    {
        return false;
    }
    for (key, value) in property_equals {
        if node.props.get(key) != Some(&value.as_value()) {
            return false;
        }
    }
    for (key, value) in property_not_equals {
        if node.props.get(key) == Some(&value.as_value()) {
            return false;
        }
    }
    true
}

fn validate_graph(graph: &Graph) -> Result<(), String> {
    let node_ids = graph
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    for edge in &graph.edges {
        if !node_ids.contains(&edge.from) {
            return Err(format!(
                "edge '{}' references unknown from node '{}'",
                edge.label, edge.from
            ));
        }
        if !node_ids.contains(&edge.to) {
            return Err(format!(
                "edge '{}' references unknown to node '{}'",
                edge.label, edge.to
            ));
        }
    }
    Ok(())
}

fn node_by_id<'a>(graph: &'a Graph, id: &str) -> Option<&'a Node> {
    let id = NodeId::from(id);
    graph.nodes.iter().find(|node| node.id == id)
}

fn has_labeled_edge(graph: &Graph, from: &str, to: &str, label: &str) -> bool {
    graph.edges.iter().any(|edge| {
        edge.from == NodeId::from(from)
            && edge.to == NodeId::from(to)
            && edge.label == Label::from(label)
    })
}

fn path_exists(
    graph: &Graph,
    from: &str,
    to: &str,
    edge_label: &str,
    direction: Direction,
) -> bool {
    let start = NodeId::from(from);
    let goal = NodeId::from(to);
    if start == goal {
        return true;
    }

    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([start.clone()]);
    seen.insert(start);

    while let Some(current) = queue.pop_front() {
        for next in neighbors(graph, &current, edge_label, &direction) {
            if next == goal {
                return true;
            }
            if seen.insert(next.clone()) {
                queue.push_back(next);
            }
        }
    }

    false
}

fn neighbors(graph: &Graph, node: &NodeId, edge_label: &str, direction: &Direction) -> Vec<NodeId> {
    graph
        .edges
        .iter()
        .filter(|edge| edge.label == Label::from(edge_label))
        .filter_map(|edge| match direction {
            Direction::Out if edge.from == *node => Some(edge.to.clone()),
            Direction::In if edge.to == *node => Some(edge.from.clone()),
            Direction::Both if edge.from == *node => Some(edge.to.clone()),
            Direction::Both if edge.to == *node => Some(edge.from.clone()),
            _ => None,
        })
        .collect()
}

fn expand_subject(value: &str, subject: &str) -> String {
    if value == "$subject" {
        subject.to_string()
    } else {
        value.to_string()
    }
}

fn matches_glob(pattern: &str, resource: &str) -> bool {
    pattern == "*" || Pattern::new(pattern).is_ok_and(|p| p.matches(resource))
}

#[cfg(test)]
mod tests {
    use super::*;

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
          level: Executive
      - id: employee:marco
        label: Employee
        props:
          level: M2
      - id: employee:nia
        label: Employee
        props:
          level: IC4
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

    #[test]
    fn role_can_write_non_executive_employee_node() {
        assert_eq!(
            engine().check(
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
            engine().check(
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
            engine().check(
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
            engine().check(
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
            engine().check(
                "agent:hr-onboarding",
                "write",
                "relationship/reports_to/employee:nia/employee:evelyn"
            ),
            PolicyResult::Allow
        );
    }
}
