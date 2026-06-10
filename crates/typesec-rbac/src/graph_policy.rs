//! Graph-aware policy definitions backed by Grust graphs.

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use glob::Pattern;
use grust::prelude::{
    Direction, Field, FieldType, Graph, GraphSchema, Label, Node, NodeId, TypedEdge,
    TypedGraphBuilder, TypedNode, Value, garde,
    zod_rs::prelude::{object, string},
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use tracing::debug;
use typesec_core::policy::{PolicyEngine, PolicyResult};

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

pub fn company_graph_schema() -> GraphSchema {
    GraphSchema::builder()
        .node("Agent", vec![Field::required("id", FieldType::String)])
        .node("Role", vec![Field::required("id", FieldType::String)])
        .node(
            "Employee",
            vec![
                Field::required("id", FieldType::String),
                Field::required("name", FieldType::String),
                Field::required("title", FieldType::String),
                Field::required("department", FieldType::String),
                Field::required("level", FieldType::String),
                Field::required("compensation_band", FieldType::String),
            ],
        )
        .edge(
            "HAS_ROLE",
            vec![Label::from("Agent")],
            vec![Label::from("Role")],
            Vec::<Field>::new(),
        )
        .edge(
            "REPORTS_TO",
            vec![Label::from("Employee")],
            vec![Label::from("Employee")],
            vec![
                Field::optional("visibility", FieldType::String),
                Field::optional("source", FieldType::String),
            ],
        )
        .build()
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphPolicy {
    #[serde(deserialize_with = "deserialize_graph")]
    pub graph: Graph,
    #[serde(default)]
    pub rules: Vec<GraphRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawGraphPolicyDocument {
    graph_policy: RawGraphPolicy,
}

#[derive(Debug, Clone, Deserialize)]
struct RawGraphPolicy {
    graph: AuthoredGraph,
    #[serde(default)]
    rules: Vec<GraphRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthoredGraph {
    #[serde(default)]
    nodes: Vec<AuthoredNode>,
    #[serde(default)]
    edges: Vec<AuthoredEdge>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthoredNode {
    id: String,
    label: String,
    #[serde(default)]
    props: JsonMap<String, JsonValue>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthoredEdge {
    label: String,
    from: String,
    to: String,
    #[serde(default)]
    props: JsonMap<String, JsonValue>,
}

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

    fn from_node_id(&self) -> NodeId {
        self.from.clone().into()
    }

    fn to_node_id(&self) -> NodeId {
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

    fn from_node_id(&self) -> NodeId {
        self.from.clone().into()
    }

    fn to_node_id(&self) -> NodeId {
        self.to.clone().into()
    }
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

fn build_typed_graph(graph: &AuthoredGraph) -> Result<Graph, String> {
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

fn flattened_node_value(node: &AuthoredNode) -> Result<JsonValue, String> {
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

fn edge_value(edge: &AuthoredEdge) -> JsonValue {
    let mut fields = JsonMap::new();
    fields.insert("from".to_string(), JsonValue::String(edge.from.clone()));
    fields.insert("to".to_string(), JsonValue::String(edge.to.clone()));
    JsonValue::Object(fields)
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
}
