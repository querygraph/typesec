//! Pure matching / traversal layer over a built [`Graph`].
//!
//! Everything here is side-effect free: given a graph and a rule (or condition),
//! decide whether it matches a request. The engine ([`super::engine`]) drives
//! these helpers and applies allow/deny resolution on top.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use grust::prelude::{Direction, Graph, Label, Node, NodeId};
use typesec_core::glob::GlobPattern;

use super::rule::{
    GraphConditions, GraphRule, PathCondition, PathDirection, RelationshipCondition, Scalar,
    TargetCondition,
};

pub(crate) fn rule_matches(
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

pub(crate) fn validate_graph(graph: &Graph) -> Result<(), String> {
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
    GlobPattern::compile(pattern, "resource").is_ok_and(|p| p.matches(resource))
}
