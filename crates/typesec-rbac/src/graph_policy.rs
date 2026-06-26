//! Graph-aware policy definitions backed by Grust graphs.

mod authored;
mod engine;
mod eval;
mod rule;
mod schema;
mod typed_graph;

pub use engine::{GraphPolicy, GraphPolicyDocument, GraphPolicyEngine};
pub use rule::{
    GraphConditions, GraphRule, PathCondition, PathDirection, RelationshipCondition, RuleEffect,
    Scalar, TargetCondition,
};
pub use schema::{
    COMPANY_GRAPH_CYPHER_CONSTRAINTS, apply_company_graph_cypher_constraints,
    company_graph_cypher_constraints, company_graph_schema,
};

#[cfg(test)]
mod tests;
