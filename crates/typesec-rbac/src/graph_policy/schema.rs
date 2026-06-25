//! Company graph schema + Cypher DDL constraints.

use grust::prelude::{Field, FieldType, GraphSchema, GraphStore, Label};
use grust_cypher::{CypherConstraintRegistry, CypherSchemaApplication, apply_cypher_ddl_to_schema};

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

pub const COMPANY_GRAPH_CYPHER_CONSTRAINTS: &str = r#"
CREATE CONSTRAINT agent_id IF NOT EXISTS FOR (n:Agent) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT role_id IF NOT EXISTS FOR (n:Role) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT employee_id IF NOT EXISTS FOR (n:Employee) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT employee_name_required IF NOT EXISTS FOR (n:Employee) REQUIRE n.name IS NOT NULL;
"#;

pub fn company_graph_cypher_constraints() -> &'static str {
    COMPANY_GRAPH_CYPHER_CONSTRAINTS
}

pub async fn apply_company_graph_cypher_constraints<S>(
    store: &S,
) -> grust::Result<CypherSchemaApplication>
where
    S: GraphStore + Sync,
{
    let schema = company_graph_schema();
    let mut registry = CypherConstraintRegistry::from_schema(&schema);
    apply_cypher_ddl_to_schema(
        store,
        &schema,
        &mut registry,
        company_graph_cypher_constraints(),
    )
    .await
}
