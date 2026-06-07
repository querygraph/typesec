//! Secure company graph writer using Typesec capabilities and Grust with Sail.
//!
//! If a Sail SparkConnect server is listening on `127.0.0.1:50051`, this example
//! bootstraps the Grust Sail backend and writes the graph. If Sail is offline,
//! it still demonstrates policy enforcement and prints the graph that would be
//! persisted.

use std::{net::TcpStream, sync::Arc};

use grust::prelude::*;
use typesec_agent::SecureAgent;
use typesec_core::{
    Capability, Credentials, Resource,
    permissions::{CanReadSensitive, CanWrite},
    policy::CapabilityError,
};
use typesec_rbac::GraphPolicyEngine;

const POLICY: &str = include_str!("../../policies/graph-corporate-example.yaml");

#[derive(Debug, Clone)]
struct CompanyGraphResource {
    id: String,
}

impl CompanyGraphResource {
    fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl Resource for CompanyGraphResource {
    fn resource_id(&self) -> &str {
        &self.id
    }

    fn resource_type() -> &'static str {
        "CompanyGraphResource"
    }
}

#[derive(Debug, Clone)]
struct EmployeeNodeResource {
    id: String,
}

impl EmployeeNodeResource {
    fn public(employee_id: &str) -> Self {
        Self {
            id: format!("employee/public/{employee_id}"),
        }
    }

    fn private(employee_id: &str) -> Self {
        Self {
            id: format!("employee/private/{employee_id}"),
        }
    }

    fn executive(employee_id: &str) -> Self {
        Self {
            id: format!("employee/executive/{employee_id}"),
        }
    }
}

impl Resource for EmployeeNodeResource {
    fn resource_id(&self) -> &str {
        &self.id
    }

    fn resource_type() -> &'static str {
        "EmployeeNodeResource"
    }
}

#[derive(Debug, Clone)]
struct RelationshipResource {
    id: String,
}

impl RelationshipResource {
    fn reports_to(from: &str, to: &str) -> Self {
        Self {
            id: format!("relationship/reports_to/{from}/{to}"),
        }
    }
}

impl Resource for RelationshipResource {
    fn resource_id(&self) -> &str {
        &self.id
    }

    fn resource_type() -> &'static str {
        "RelationshipResource"
    }
}

#[derive(Debug, Clone)]
struct EmployeeNetworkResource {
    id: String,
}

impl EmployeeNetworkResource {
    fn org_chart() -> Self {
        Self {
            id: "network/org-chart".to_string(),
        }
    }
}

impl Resource for EmployeeNetworkResource {
    fn resource_id(&self) -> &str {
        &self.id
    }

    fn resource_type() -> &'static str {
        "EmployeeNetworkResource"
    }
}

#[derive(Debug, Clone)]
struct Employee {
    id: &'static str,
    name: &'static str,
    title: &'static str,
    department: &'static str,
    level: &'static str,
    compensation_band: &'static str,
}

fn add_employee_node(
    _cap: &Capability<CanWrite, EmployeeNodeResource>,
    builder: &mut GraphBuilder,
    employee: &Employee,
) {
    builder
        .node("Employee", employee.id)
        .prop("name", employee.name)
        .prop("title", employee.title)
        .prop("department", employee.department)
        .prop("level", employee.level)
        .prop("compensation_band", employee.compensation_band)
        .finish();
}

fn add_reports_to_relationship(
    _cap: &Capability<CanWrite, RelationshipResource>,
    builder: &mut GraphBuilder,
    employee: &Employee,
    manager: &Employee,
) {
    builder
        .edge("REPORTS_TO", employee.id, manager.id)
        .prop("visibility", "employee-network")
        .prop("source", "hris")
        .finish();
}

fn inspect_sensitive_network(
    _cap: &Capability<CanReadSensitive, EmployeeNetworkResource>,
    graph: &Graph,
) {
    println!(
        "executive network view: {} employee nodes, {} relationships",
        graph.nodes.len(),
        graph.edges.len()
    );
}

async fn persist_graph_to_sail(
    _cap: &Capability<CanWrite, CompanyGraphResource>,
    graph: &Graph,
) -> grust::Result<()> {
    if TcpStream::connect("127.0.0.1:50051").is_err() {
        println!("Sail is not listening on 127.0.0.1:50051; skipping backend write.");
        return Ok(());
    }

    let store = SailGraphStore::connect(SailConfig::default()).await?;
    store.bootstrap().await?;
    store.clear().await?;
    let report = store.put_graph(graph).await?;
    println!(
        "wrote graph to Sail via Grust: {} nodes, {} edges",
        report.nodes, report.edges
    );
    Ok(())
}

async fn request_write_cap<R: Resource>(
    agent: &SecureAgent<typesec_core::Authenticated>,
    resource: &R,
) -> std::result::Result<Capability<CanWrite, R>, CapabilityError> {
    agent.request_capability::<CanWrite, _>(resource).await
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let engine = Arc::new(GraphPolicyEngine::from_yaml(POLICY)?);

    let executive = SecureAgent::new(engine.clone())
        .authenticate(Credentials::new("agent:executive-chief", "tok"))?;
    let hr = SecureAgent::new(engine.clone())
        .authenticate(Credentials::new("agent:hr-onboarding", "tok"))?;
    let employee_self_service =
        SecureAgent::new(engine).authenticate(Credentials::new("agent:employee-nia", "tok"))?;

    let evelyn = Employee {
        id: "employee:evelyn",
        name: "Evelyn Chen",
        title: "Chief Executive Officer",
        department: "Executive",
        level: "Executive",
        compensation_band: "exec-1",
    };
    let priya = Employee {
        id: "employee:priya",
        name: "Priya Raman",
        title: "VP Engineering",
        department: "Engineering",
        level: "VP",
        compensation_band: "vp-2",
    };
    let marco = Employee {
        id: "employee:marco",
        name: "Marco Silva",
        title: "Engineering Manager",
        department: "Engineering",
        level: "M2",
        compensation_band: "m2-3",
    };
    let nia = Employee {
        id: "employee:nia",
        name: "Nia Patel",
        title: "Senior Software Engineer",
        department: "Engineering",
        level: "IC4",
        compensation_band: "ic4-4",
    };
    let omar = Employee {
        id: "employee:omar",
        name: "Omar Haddad",
        title: "Data Engineer",
        department: "Data",
        level: "IC3",
        compensation_band: "ic3-2",
    };

    let mut builder = Graph::builder();

    println!("executive builds the executive node");
    let exec_node_cap =
        request_write_cap(&executive, &EmployeeNodeResource::executive(evelyn.id)).await?;
    add_employee_node(&exec_node_cap, &mut builder, &evelyn);

    println!("HR writes non-executive employee nodes");
    for employee in [&priya, &marco, &nia, &omar] {
        let cap = request_write_cap(&hr, &EmployeeNodeResource::private(employee.id)).await?;
        add_employee_node(&cap, &mut builder, employee);
    }

    println!("HR writes REPORTS_TO relationships");
    for (employee, manager) in [
        (&priya, &evelyn),
        (&marco, &priya),
        (&nia, &marco),
        (&omar, &marco),
    ] {
        let rel = RelationshipResource::reports_to(employee.id, manager.id);
        let cap = request_write_cap(&hr, &rel).await?;
        add_reports_to_relationship(&cap, &mut builder, employee, manager);
    }

    println!("employee self-service updates only their public profile");
    let nia_public = request_write_cap(
        &employee_self_service,
        &EmployeeNodeResource::public(nia.id),
    )
    .await?;
    add_employee_node(&nia_public, &mut builder, &nia);

    println!("attempting denied writes and reads");
    let denied_exec_write = request_write_cap(&hr, &EmployeeNodeResource::executive(evelyn.id))
        .await
        .expect_err("HR must not write executive-only node data");
    println!("HR executive-node write denied: {denied_exec_write}");

    let network = EmployeeNetworkResource::org_chart();
    let denied_network_read = employee_self_service
        .request_capability::<CanReadSensitive, _>(&network)
        .await
        .expect_err("employees must not read full sensitive org network");
    println!("employee sensitive-network read denied: {denied_network_read}");

    let graph = builder.build();
    let executive_network_cap = executive
        .request_capability::<CanReadSensitive, _>(&network)
        .await?;
    inspect_sensitive_network(&executive_network_cap, &graph);

    let graph_resource = CompanyGraphResource::new("company/acme/org-graph");
    let graph_write_cap = request_write_cap(&executive, &graph_resource).await?;
    persist_graph_to_sail(&graph_write_cap, &graph).await?;

    println!("company graph is ready: {graph:#?}");
    Ok(())
}
