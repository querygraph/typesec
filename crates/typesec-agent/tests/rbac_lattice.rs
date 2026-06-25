//! RBAC allow/deny paths and lattice promotion of write→read.

mod common;

use std::sync::Arc;

use typesec_agent::SecureAgent;
use typesec_core::{
    Capability, Credentials, PolicyResult,
    combinator::{CombineStrategy, PolicyEngineBuilder},
    lattice::LatticeEngine,
    permissions::{CanRead, CanWrite},
    resource::GenericResource,
};
use typesec_odrl::OdrlEngine;
use typesec_rbac::RbacEngine;

use common::{ODRL_PERMIT_READ, RBAC_ANALYST, RBAC_WRITER_ONLY, check_engine};

/// An analyst agent reading a report they are authorised for succeeds.
#[tokio::test]
async fn rbac_allow_analyst_reads_report() {
    let engine = Arc::new(RbacEngine::from_yaml(RBAC_ANALYST).expect("parse rbac"));
    let agent = SecureAgent::new(engine)
        .authenticate_unverified(Credentials::new("agent:analyst", "tok"))
        .expect("auth ok");

    let resource = GenericResource::new("reports/q1", "report");
    let cap = agent
        .request_capability::<CanRead, _>(&resource)
        .await
        .expect("analyst should be allowed to read reports/q1");

    assert_eq!(cap.subject(), "agent:analyst");
    assert_eq!(cap.resource_id(), "reports/q1");
}

/// An analyst agent trying to WRITE to a report they can only read is denied.
#[tokio::test]
async fn rbac_deny_analyst_writes_report() {
    let engine = Arc::new(RbacEngine::from_yaml(RBAC_ANALYST).expect("parse rbac"));
    let agent = SecureAgent::new(engine)
        .authenticate_unverified(Credentials::new("agent:analyst", "tok"))
        .expect("auth ok");

    let resource = GenericResource::new("reports/q1", "report");
    let result = agent.request_capability::<CanWrite, _>(&resource).await;

    assert!(
        result.is_err(),
        "analyst should NOT be allowed to write reports/q1"
    );
}

/// Agent has `write` grant but requests `read` — LatticeEngine promotes it.
#[tokio::test]
async fn lattice_promotes_write_to_read() {
    // Inner engine: only grants `write`, never `read` directly.
    let inner = Arc::new(RbacEngine::from_yaml(RBAC_WRITER_ONLY).expect("parse rbac"));
    let lattice_engine: Arc<dyn typesec_core::PolicyEngine> = Arc::new(LatticeEngine::new(inner));

    let agent = SecureAgent::new(lattice_engine)
        .authenticate_unverified(Credentials::new("agent:writer", "tok"))
        .expect("auth ok");

    let resource = GenericResource::new("data/file.csv", "data");

    // Reading is denied by the raw RBAC engine (no `read` rule).
    // The LatticeEngine promotes: `write` implies `read` → Allow.
    let cap = agent
        .request_capability::<CanRead, _>(&resource)
        .await
        .expect("lattice should grant read because write is allowed");

    assert_eq!(cap.subject(), "agent:writer");
    assert_eq!(
        Capability::<CanRead, GenericResource>::permission_name(),
        "read"
    );
}

#[tokio::test]
async fn lattice_wraps_composed_engine_and_promotes_rbac_grant() {
    let odrl: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(OdrlEngine::from_yaml(ODRL_PERMIT_READ).expect("odrl"));
    let rbac: Arc<dyn typesec_core::PolicyEngine> =
        Arc::new(RbacEngine::from_yaml(RBAC_WRITER_ONLY).expect("rbac"));
    let composed = PolicyEngineBuilder::new()
        .add_engine(odrl)
        .add_engine(rbac)
        .strategy(CombineStrategy::PriorityOrder)
        .build();
    let lattice = LatticeEngine::new(Arc::new(composed));

    let result = check_engine(&lattice, "agent:writer", "read", "data/file.csv");

    assert_eq!(
        result,
        PolicyResult::Allow,
        "ODRL delegates, then RBAC write grant should promote to read"
    );
}
