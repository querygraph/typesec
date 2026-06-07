//! # RBAC Agent Example
//!
//! Demonstrates type-level security enforcement with RBAC policies.
//!
//! Run with:
//! ```sh
//! cargo run --example rbac_agent
//! ```
//!
//! ## What this shows
//!
//! 1. **Typestate**: The agent starts as `Unauthenticated` and transitions to
//!    `Authenticated` via `authenticate()`. Only authenticated agents can request
//!    capabilities.
//!
//! 2. **Compile-time enforcement**: The `execute` method requires a
//!    `Capability<P, R>`. If you comment out the capability request and try to
//!    call `execute`, you get a compile error — not a runtime panic.
//!
//! 3. **Runtime RBAC checking**: The `data-pipeline` agent can read reports
//!    but not write them. The capability request for write returns an error.
//!
//! 4. **Audit trail**: Every policy decision is logged via `tracing`.

use std::sync::Arc;

use typesec_agent::SecureAgent;
use typesec_core::{
    Credentials, Resource,
    permissions::{CanRead, CanWrite},
    resource::GenericResource,
};
use typesec_rbac::RbacEngine;

const POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read, read_sensitive]
    resources: ["reports/*", "metrics/*"]
  - name: engineer
    permissions: [read, write, execute]
    resources: ["code/*", "infra/*"]
  - name: admin
    inherits: [analyst, engineer]
    permissions: [delete, delegate]
    resources: ["*"]

assignments:
  - subject: "agent:data-pipeline"
    roles: [analyst]
  - subject: "agent:deploy-bot"
    roles: [engineer]
  - subject: "agent:superadmin"
    roles: [admin]
"#;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    println!("=== typesec RBAC Agent Demo ===\n");

    // Build the policy engine from YAML.
    let engine = RbacEngine::from_yaml(POLICY).expect("policy parse ok");
    let engine: Arc<dyn typesec_core::policy::PolicyEngine> = Arc::new(engine);

    // ── Analyst agent ────────────────────────────────────────────────────────
    println!("--- agent:data-pipeline (role: analyst) ---");

    let agent = SecureAgent::new(engine.clone());
    let agent = agent
        .authenticate(Credentials::new("agent:data-pipeline", "token-abc"))
        .expect("auth ok");

    let report = GenericResource::new("reports/q1-2025", "report");

    // ✓ Should succeed: analyst can read reports.
    match agent.request_capability::<CanRead, _>(&report).await {
        Ok(cap) => {
            println!("✓ Got capability: {cap}");
            agent
                .execute(&cap, &report, |r| {
                    let resource_id = r.resource_id().to_owned();
                    Box::pin(async move {
                        println!("  Action: reading report '{resource_id}'");
                        Ok(())
                    })
                })
                .await
                .expect("execute ok");
        }
        Err(e) => println!("✗ Denied (unexpected): {e}"),
    }

    // ✗ Should fail: analyst cannot write reports.
    match agent.request_capability::<CanWrite, _>(&report).await {
        Ok(cap) => println!("✗ Got write cap (unexpected!): {cap}"),
        Err(e) => println!("✓ Write denied (expected): {e}"),
    }

    println!();

    // ── Engineer agent ───────────────────────────────────────────────────────
    println!("--- agent:deploy-bot (role: engineer) ---");

    let agent2 = SecureAgent::new(engine.clone());
    let agent2 = agent2
        .authenticate(Credentials::new("agent:deploy-bot", "token-xyz"))
        .expect("auth ok");

    let code_file = GenericResource::new("code/deploy.sh", "code");

    // ✓ Engineer can write code.
    match agent2.request_capability::<CanWrite, _>(&code_file).await {
        Ok(cap) => {
            println!("✓ Got write capability: {cap}");
            agent2
                .execute(&cap, &code_file, |r| {
                    let resource_id = r.resource_id().to_owned();
                    Box::pin(async move {
                        println!("  Action: writing to '{resource_id}'");
                        Ok(())
                    })
                })
                .await
                .expect("execute ok");
        }
        Err(e) => println!("✗ Denied (unexpected): {e}"),
    }

    // ✗ Engineer cannot access reports.
    match agent2.request_capability::<CanRead, _>(&report).await {
        Ok(cap) => println!("✗ Got report read cap (unexpected!): {cap}"),
        Err(e) => println!("✓ Report read denied (expected): {e}"),
    }

    println!();

    // ── Admin agent ─────────────────────────────────────────────────────────
    println!("--- agent:superadmin (role: admin, inherits analyst + engineer) ---");

    let agent3 = SecureAgent::new(engine.clone());
    let agent3 = agent3
        .authenticate(Credentials::new("agent:superadmin", "token-admin"))
        .expect("auth ok");

    // Admin inherits everything.
    for resource in [
        GenericResource::new("reports/q1-2025", "report"),
        GenericResource::new("code/main.rs", "code"),
        GenericResource::new("anything/at/all", "misc"),
    ] {
        match agent3.request_capability::<CanWrite, _>(&resource).await {
            Ok(cap) => println!("✓ Admin write cap: {cap}"),
            Err(e) => println!("✗ Admin write denied: {e}"),
        }
    }

    println!("\n=== Demo complete ===");

    // ── Compile-time safety note ─────────────────────────────────────────────
    //
    // Try uncommenting this block. It won't compile because there's no
    // `Capability<CanWrite, GenericResource>` in scope:
    //
    // let no_cap_for_me = GenericResource::new("secure/data", "secret");
    // agent.execute(
    //     /* ??? */,  // ← what would you put here? There's no cap to give!
    //     &no_cap_for_me,
    //     |_| Box::pin(async { Ok(()) }),
    // ).await.unwrap();
}
