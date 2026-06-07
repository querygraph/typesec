//! # ODRL Agent Example
//!
//! Demonstrates ODRL policy enforcement with runtime constraints.
//!
//! Run with:
//! ```sh
//! cargo run --example odrl_agent
//! ```
//!
//! ## What this shows
//!
//! 1. **Constraint evaluation**: Permissions carry conditions like `purpose=analytics`
//!    and `dateTime < 2027-01-01`. The engine evaluates these at runtime.
//!
//! 2. **Prohibition supremacy**: Even if a permission rule matches, a prohibition
//!    on the same action takes precedence. The `exfiltrate` prohibition can never
//!    be overridden by any permission.
//!
//! 3. **Delegation**: When no ODRL rule matches, the engine returns `Delegate`.
//!    In a composed setup (ODRL + RBAC fallback), the RBAC engine would be tried next.
//!
//! 4. **Audit trail**: Every decision (permit/prohibit/delegate) is logged.

use std::sync::Arc;

use typesec_agent::SecureAgent;
use typesec_core::{
    Credentials, Resource,
    permissions::{AiCanExfiltrate, AiCanInfer, CanRead},
    resource::GenericResource,
};
use typesec_odrl::{OdrlEngine, constraint::ConstraintContext};

const POLICY: &str = r#"
policies:
  - uid: "policy:ai-agent-analytics"
    type: Set
    rules:
      - type: permission
        assigner: "org:acme"
        assignee: "agent:summarizer"
        action: read
        target: "asset:customer-data"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: "analytics"
          - leftOperand: dateTime
            operator: lt
            rightOperand: "2099-01-01T00:00:00Z"

      - type: permission
        assigner: "org:acme"
        assignee: "agent:summarizer"
        action: "ai:infer"
        target: "asset:customer-data"
        constraints:
          - leftOperand: purpose
            operator: isPartOf
            rightOperand: "analytics, audit, reporting"

      - type: prohibition
        assignee: "agent:summarizer"
        action: exfiltrate
        target: "asset:customer-data"
"#;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    println!("=== typesec ODRL Agent Demo ===\n");

    let customer_data = GenericResource::new("customer-data", "asset");

    // ── Scenario 1: correct purpose → allowed ────────────────────────────────
    println!("--- Scenario 1: purpose=analytics (should be allowed) ---");
    {
        let ctx = ConstraintContext::default().with_purpose("analytics");
        let engine = OdrlEngine::from_yaml(POLICY)
            .expect("parse ok")
            .with_context(ctx);
        let engine_arc: Arc<dyn typesec_core::policy::PolicyEngine> = Arc::new(engine);

        let agent = SecureAgent::new(engine_arc)
            .authenticate(Credentials::new("agent:summarizer", "tok"))
            .expect("auth");

        match agent.request_capability::<CanRead, _>(&customer_data).await {
            Ok(cap) => {
                println!("✓ Read allowed: {cap}");
                agent
                    .execute(&cap, &customer_data, |r| {
                        let resource_id = r.resource_id().to_owned();
                        Box::pin(async move {
                            println!("  Action: summarising '{resource_id}'");
                            Ok(())
                        })
                    })
                    .await
                    .unwrap();
            }
            Err(e) => println!("✗ Unexpected denial: {e}"),
        }
    }
    println!();

    // ── Scenario 2: wrong purpose → no matching rule → delegate ──────────────
    println!("--- Scenario 2: purpose=billing (should delegate / deny) ---");
    {
        let ctx = ConstraintContext::default().with_purpose("billing");
        let engine = OdrlEngine::from_yaml(POLICY)
            .expect("parse ok")
            .with_context(ctx);
        let engine_arc: Arc<dyn typesec_core::policy::PolicyEngine> = Arc::new(engine);

        let agent = SecureAgent::new(engine_arc)
            .authenticate(Credentials::new("agent:summarizer", "tok"))
            .expect("auth");

        match agent.request_capability::<CanRead, _>(&customer_data).await {
            Ok(cap) => println!("✗ Unexpected cap: {cap}"),
            Err(e) => println!("✓ No cap (expected — wrong purpose): {e}"),
        }
    }
    println!();

    // ── Scenario 3: AI inference with valid purpose ───────────────────────────
    println!("--- Scenario 3: ai:infer with purpose=audit (allowed via isPartOf) ---");
    {
        let ctx = ConstraintContext::default().with_purpose("audit");
        let engine = OdrlEngine::from_yaml(POLICY)
            .expect("parse ok")
            .with_context(ctx);
        let engine_arc: Arc<dyn typesec_core::policy::PolicyEngine> = Arc::new(engine);

        let agent = SecureAgent::new(engine_arc)
            .authenticate(Credentials::new("agent:summarizer", "tok"))
            .expect("auth");

        match agent
            .request_capability::<AiCanInfer, _>(&customer_data)
            .await
        {
            Ok(cap) => println!("✓ Inference allowed: {cap}"),
            Err(e) => println!("✗ Unexpected denial: {e}"),
        }
    }
    println!();

    // ── Scenario 4: exfiltrate — always prohibited ───────────────────────────
    println!("--- Scenario 4: exfiltrate (unconditional prohibition) ---");
    {
        // Even with analytics purpose, exfiltration is prohibited.
        let ctx = ConstraintContext::default().with_purpose("analytics");
        let engine = OdrlEngine::from_yaml(POLICY)
            .expect("parse ok")
            .with_context(ctx);
        let engine_arc: Arc<dyn typesec_core::policy::PolicyEngine> = Arc::new(engine);

        let agent = SecureAgent::new(engine_arc)
            .authenticate(Credentials::new("agent:summarizer", "tok"))
            .expect("auth");

        match agent
            .request_capability::<AiCanExfiltrate, _>(&customer_data)
            .await
        {
            Ok(cap) => println!("✗ Exfiltration cap granted (SECURITY BUG!): {cap}"),
            Err(e) => println!("✓ Exfiltration denied (expected): {e}"),
        }
    }
    println!();

    // ── Scenario 5: composed engine (ODRL + RBAC fallback) ───────────────────
    println!("--- Scenario 5: ODRL + RBAC fallback composition ---");
    {
        let rbac_yaml = r#"
roles:
  - name: reader
    permissions: [read]
    resources: ["customer-data"]
assignments:
  - subject: "agent:summarizer"
    roles: [reader]
"#;
        let rbac = typesec_rbac::RbacEngine::from_yaml(rbac_yaml).expect("rbac ok");
        let rbac_arc: Arc<dyn typesec_core::policy::PolicyEngine> = Arc::new(rbac);

        // ODRL with no purpose context → will delegate for `read`
        let odrl = OdrlEngine::from_yaml(POLICY).expect("odrl ok");
        let odrl_arc: Arc<dyn typesec_core::policy::PolicyEngine> = Arc::new(odrl);

        // Compose: ODRL first, RBAC fallback.
        let composed = typesec_agent::AgentBuilder::new()
            .with_composed_engine(odrl_arc, rbac_arc)
            .build()
            .expect("build");

        let agent = composed
            .authenticate(Credentials::new("agent:summarizer", "tok"))
            .expect("auth");

        // ODRL delegates (no purpose set), RBAC grants.
        match agent.request_capability::<CanRead, _>(&customer_data).await {
            Ok(cap) => println!("✓ RBAC fallback granted: {cap}"),
            Err(e) => println!("✗ Denied: {e}"),
        }
    }

    println!("\n=== Demo complete ===");
}
