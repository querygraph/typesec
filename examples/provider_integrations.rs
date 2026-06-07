//! # Provider Integrations Example
//!
//! Demonstrates how Typesec can sit behind OAuth-oriented systems:
//!
//! 1. JWT/OIDC claims grant fast org-wide permissions.
//! 2. WorkOS FGA grants precise app-resource permissions.
//! 3. Arcade-style tool authorization grants external SaaS tool execution.
//! 4. `ProtectedTool` refuses to run unless the matching typed capability exists.
//!
//! The example uses mocked HTTP clients, so it runs without WorkOS or Arcade
//! credentials while exercising the same `PolicyEngine` path used in production.

use std::sync::Arc;

use serde_json::json;
use typesec_agent::{ProtectedTool, SecureAgent, ToolFuture};
use typesec_core::{
    Capability, CombineStrategy, Credentials, PolicyEngine, PolicyEngineBuilder, Resource,
    permissions::{CanExecute, CanRead, CanWrite},
    resource::GenericResource,
};
use typesec_integrations::{
    ArcadeToolAuthEngine, JwtClaimsEngine, WorkOsFgaEngine, http::StaticHttpClient,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    println!("=== typesec OAuth Provider Integration Demo ===\n");

    let workos_http = StaticHttpClient::new().with_response(
        "https://api.workos.test/authorization/organization_memberships/user@example.com/check",
        json!({ "authorized": true }),
    );
    let arcade_http = StaticHttpClient::new().with_response(
        "https://api.arcade.test/v1/tools/authorize",
        json!({ "status": "completed" }),
    );

    let jwt_claims = Arc::new(JwtClaimsEngine::from_permissions(
        "user@example.com",
        ["read".to_string()],
    ));
    let workos = Arc::new(WorkOsFgaEngine::with_http(
        "sk_test",
        "https://api.workos.test",
        Arc::new(workos_http),
    ));
    let arcade = Arc::new(
        ArcadeToolAuthEngine::with_http(
            "arc_test",
            "https://api.arcade.test",
            Arc::new(arcade_http),
        )
        .with_tool_mapping("Gmail.ListEmails", "Gmail.ListEmails"),
    );

    let engine = PolicyEngineBuilder::new()
        .add_engine(jwt_claims)
        .add_engine(workos)
        .add_engine(arcade)
        .strategy(CombineStrategy::PriorityOrder)
        .build();
    let engine: Arc<dyn PolicyEngine> = Arc::new(engine);

    let agent = SecureAgent::new(engine)
        .authenticate(Credentials::new("user@example.com", "verified-oidc-token"))
        .expect("auth ok");

    // JWT claims path: the token already carries a broad read permission.
    let org = GenericResource::new("org/acme", "organization");
    let org_read: Capability<CanRead, GenericResource> = agent
        .request_capability(&org)
        .await
        .expect("jwt claim should grant read");
    println!("✓ JWT claims minted capability: {org_read}");

    // WorkOS path: the JWT does not contain write, so the composed engine falls
    // through to the mocked WorkOS FGA check for project/proj_123.
    let project = GenericResource::new("project/proj_123", "project");
    let project_write: Capability<CanWrite, GenericResource> = agent
        .request_capability(&project)
        .await
        .expect("WorkOS FGA should grant project write");
    println!("✓ WorkOS FGA minted capability: {project_write}");

    // Arcade path: WorkOS delegates because this is not a type/id app resource;
    // the Arcade engine checks whether the user has authorized the Gmail tool.
    let gmail_resource = GenericResource::new("Gmail.ListEmails", "tool");
    let gmail_execute: Capability<CanExecute, GenericResource> = agent
        .request_capability(&gmail_resource)
        .await
        .expect("Arcade tool auth should grant execute");
    println!("✓ Arcade tool auth minted capability: {gmail_execute}");

    let gmail_tool = ProtectedTool::<CanExecute, _, _>::new(
        "gmail.list",
        "List Gmail messages through an authorized external tool",
        gmail_resource,
        list_gmail_messages,
    );

    gmail_tool
        .invoke(&agent, &gmail_execute)
        .await
        .expect("protected tool should run");

    println!("\n=== Demo complete ===");
}

fn list_gmail_messages(resource: &GenericResource) -> ToolFuture<'_> {
    let resource_id = resource.resource_id().to_string();
    Box::pin(async move {
        println!("  Action: invoking protected external tool '{resource_id}'");
        Ok(())
    })
}
